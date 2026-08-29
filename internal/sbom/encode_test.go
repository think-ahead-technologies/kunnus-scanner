// ABOUTME: Tests for sbom.Encode: builds an inventory with one package and validates the output JSON.
// ABOUTME: Parses the encoded output rather than golden-file matching, since UUIDs / timestamps drift.
package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/opencontainers/go-digest"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func sampleInventory() inventory.Inventory {
	pkg := &extractor.Package{
		Name:     "github.com/stretchr/testify",
		Version:  "1.8.0",
		PURLType: "golang",
		Plugins:  []string{"go/gomod"},
	}
	return inventory.Inventory{Packages: []*extractor.Package{pkg}}
}

func TestEncode_HasCPE(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comps, _ := doc["components"].([]any)
	if len(comps) == 0 {
		t.Fatal("no components in output")
	}
	got, _ := comps[0].(map[string]any)["cpe"].(string)
	want := "cpe:2.3:a:stretchr:testify:1.8.0:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("component cpe = %q, want %q", got, want)
	}
}

func TestEncode_CycloneDX(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{
			Name:    "my-os",
			Version: "22.04",
			Type:    "operating-system",
		},
	})
	if err != nil {
		t.Fatalf("Encode CycloneDX: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\nbody:\n%s", err, buf.String())
	}

	if v, _ := doc["bomFormat"].(string); v != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}

	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		t.Fatal("missing metadata")
	}
	comp, _ := meta["component"].(map[string]any)
	if comp == nil {
		t.Fatal("missing metadata.component")
	}
	if v, _ := comp["name"].(string); v != "my-os" {
		t.Errorf("component.name = %v, want my-os", comp["name"])
	}
	if v, _ := comp["type"].(string); v != "operating-system" {
		t.Errorf("component.type = %v, want operating-system", comp["type"])
	}

	if !strings.Contains(buf.String(), "testify") {
		t.Error("CycloneDX output missing testify")
	}
}

func TestBackfillScalibrToolVersion(t *testing.T) {
	// scalibr's converter emits its SCALIBR tool entry without a version; the
	// metadata stage backfills it so the SBOM records exactly which extractor
	// library produced it. (The end-to-end proof against a real `go build`
	// binary — the only place dependency build info exists — lives in
	// cmd/kunnus; this covers the backfill mechanics.)
	mkBOM := func(name, ver string) *cyclonedx.BOM {
		return &cyclonedx.BOM{Metadata: &cyclonedx.Metadata{
			Tools: &cyclonedx.ToolsChoice{Components: &[]cyclonedx.Component{{Name: name, Version: ver}}},
		}}
	}

	b := mkBOM("SCALIBR", "")
	backfillScalibrToolVersion(b, "v0.4.5")
	if got := (*b.Metadata.Tools.Components)[0].Version; got != "v0.4.5" {
		t.Errorf("SCALIBR version = %q, want v0.4.5", got)
	}

	// An already-set version is never overwritten.
	b = mkBOM("SCALIBR", "v9.9.9")
	backfillScalibrToolVersion(b, "v0.4.5")
	if got := (*b.Metadata.Tools.Components)[0].Version; got != "v9.9.9" {
		t.Errorf("SCALIBR version overwritten to %q, want v9.9.9 kept", got)
	}

	// Other tools are left alone; empty version and nil metadata are no-ops.
	b = mkBOM("othertool", "")
	backfillScalibrToolVersion(b, "v0.4.5")
	if got := (*b.Metadata.Tools.Components)[0].Version; got != "" {
		t.Errorf("othertool version = %q, want empty", got)
	}
	backfillScalibrToolVersion(mkBOM("SCALIBR", ""), "")
	backfillScalibrToolVersion(&cyclonedx.BOM{}, "v0.4.5")
}

func TestEncode_GenerationContextLifecycle(t *testing.T) {
	// CISA's "generation context" minimum element rides on CycloneDX
	// metadata.lifecycles: the mode declares the phase (pre-build for source
	// scans, post-build for built-artifact scans) and Encode records it.
	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
		Lifecycle: bom.LifecyclePreBuild,
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc struct {
		Metadata struct {
			Lifecycles []struct {
				Phase string `json:"phase"`
			} `json:"lifecycles"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Metadata.Lifecycles) != 1 || doc.Metadata.Lifecycles[0].Phase != "pre-build" {
		t.Errorf("metadata.lifecycles = %+v, want one pre-build phase", doc.Metadata.Lifecycles)
	}
}

func TestEncode_NoLifecycleOmitsField(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(buf.String(), "lifecycles") {
		t.Error("empty lifecycle must not emit metadata.lifecycles")
	}
}

func TestEncode_MultiLayerSamePURL_PreservesEveryLayer(t *testing.T) {
	// The same package version can be present in more than one layer of an
	// image (installed in a base layer, then re-written or re-installed by a
	// later layer). scalibr emits one Package per layer occurrence: each carries
	// the same PURL but its own LayerMetadata. Dedup collapses them to one
	// component — but the component must still record EVERY layer the package
	// lives in, not one arbitrary winner, or container layer attribution silently
	// loses where the package actually is.
	mk := func(idx int, diffID, cmd, loc string) *extractor.Package {
		return &extractor.Package{
			Name:     "musl",
			Version:  "1.2.4-r2",
			PURLType: "apk",
			Plugins:  []string{"os/apk"},
			Location: extractor.LocationFromPath(loc),
			LayerMetadata: &extractor.LayerMetadata{
				Index:   idx,
				DiffID:  digest.Digest(diffID),
				Command: cmd,
			},
		}
	}
	inv := inventory.Inventory{
		Packages: []*extractor.Package{
			mk(0, "sha256:aaaa", "ADD base /", "lib/apk/db/installed"),
			mk(3, "sha256:bbbb", "RUN apk add musl", "usr/lib/libc.musl-x86_64.so.1"),
		},
	}

	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: inv,
		Component: bom.ComponentInfo{Name: "img", Type: "container"},
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody:\n%s", err, buf.String())
	}

	// The deduped musl component carries its layer attribution as properties.
	props := componentProperties(t, doc, "pkg:apk/musl@1.2.4-r2")

	// The full set of layer indices the package occupies must be recoverable.
	if got := props["kunnus:layer:indices"]; got != "0,3" {
		t.Errorf("kunnus:layer:indices = %q, want %q", got, "0,3")
	}
	// Both layers' diffIDs must survive — index alone shifts if layers change.
	if got := props["kunnus:layer:diffids"]; !strings.Contains(got, "sha256:aaaa") || !strings.Contains(got, "sha256:bbbb") {
		t.Errorf("kunnus:layer:diffids = %q, want both sha256:aaaa and sha256:bbbb", got)
	}
}

// componentProperties returns the name→value property map of the first component
// in doc whose purl matches. Fails the test if the component is absent.
func componentProperties(t *testing.T, doc map[string]any, purl string) map[string]string {
	t.Helper()
	comps, _ := doc["components"].([]any)
	for _, c := range comps {
		m, _ := c.(map[string]any)
		if p, _ := m["purl"].(string); p != purl {
			continue
		}
		out := map[string]string{}
		props, _ := m["properties"].([]any)
		for _, p := range props {
			pm, _ := p.(map[string]any)
			name, _ := pm["name"].(string)
			val, _ := pm["value"].(string)
			out[name] = val
		}
		return out
	}
	t.Fatalf("no component with purl %q in output\ncomponents: %+v", purl, comps)
	return nil
}

func TestEncode_VendoredExtraComponentAppended(t *testing.T) {
	// Vendored hits must appear as library components in the BOM, alongside
	// scalibr's own components, and carry both the standard component.hashes[]
	// list and one "kunnus:vendored:file" property per file (path-bearing
	// hashes only — lockfile hashes have no Path and stay properties-free).
	const vendoredPURL = "pkg:generic/zlib?vendored_path=third_party/zlib"
	extras := []bom.ExtraComponent{{
		PURL:   vendoredPURL,
		Name:   "zlib",
		Type:   bom.ComponentTypeLibrary,
		BomRef: "vendored:third_party/zlib",
	}}
	hashMap := hashes.Map{
		vendoredPURL: []hashes.Hash{
			{Algorithm: hashes.AlgMD5, Hex: "deadbeefdeadbeefdeadbeefdeadbeef", Path: "deflate.c"},
			{Algorithm: hashes.AlgMD5, Hex: "cafebabecafebabecafebabecafebabe", Path: "zlib.h"},
		},
	}

	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "repo", Type: "application"},
		Hashes:    hashMap,
		Extras:    extras,
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nbody:\n%s", err, buf.String())
	}

	comps, _ := doc["components"].([]any)
	var vendored map[string]any
	for _, c := range comps {
		m, _ := c.(map[string]any)
		if purl, _ := m["purl"].(string); purl == vendoredPURL {
			vendored = m
			break
		}
	}
	if vendored == nil {
		t.Fatalf("no vendored component in output\ncomponents: %+v", comps)
	}

	if v, _ := vendored["type"].(string); v != "library" {
		t.Errorf("vendored component type = %q, want library", v)
	}
	if v, _ := vendored["name"].(string); v != "zlib" {
		t.Errorf("vendored component name = %q, want zlib", v)
	}
	if v, _ := vendored["bom-ref"].(string); v != "vendored:third_party/zlib" {
		t.Errorf("vendored component bom-ref = %q, want vendored:third_party/zlib", v)
	}

	// Standard component.hashes[] list is populated by injectHashesCDX.
	hs, _ := vendored["hashes"].([]any)
	if len(hs) != 2 {
		t.Errorf("vendored component hashes = %d entries, want 2", len(hs))
	}

	// Per-file property list — one entry per Path-bearing hash. Without it the
	// platform has no way to know which file each MD5 belongs to.
	props, _ := vendored["properties"].([]any)
	fileProps := 0
	for _, p := range props {
		m, _ := p.(map[string]any)
		if name, _ := m["name"].(string); name == "kunnus:vendored:file" {
			fileProps++
		}
	}
	if fileProps != 2 {
		t.Errorf("kunnus:vendored:file properties = %d, want 2 (one per source file)", fileProps)
	}
}

func TestEncode_AuthorDefaultsToKunnus(t *testing.T) {
	// No --author given: the document keeps the kunnus identity as SBOM
	// author (BSI sbom_creator stays satisfied out of the box).
	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc struct {
		Metadata struct {
			Authors      []struct{ Name, Email string }
			Manufacturer struct{ Name string }
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Metadata.Authors) != 1 || doc.Metadata.Authors[0].Name != "Kunnus" {
		t.Errorf("metadata.authors = %+v, want the Kunnus default", doc.Metadata.Authors)
	}
	if doc.Metadata.Manufacturer.Name != "Kunnus" {
		t.Errorf("metadata.manufacturer.name = %q, want Kunnus", doc.Metadata.Manufacturer.Name)
	}
}

func TestEncode_AuthorOverride(t *testing.T) {
	// CISA's SBOM Author element names the entity *operating* the tool, not
	// the tool itself. An explicit author replaces the kunnus identity in
	// metadata.authors and metadata.manufacturer (the org that created the
	// BOM).
	var buf bytes.Buffer
	author := bom.Author{Name: "ACME GmbH", Email: "psirt@acme.example"}
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
		Author:    author,
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc struct {
		Metadata struct {
			Authors      []struct{ Name, Email string }
			Manufacturer struct {
				Name    string
				Contact []struct{ Name, Email string }
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Metadata.Authors) != 1 || doc.Metadata.Authors[0].Name != "ACME GmbH" || doc.Metadata.Authors[0].Email != "psirt@acme.example" {
		t.Errorf("metadata.authors = %+v, want ACME GmbH <psirt@acme.example>", doc.Metadata.Authors)
	}
	if doc.Metadata.Manufacturer.Name != "ACME GmbH" {
		t.Errorf("metadata.manufacturer.name = %q, want ACME GmbH", doc.Metadata.Manufacturer.Name)
	}
}

func TestEncode_ListsKunnusAsTool(t *testing.T) {
	// The scanner belongs in metadata.tools, whoever the author is: an
	// explicit --author must not displace it.
	var buf bytes.Buffer
	author := bom.Author{Name: "ACME GmbH", Email: "psirt@acme.example"}
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "x", Type: "application"},
		Author:    author,
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc struct {
		Metadata struct {
			Tools struct {
				Components []struct{ Name string }
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var toolNames []string
	for _, c := range doc.Metadata.Tools.Components {
		toolNames = append(toolNames, c.Name)
	}
	found := false
	for _, n := range toolNames {
		if n == "kunnus" {
			found = true
		}
	}
	if !found {
		t.Errorf("metadata.tools.components = %v, want kunnus listed", toolNames)
	}
}

func TestEncode_UnknownInfoMarkersEndToEnd(t *testing.T) {
	// The unknown-info sweep must judge the *final* component state: a hash
	// arriving via hashMap (injectHashesCDX) suppresses kunnus:unknown:hash —
	// this fails if markUnknownInfoCDX runs before the hash injector — while
	// the genuinely absent fields on the same component are marked.
	const vendoredPURL = "pkg:generic/zlib?vendored_path=third_party/zlib"
	extras := []bom.ExtraComponent{{
		PURL:   vendoredPURL,
		Name:   "zlib",
		Type:   bom.ComponentTypeLibrary,
		BomRef: "vendored:third_party/zlib",
	}}
	hashMap := hashes.Map{
		vendoredPURL: []hashes.Hash{
			{Algorithm: hashes.AlgMD5, Hex: "deadbeefdeadbeefdeadbeefdeadbeef", Path: "deflate.c"},
		},
	}

	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: sampleInventory(),
		Component: bom.ComponentInfo{Name: "repo", Type: "application"},
		Hashes:    hashMap,
		Extras:    extras,
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	props := componentProperties(t, doc, vendoredPURL)
	// Hash came in via hashMap: not unknown.
	if _, ok := props["kunnus:unknown:hash"]; ok {
		t.Error("kunnus:unknown:hash set despite hashMap hash (sweep ran too early?)")
	}
	// The vendored component genuinely has no version, producer, or licence.
	for _, field := range []string{"producer", "version", "license"} {
		if props["kunnus:unknown:"+field] != "true" {
			t.Errorf("kunnus:unknown:%s = %q, want \"true\"", field, props["kunnus:unknown:"+field])
		}
	}

	// The scalibr package (testify with version + derivable golang supplier)
	// must not be marked for producer or version.
	tProps := componentProperties(t, doc, "pkg:golang/github.com/stretchr/testify@1.8.0")
	for _, field := range []string{"producer", "version"} {
		if _, ok := tProps["kunnus:unknown:"+field]; ok {
			t.Errorf("kunnus:unknown:%s set on testify, which has the field", field)
		}
	}
}
