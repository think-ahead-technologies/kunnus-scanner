// ABOUTME: Tests for sbom.Encode: builds an inventory with one package and validates the output JSON.
// ABOUTME: Parses the encoded output rather than golden-file matching, since UUIDs / timestamps drift.
package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/opencontainers/go-digest"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

func sampleResult() *scan.Result {
	pkg := &extractor.Package{
		Name:     "github.com/stretchr/testify",
		Version:  "1.8.0",
		PURLType: "golang",
		Plugins:  []string{"go/gomod"},
	}
	return &scan.Result{
		Inventory: inventory.Inventory{
			Packages: []*extractor.Package{pkg},
		},
	}
}

func TestEncode_HasCPE(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, sampleResult(), bom.ComponentInfo{Name: "x", Type: "application"}, nil, nil, nil); err != nil {
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
	err := Encode(&buf, sampleResult(), bom.ComponentInfo{
		Name:    "my-os",
		Version: "22.04",
		Type:    "operating-system",
	}, nil, nil, nil)
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
			Name:      "musl",
			Version:   "1.2.4-r2",
			PURLType:  "apk",
			Plugins:   []string{"os/apk"},
			Locations: []string{loc},
			LayerMetadata: &extractor.LayerMetadata{
				Index:   idx,
				DiffID:  digest.Digest(diffID),
				Command: cmd,
			},
		}
	}
	result := &scan.Result{
		Inventory: inventory.Inventory{
			Packages: []*extractor.Package{
				mk(0, "sha256:aaaa", "ADD base /", "lib/apk/db/installed"),
				mk(3, "sha256:bbbb", "RUN apk add musl", "usr/lib/libc.musl-x86_64.so.1"),
			},
		},
	}

	var buf bytes.Buffer
	if err := Encode(&buf, result, bom.ComponentInfo{Name: "img", Type: "container"}, nil, nil, nil); err != nil {
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
	if err := Encode(&buf, sampleResult(), bom.ComponentInfo{Name: "repo", Type: "application"}, hashMap, nil, extras); err != nil {
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
