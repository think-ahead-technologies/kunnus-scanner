// ABOUTME: Guards for sbom.Encode's stage ordering plus the output invariants those stages produce.
// ABOUTME: The *_Ordering_* tests were verified by mutation testing to fail when their stage is reordered; the rest pin output shape.
package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/binclass"
	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// Encode (see internal/sbom/encode.go) runs ten mutation stages whose order is
// documented only in a body comment. Several stages join on the raw scalibr
// PURL string, and one stage (normalizePURLsCDX) rewrites that string, so it
// must run last; extras must be appended before the stages that index or
// reference them.
//
// The TestEncode_Ordering_* tests below were validated by mutation testing at
// the time they were written: each failed when its stage was moved out of
// order (see the licence test's note on how scalibr's newer purl rendering has
// since degraded one of them to defensive). The remaining tests pin the
// output invariants those stages produce (useful regression coverage) but do
// NOT, on their own, prove a particular stage order — see the note on
// TestEncode_DedupCollapsesSharedPURL for why the dedup/enrich and
// metadata/depgraph orderings are defensive rather than output-observable.
//
// Helpers in this file are prefixed "ord" to avoid clashing with the other
// _test.go files in package sbom.

// TestEncode_Ordering_LicenseJoinBeforePURLNormalize guards constraints #4/#5:
// licences join on the raw PURL, BEFORE normalizePURLsCDX rewrites it.
//
// scalibr over-escapes a namespaced npm package's scope separator
// ("pkg:npm/%40scope%2Fname"); normalizePURLsCDX decodes the "%2F" to "/" as
// the final stage. injectLicensesCDX matches the inventory on the still-escaped
// PURL. If normalization ran first, the licence-join key would no longer match
// the rewritten component PURL and the licence would be dropped.
//
// Mutation-verified against the scalibr that escaped the scope separator
// ("pkg:npm/%40scope%2Fname"): moving normalizePURLsCDX ahead of
// injectLicensesCDX made this test fail (the ISC licence disappeared).
// Current scalibr emits the namespace as its own segment with no "%2F", so
// normalizePURLsCDX is a no-op on this purl, the "%2F" check below is
// trivially satisfied, and the ordering has degraded to defensive — the
// mutation no longer fails until an escaped purl shape returns.
//
// Two post-conditions, neither able to false-fail:
//   - the emitted PURL no longer contains the "%2F" separator (normalize ran);
//   - the component still carries its declared licence (the join matched the
//     pre-normalization key).
//
// The "%40" scope marker is intentionally left encoded by normalizePURL, so we
// do not assert on it.
func TestEncode_Ordering_LicenseJoinBeforePURLNormalize(t *testing.T) {
	pkg := &extractor.Package{
		Name:     "@isaacs/cliui",
		Version:  "8.0.0",
		PURLType: "npm",
		Location: extractor.LocationFromPath("package-lock.json"),
		Plugins:  []string{"javascript/packagelockjson"},
		Licenses: []string{"ISC"},
	}
	result := &scan.Result{Inventory: inventory.Inventory{Packages: []*extractor.Package{pkg}}}

	doc := ordEncodeDoc(t, result, bom.ComponentInfo{Name: "app", Type: "application"}, nil, nil)

	c := ordFindComponent(doc, func(c map[string]any) bool {
		purl, _ := c["purl"].(string)
		return strings.Contains(purl, "cliui")
	})
	if c == nil {
		t.Fatalf("scoped npm component not found in output")
	}
	purl, _ := c["purl"].(string)
	if strings.Contains(purl, "%2F") || strings.Contains(purl, "%2f") {
		t.Errorf("emitted purl %q still contains an escaped %%2F separator — normalizePURLsCDX did not run", purl)
	}
	if !ordHasLicenseID(c, "ISC") {
		t.Errorf("scoped component lost its ISC licence — the licence join ran after PURL normalization broke its key")
	}
}

// TestEncode_ClassifierCPETemplatesSurviveEncode pins the classifier-CPE
// output through the full Encode pipeline: a package carrying binclass CPE
// templates comes out with the first curated CPE (version rendered in, not
// the PURL heuristic's vendor) and each further template as a kunnus:cpe
// alias property.
//
// NOTE: like the licence join, the CPE join indexes the inventory by raw PURL
// and so belongs before normalizePURLsCDX (constraint #4), but that ordering
// is defensive rather than output-observable today — normalizePURLsCDX is a
// no-op on every purl current scalibr emits (see the constraint comment in
// encode.go).
func TestEncode_ClassifierCPETemplatesSurviveEncode(t *testing.T) {
	pkg := &extractor.Package{
		Name:     "python",
		Version:  "3.14.5",
		PURLType: "generic",
		Location: extractor.LocationFromPath("usr/local/lib/libpython3.14.so"),
		Plugins:  []string{"kunnus/binclass"},
		Metadata: &binclass.Metadata{CPEs: []string{
			"cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
		}},
	}
	result := &scan.Result{Inventory: inventory.Inventory{Packages: []*extractor.Package{pkg}}}

	doc := ordEncodeDoc(t, result, bom.ComponentInfo{Name: "app", Type: "application"}, nil, nil)

	c := ordFindComponent(doc, func(c map[string]any) bool { return c["name"] == "python" })
	if c == nil {
		t.Fatalf("python component not found in output")
	}
	if cpe, _ := c["cpe"].(string); cpe != "cpe:2.3:a:python_software_foundation:python:3.14.5:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %q, want the curated python_software_foundation template, not the PURL heuristic", cpe)
	}
	if !ordHasPropertyValue(c, "kunnus:cpe", "cpe:2.3:a:python:python:3.14.5:*:*:*:*:*:*:*") {
		t.Errorf("second catalog template missing from kunnus:cpe alias properties; component=%v", c)
	}
}

// TestEncode_Ordering_ExtrasBeforeHashesAndDepGraph guards that
// appendExtraComponents runs BEFORE both injectHashesCDX and injectDepGraphCDX
// (encode.go: "Extras must be appended before injectHashesCDX ... and before
// injectDepGraphCDX"). An extra component is supplied with a matching hash-map
// entry; the output must show the hash stamped onto it AND its bom-ref present
// in the dependency graph.
//
// Mutation-verified: moving appendExtraComponents after those two stages makes
// this test fail (the extra carries no hash and is absent from dependencies[]).
func TestEncode_Ordering_ExtrasBeforeHashesAndDepGraph(t *testing.T) {
	const extraPURL = "pkg:generic/zlib"
	const extraRef = "vendored:third_party/zlib"
	extras := []bom.ExtraComponent{{
		PURL:   extraPURL,
		Name:   "zlib",
		Type:   bom.ComponentTypeLibrary,
		BomRef: extraRef,
	}}
	h := hashes.Map{extraPURL: {{Algorithm: hashes.AlgSHA256, Hex: "abc123"}}}
	result := &scan.Result{Inventory: inventory.Inventory{}}

	doc := ordEncodeDoc(t, result, bom.ComponentInfo{Name: "app", Type: "application"}, h, extras)

	z := ordFindComponent(doc, func(c map[string]any) bool { return c["name"] == "zlib" })
	if z == nil {
		t.Fatalf("extra component was not appended to the output")
	}
	if !ordHasHash(z, "SHA-256", "abc123") {
		t.Errorf("extra component carries no hash — appendExtraComponents ran after injectHashesCDX")
	}
	if !ordDependencyExists(doc, extraRef) {
		t.Errorf("extra bom-ref %q absent from dependencies[] — appendExtraComponents ran after injectDepGraphCDX", extraRef)
	}
}

// TestEncode_DedupCollapsesSharedPURL pins the output of constraint #1's stage
// (dedup): two packages with one PURL collapse to one fully-enriched component.
//
// NOTE: this asserts the dedup *output*, not the dedup-before-enrich *order*.
// Mutation testing showed that ordering is defensive, not output-observable:
// enrichCDXComponents indexes result.Inventory (the scalibr packages), never
// the CDX component slice, so component dedup cannot change what enrichment
// aggregates. Running enrich on the duplicates and then deduping yields the
// same single enriched component as deduping first. The ordering is kept for
// safety (a future enrichment that reads the component slice would need it),
// but only a structural stage-order assertion could guard it — out of scope for
// this black-box suite.
func TestEncode_DedupCollapsesSharedPURL(t *testing.T) {
	mk := func(loc string) *extractor.Package {
		return &extractor.Package{
			Name:     "left-pad",
			Version:  "1.3.0",
			PURLType: "npm",
			Location: extractor.LocationFromPath(loc),
			Plugins:  []string{"javascript/packagelockjson"},
		}
	}
	result := &scan.Result{Inventory: inventory.Inventory{Packages: []*extractor.Package{
		mk("a/package-lock.json"),
		mk("b/package-lock.json"),
	}}}

	doc := ordEncodeDoc(t, result, bom.ComponentInfo{Name: "app", Type: "application"}, nil, nil)

	if n := ordCountComponents(doc, func(c map[string]any) bool { return c["name"] == "left-pad" }); n != 1 {
		t.Fatalf("left-pad component count = %d, want 1 (dedup must collapse the duplicate)", n)
	}
	lp := ordFindComponent(doc, func(c map[string]any) bool { return c["name"] == "left-pad" })
	if cpe, _ := lp["cpe"].(string); cpe == "" {
		t.Errorf("deduped component has no synthesised CPE — enrichment did not apply to it")
	}
	if !ordHasProperty(lp, "bsi:component:structured") {
		t.Errorf("deduped component has no BSI properties — enrichment did not apply to it")
	}
}

// TestEncode_RootDependsOnAllComponents pins the dep-graph output: the root
// component depends on every discovered component, including supplied extras.
//
// NOTE: this asserts the dep-graph *output*, not the metadata-before-depgraph
// *order* (constraint #2). Mutation testing showed that ordering is currently
// defensive: the root component's bom-ref is set by scalibr's converter before
// either stage runs (enrichCDXMetadata/enrichRootComponent never set BOMRef),
// so injectDepGraphCDX finds the root regardless of order. The constraint
// guards a future enrichment that *does* synthesise the root ref; guarding it
// today would require a structural stage-order assertion.
func TestEncode_RootDependsOnAllComponents(t *testing.T) {
	pkg := &extractor.Package{
		Name:     "left-pad",
		Version:  "1.3.0",
		PURLType: "npm",
		Location: extractor.LocationFromPath("package-lock.json"),
		Plugins:  []string{"javascript/packagelockjson"},
	}
	const extraRef = "vendored:zlib"
	extras := []bom.ExtraComponent{{
		PURL:   "pkg:generic/zlib",
		Name:   "zlib",
		Type:   bom.ComponentTypeLibrary,
		BomRef: extraRef,
	}}
	result := &scan.Result{Inventory: inventory.Inventory{Packages: []*extractor.Package{pkg}}}

	doc := ordEncodeDoc(t, result, bom.ComponentInfo{Name: "app", Type: "application"}, nil, extras)

	rootRef := ordRootBomRef(doc)
	if rootRef == "" {
		t.Fatal("no root bom-ref in output — dep graph has no root to anchor on")
	}
	rootDeps, ok := ordDependsOn(doc, rootRef)
	if !ok {
		t.Fatalf("root ref %q has no dependency entry", rootRef)
	}
	if !ordContains(rootDeps, extraRef) {
		t.Errorf("root does not depend on the extra component %q; dependsOn=%v", extraRef, rootDeps)
	}
}

// --- helpers (ord-prefixed to avoid clashing with sibling _test.go files) ---

func ordEncodeDoc(t *testing.T, result *scan.Result, comp bom.ComponentInfo, h hashes.Map, extras []bom.ExtraComponent) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := Encode(&buf, result, comp, bom.Series{}, "", bom.Author{}, h, nil, nil, extras, nil); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	return doc
}

func ordFindComponent(doc map[string]any, pred func(map[string]any) bool) map[string]any {
	comps, _ := doc["components"].([]any)
	for _, ci := range comps {
		c, _ := ci.(map[string]any)
		if c != nil && pred(c) {
			return c
		}
	}
	return nil
}

func ordCountComponents(doc map[string]any, pred func(map[string]any) bool) int {
	n := 0
	comps, _ := doc["components"].([]any)
	for _, ci := range comps {
		c, _ := ci.(map[string]any)
		if c != nil && pred(c) {
			n++
		}
	}
	return n
}

func ordHasProperty(c map[string]any, name string) bool {
	props, _ := c["properties"].([]any)
	for _, pi := range props {
		p, _ := pi.(map[string]any)
		if p["name"] == name {
			return true
		}
	}
	return false
}

func ordHasPropertyValue(c map[string]any, name, value string) bool {
	props, _ := c["properties"].([]any)
	for _, pi := range props {
		p, _ := pi.(map[string]any)
		if p["name"] == name && p["value"] == value {
			return true
		}
	}
	return false
}

func ordHasLicenseID(c map[string]any, id string) bool {
	lics, _ := c["licenses"].([]any)
	for _, li := range lics {
		l, _ := li.(map[string]any)
		lo, _ := l["license"].(map[string]any)
		if lo != nil && lo["id"] == id {
			return true
		}
	}
	return false
}

func ordHasHash(c map[string]any, alg, content string) bool {
	hs, _ := c["hashes"].([]any)
	for _, hi := range hs {
		h, _ := hi.(map[string]any)
		if h["alg"] == alg && h["content"] == content {
			return true
		}
	}
	return false
}

func ordDependencyExists(doc map[string]any, ref string) bool {
	_, ok := ordDependsOn(doc, ref)
	return ok
}

// ordDependsOn returns the dependsOn refs for the dependency entry whose ref
// matches, and whether such an entry exists (the entry can exist with an empty
// dependsOn list).
func ordDependsOn(doc map[string]any, ref string) ([]string, bool) {
	deps, _ := doc["dependencies"].([]any)
	for _, di := range deps {
		d, _ := di.(map[string]any)
		if d["ref"] != ref {
			continue
		}
		raw, _ := d["dependsOn"].([]any)
		out := make([]string, 0, len(raw))
		for _, r := range raw {
			if s, ok := r.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

func ordRootBomRef(doc map[string]any) string {
	meta, _ := doc["metadata"].(map[string]any)
	comp, _ := meta["component"].(map[string]any)
	ref, _ := comp["bom-ref"].(string)
	return ref
}

func ordContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
