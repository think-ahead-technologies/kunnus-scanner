// ABOUTME: Tests algorithm mapping and the inject stage that writes hashes onto components.
// ABOUTME: Guards the silent-fallback footgun: an unrecognised algorithm must never be mislabelled.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/binclass"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func TestAlgorithmToCDX_KnownAlgorithms(t *testing.T) {
	cases := []struct {
		in   hashes.Algorithm
		want cyclonedx.HashAlgorithm
	}{
		{hashes.AlgSHA512, cyclonedx.HashAlgoSHA512},
		{hashes.AlgSHA256, cyclonedx.HashAlgoSHA256},
		{hashes.AlgSHA1, cyclonedx.HashAlgoSHA1},
		{hashes.AlgMD5, cyclonedx.HashAlgoMD5},
	}
	for _, c := range cases {
		got, ok := algorithmToCDX(c.in)
		if !ok {
			t.Errorf("algorithmToCDX(%q) ok=false, want true", c.in)
		}
		if got != c.want {
			t.Errorf("algorithmToCDX(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAlgorithmToCDX_UnknownAlgorithmIsRejected(t *testing.T) {
	// An algorithm constant added without extending the switch must NOT be
	// silently relabelled as something familiar. Returning ok=false lets the
	// caller drop the hash rather than emit a corrupted digest.
	if got, ok := algorithmToCDX(hashes.Algorithm("SHA-384")); ok {
		t.Errorf("algorithmToCDX(SHA-384) ok=true (got %q), want false", got)
	}
	if got, ok := algorithmToCDX(hashes.Algorithm("")); ok {
		t.Errorf("algorithmToCDX(empty) ok=true (got %q), want false", got)
	}
}

func TestInjectHashesCDX_SkipsHashWithUnknownAlgorithm(t *testing.T) {
	// A hash carrying an unsupported algorithm must not slip into the SBOM
	// under a different algorithm name. The whole hash entry is dropped.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "x", PackageURL: "pkg:generic/example@1"},
		},
	}
	hashMap := hashes.Map{
		"pkg:generic/example@1": []hashes.Hash{
			{Algorithm: hashes.Algorithm("SHA-384"), Hex: "deadbeef"},
			{Algorithm: hashes.AlgSHA256, Hex: "cafef00d"},
		},
	}
	injectHashesCDX(bom, hashMap)

	c := (*bom.Components)[0]
	if c.Hashes == nil {
		t.Fatal("component.hashes should be populated for the SHA-256 entry")
	}
	if len(*c.Hashes) != 1 {
		t.Fatalf("component.hashes len = %d, want 1 (SHA-384 must be skipped)", len(*c.Hashes))
	}
	if (*c.Hashes)[0].Algorithm != cyclonedx.HashAlgoSHA256 {
		t.Errorf("kept algorithm = %q, want SHA-256", (*c.Hashes)[0].Algorithm)
	}
}

func TestInjectHashesCDX_OmitsComponentWhenAllHashesUnknown(t *testing.T) {
	// If every hash for a PURL is unrecognised, the component should be left
	// untouched — no empty hashes[] array, no synthetic distribution reference.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "x", PackageURL: "pkg:generic/example@1"},
		},
	}
	hashMap := hashes.Map{
		"pkg:generic/example@1": []hashes.Hash{
			{Algorithm: hashes.Algorithm("SHA-384"), Hex: "deadbeef"},
		},
	}
	injectHashesCDX(bom, hashMap)

	c := (*bom.Components)[0]
	if c.Hashes != nil && len(*c.Hashes) != 0 {
		t.Errorf("component.hashes should be nil/empty, got %+v", *c.Hashes)
	}
	if c.ExternalReferences != nil && len(*c.ExternalReferences) != 0 {
		t.Errorf("externalReferences should be nil/empty, got %+v", *c.ExternalReferences)
	}
}

func TestInjectHashesCDX_MatchesNamespacedPURLBeforeNormalization(t *testing.T) {
	// injectHashesCDX runs before normalizePURLsCDX, so a namespaced package
	// (ESP-IDF's "espressif/led_strip") still carries the scalibr-encoded purl
	// ("...espressif%2Fled_strip...") when hashes are joined. The hash map is
	// keyed by the conventional decoded form — the injector must match it the
	// way the licence stage does, via normalizePURL.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "x", PackageURL: "pkg:generic/espressif%2Fled_strip@2.5.5"},
		},
	}
	digest := "384db8dd8f4d4d0dd5d941358588c4455bb783e6588e04fbcfdc27eab6d199a8"
	hashMap := hashes.Map{
		"pkg:generic/espressif/led_strip@2.5.5": []hashes.Hash{
			{Algorithm: hashes.AlgSHA256, Hex: digest},
		},
	}
	injectHashesCDX(bom, hashMap)

	c := (*bom.Components)[0]
	if c.Hashes == nil || len(*c.Hashes) != 1 {
		t.Fatalf("namespaced component got no hashes: %+v", c.Hashes)
	}
	if h := (*c.Hashes)[0]; h.Algorithm != cyclonedx.HashAlgoSHA256 || h.Value != digest {
		t.Errorf("hash = %s:%s, want SHA-256:%s", h.Algorithm, h.Value, digest)
	}
}

func TestInjectClassifierHashes(t *testing.T) {
	// The binary classifier records the classified file's SHA-256 in its
	// package metadata; the stage must surface it as a standard
	// component.hashes[] entry (CISA Component Hash Value + Algorithm).
	const digest = "3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855c"
	pkg := &extractor.Package{
		Name:     "memcached",
		Version:  "1.6.42",
		PURLType: "generic",
		Metadata: &binclass.Metadata{SHA256: digest},
	}
	inv := inventory.Inventory{Packages: []*extractor.Package{pkg}}
	bomDoc := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
		Name:       "memcached",
		Version:    "1.6.42",
		PackageURL: pkg.PURL().String(),
	}}}

	injectClassifierHashesCDX(bomDoc, inv)

	c := (*bomDoc.Components)[0]
	if c.Hashes == nil || len(*c.Hashes) != 1 {
		t.Fatalf("hashes = %+v, want exactly one entry", c.Hashes)
	}
	h := (*c.Hashes)[0]
	if h.Algorithm != cyclonedx.HashAlgoSHA256 || h.Value != digest {
		t.Errorf("hash = %+v, want SHA-256 %s", h, digest)
	}
}

func TestInjectClassifierHashes_NoDigestNoEntry(t *testing.T) {
	// A partially-read binary carries no digest — the component must stay
	// hash-free (and later receive the explicit unknown-hash marker) rather
	// than gain an empty hash entry. Components with existing hashes and
	// non-classifier packages are left untouched.
	pkg := &extractor.Package{
		Name:     "memcached",
		Version:  "1.6.42",
		PURLType: "generic",
		Metadata: &binclass.Metadata{}, // no SHA256: file exceeded the scan cap
	}
	inv := inventory.Inventory{Packages: []*extractor.Package{pkg}}
	bomDoc := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
		Name:       "memcached",
		Version:    "1.6.42",
		PackageURL: pkg.PURL().String(),
	}}}

	injectClassifierHashesCDX(bomDoc, inv)

	if c := (*bomDoc.Components)[0]; c.Hashes != nil {
		t.Errorf("hashes = %+v, want none for a digest-less classifier package", c.Hashes)
	}
}
