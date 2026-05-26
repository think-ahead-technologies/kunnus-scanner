// ABOUTME: Tests algorithm mapping and the inject stage that writes hashes onto components.
// ABOUTME: Guards the silent-fallback footgun: an unrecognised algorithm must never be mislabelled.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

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
