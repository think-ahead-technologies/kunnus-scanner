// ABOUTME: Tests for the unknown-information markers (CISA "Explicitly Identifying
// ABOUTME: Unknown Information"): absent fields get explicit kunnus:unknown:* properties.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func propValue(c cyclonedx.Component, name string) (string, bool) {
	if c.Properties == nil {
		return "", false
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

func TestMarkUnknownInfo_AllFieldsMissing(t *testing.T) {
	// A component with no supplier, version, hashes or licences gets one
	// explicit marker per unknown field — omission is never left implicit.
	bomDoc := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
		Name:       "mystery",
		PackageURL: "pkg:generic/mystery",
	}}}
	markUnknownInfoCDX(bomDoc)

	c := (*bomDoc.Components)[0]
	for _, field := range []string{"producer", "version", "hash", "license"} {
		if v, ok := propValue(c, "kunnus:unknown:"+field); !ok || v != "true" {
			t.Errorf("kunnus:unknown:%s = %q,%v; want \"true\",true", field, v, ok)
		}
	}
}

func TestMarkUnknownInfo_KnownFieldsNotMarked(t *testing.T) {
	// Fields that carry data must not be marked unknown.
	bomDoc := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
		Name:       "known",
		Version:    "1.2.3",
		PackageURL: "pkg:npm/known@1.2.3",
		Supplier:   &cyclonedx.OrganizationalEntity{Name: "known"},
		Hashes:     &[]cyclonedx.Hash{{Algorithm: cyclonedx.HashAlgoSHA256, Value: "ab"}},
		Licenses:   &cyclonedx.Licenses{{License: &cyclonedx.License{ID: "MIT"}}},
	}}}
	markUnknownInfoCDX(bomDoc)

	c := (*bomDoc.Components)[0]
	for _, field := range []string{"producer", "version", "hash", "license"} {
		if _, ok := propValue(c, "kunnus:unknown:"+field); ok {
			t.Errorf("kunnus:unknown:%s present on a component that has the field", field)
		}
	}
}

func TestMarkUnknownInfo_EmptySlicesCountAsUnknown(t *testing.T) {
	// Non-nil but empty hash/licence slices carry no information either.
	bomDoc := &cyclonedx.BOM{Components: &[]cyclonedx.Component{{
		Name:       "hollow",
		Version:    "2.0",
		PackageURL: "pkg:generic/hollow@2.0",
		Hashes:     &[]cyclonedx.Hash{},
		Licenses:   &cyclonedx.Licenses{},
	}}}
	markUnknownInfoCDX(bomDoc)

	c := (*bomDoc.Components)[0]
	for _, field := range []string{"hash", "license"} {
		if v, ok := propValue(c, "kunnus:unknown:"+field); !ok || v != "true" {
			t.Errorf("kunnus:unknown:%s = %q,%v; want \"true\",true", field, v, ok)
		}
	}
	if _, ok := propValue(c, "kunnus:unknown:version"); ok {
		t.Error("kunnus:unknown:version present despite version 2.0")
	}
}

func TestMarkUnknownInfo_RootComponentLeftAlone(t *testing.T) {
	// The root component is the author's own product: its identity is the
	// author's statement (via flags), not scanner-derived, so it is never
	// marked unknown-provenance by the sweep.
	bomDoc := &cyclonedx.BOM{
		Metadata:   &cyclonedx.Metadata{Component: &cyclonedx.Component{Name: "my-product"}},
		Components: &[]cyclonedx.Component{},
	}
	markUnknownInfoCDX(bomDoc)
	if bomDoc.Metadata.Component.Properties != nil {
		t.Errorf("root component gained properties: %+v", *bomDoc.Metadata.Component.Properties)
	}
}

func TestMarkUnknownInfo_NilTolerant(t *testing.T) {
	markUnknownInfoCDX(nil)
	markUnknownInfoCDX(&cyclonedx.BOM{})
}
