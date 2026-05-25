// ABOUTME: Tests for dedupCDXComponents — merging same-PURL components into one with combined occurrences.
// ABOUTME: Verifies merging behaviour for evidence, supplier/CPE preference, and singleton passthrough.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestDedupCDXComponents_MergesByPURL(t *testing.T) {
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "ref-1",
				Name:       "stringset",
				Version:    "0.0.14",
				PackageURL: "pkg:golang/bitbucket.org/creachadair/stringset@0.0.14",
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{{Location: "bin/kunnus"}},
				},
			},
			{
				BOMRef:     "ref-2",
				Name:       "stringset",
				Version:    "0.0.14",
				PackageURL: "pkg:golang/bitbucket.org/creachadair/stringset@0.0.14",
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{{Location: "go.mod"}},
				},
			},
		},
	}

	dedupCDXComponents(bom)

	if len(*bom.Components) != 1 {
		t.Fatalf("want 1 component after dedup, got %d", len(*bom.Components))
	}
	c := (*bom.Components)[0]
	if c.BOMRef != "ref-1" {
		t.Errorf("want first bom-ref preserved (ref-1), got %q", c.BOMRef)
	}
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		t.Fatal("want evidence.occurrences preserved")
	}
	occs := *c.Evidence.Occurrences
	if len(occs) != 2 {
		t.Errorf("want 2 occurrences after merge, got %d", len(occs))
	}
	locs := map[string]bool{occs[0].Location: true, occs[1].Location: true}
	if !locs["bin/kunnus"] || !locs["go.mod"] {
		t.Errorf("want both locations present, got %v", locs)
	}
}

func TestDedupCDXComponents_DedupesOccurrenceLocations(t *testing.T) {
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "ref-1",
				PackageURL: "pkg:npm/lodash@4.17.21",
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{{Location: "package-lock.json"}},
				},
			},
			{
				BOMRef:     "ref-2",
				PackageURL: "pkg:npm/lodash@4.17.21",
				Evidence: &cyclonedx.Evidence{
					Occurrences: &[]cyclonedx.EvidenceOccurrence{{Location: "package-lock.json"}},
				},
			},
		},
	}
	dedupCDXComponents(bom)
	if len(*bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(*bom.Components))
	}
	occs := *(*bom.Components)[0].Evidence.Occurrences
	if len(occs) != 1 {
		t.Errorf("want identical occurrence dedup'd to 1, got %d", len(occs))
	}
}

func TestDedupCDXComponents_PrefersNonEmptyMetadata(t *testing.T) {
	// First component is bare; second has supplier + cpe. Result should
	// keep the second's metadata even though we keep the first's bom-ref.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "ref-bare",
				PackageURL: "pkg:pypi/requests@2.31.0",
			},
			{
				BOMRef:     "ref-rich",
				PackageURL: "pkg:pypi/requests@2.31.0",
				CPE:        "cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*",
				Supplier: &cyclonedx.OrganizationalEntity{
					Name: "requests",
					URL:  &[]string{"https://pypi.org/project/requests/"},
				},
			},
		},
	}
	dedupCDXComponents(bom)
	if len(*bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(*bom.Components))
	}
	c := (*bom.Components)[0]
	if c.BOMRef != "ref-bare" {
		t.Errorf("want first bom-ref preserved, got %q", c.BOMRef)
	}
	if c.CPE == "" {
		t.Error("want CPE merged in from richer duplicate")
	}
	if c.Supplier == nil {
		t.Error("want Supplier merged in from richer duplicate")
	}
}

func TestDedupCDXComponents_SingletonPassthrough(t *testing.T) {
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "a", PackageURL: "pkg:npm/foo@1"},
			{BOMRef: "b", PackageURL: "pkg:npm/bar@1"},
			{BOMRef: "c", PackageURL: "pkg:npm/baz@1"},
		},
	}
	dedupCDXComponents(bom)
	if len(*bom.Components) != 3 {
		t.Errorf("want 3 unchanged components, got %d", len(*bom.Components))
	}
}

func TestDedupCDXComponents_PreservesComponentsWithoutPURL(t *testing.T) {
	// Components without a PURL cannot be dedup'd safely — different bom-refs
	// without an identifier may legitimately represent different artifacts.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "file-1", Name: "binary-a"},
			{BOMRef: "file-2", Name: "binary-b"},
			{BOMRef: "lib-1", PackageURL: "pkg:npm/foo@1"},
			{BOMRef: "lib-2", PackageURL: "pkg:npm/foo@1"},
		},
	}
	dedupCDXComponents(bom)
	if len(*bom.Components) != 3 {
		t.Errorf("want 3 components (2 PURL-less + 1 merged), got %d", len(*bom.Components))
	}
}

func TestDedupCDXComponents_PropertiesMergedByName(t *testing.T) {
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "a",
				PackageURL: "pkg:npm/lodash@1",
				Properties: &[]cyclonedx.Property{
					{Name: "bsi:component:executable", Value: "false"},
				},
			},
			{
				BOMRef:     "b",
				PackageURL: "pkg:npm/lodash@1",
				Properties: &[]cyclonedx.Property{
					{Name: "bsi:component:executable", Value: "false"}, // duplicate name
					{Name: "bsi:component:archive", Value: "false"},
				},
			},
		},
	}
	dedupCDXComponents(bom)
	if len(*bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(*bom.Components))
	}
	props := *(*bom.Components)[0].Properties
	if len(props) != 2 {
		t.Errorf("want 2 unique properties after dedup, got %d (%v)", len(props), props)
	}
}

func TestDedupCDXComponents_NilSafe(t *testing.T) {
	// Must not panic on any of these.
	dedupCDXComponents(nil)
	dedupCDXComponents(&cyclonedx.BOM{})
	dedupCDXComponents(&cyclonedx.BOM{Components: &[]cyclonedx.Component{}})
}
