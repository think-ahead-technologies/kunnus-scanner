// ABOUTME: Tests injectDepGraphCDX — synthesises BSI-required dependencies[] and compositions[].
// ABOUTME: Per TR-03183-2 v2.1 §5.2.2 c.177 every component must appear in dependencies[].
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestInjectDepGraphCDX_PopulatesDependenciesArray(t *testing.T) {
	bom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{
				BOMRef: "root-ref",
				Type:   cyclonedx.ComponentTypeApplication,
				Name:   "my-app",
			},
		},
		Components: &[]cyclonedx.Component{
			{BOMRef: "lib-a", Name: "a"},
			{BOMRef: "lib-b", Name: "b"},
		},
	}

	injectDepGraphCDX(bom)

	if bom.Dependencies == nil {
		t.Fatal("dependencies array must be present")
	}
	deps := *bom.Dependencies
	if len(deps) != 3 {
		t.Fatalf("want 3 dependency entries (root + 2 libs), got %d", len(deps))
	}

	// Root entry must list every component as a dependency.
	var rootEntry *cyclonedx.Dependency
	for i, d := range deps {
		if d.Ref == "root-ref" {
			rootEntry = &deps[i]
			break
		}
	}
	if rootEntry == nil {
		t.Fatal("missing root dependency entry")
	}
	if rootEntry.Dependencies == nil {
		t.Fatal("root must have non-nil dependsOn array")
	}
	if len(*rootEntry.Dependencies) != 2 {
		t.Errorf("root should depend on 2 components, got %d", len(*rootEntry.Dependencies))
	}

	// Every non-root entry must exist with empty dependsOn (BSI claim 177).
	for _, d := range deps {
		if d.Ref == "root-ref" {
			continue
		}
		if d.Dependencies != nil && len(*d.Dependencies) != 0 {
			t.Errorf("component %s should have empty dependsOn, got %v", d.Ref, *d.Dependencies)
		}
	}
}

func TestInjectDepGraphCDX_AddsIncompleteComposition(t *testing.T) {
	// Our scan reports presence-of-component, not full transitive dep edges,
	// so the composition aggregate must honestly say "incomplete".
	bom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{BOMRef: "root", Name: "x"},
		},
		Components: &[]cyclonedx.Component{
			{BOMRef: "a"},
		},
	}
	injectDepGraphCDX(bom)

	if bom.Compositions == nil || len(*bom.Compositions) == 0 {
		t.Fatal("compositions[] must be present")
	}
	comp := (*bom.Compositions)[0]
	if comp.Aggregate != cyclonedx.CompositionAggregateIncomplete {
		t.Errorf("aggregate = %q, want incomplete", comp.Aggregate)
	}
	if comp.Dependencies == nil || len(*comp.Dependencies) == 0 {
		t.Error("composition should reference at least one dependency bom-ref")
	}
}

func TestInjectDepGraphCDX_PreservesExistingDependencies(t *testing.T) {
	// If a future scalibr version starts emitting real dependency edges, we
	// must not clobber them — only top up missing entries and add the
	// completeness declaration.
	bom := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{BOMRef: "root"},
		},
		Components: &[]cyclonedx.Component{
			{BOMRef: "a"},
			{BOMRef: "b"},
		},
		Dependencies: &[]cyclonedx.Dependency{
			{Ref: "a", Dependencies: &[]string{"b"}},
		},
	}
	injectDepGraphCDX(bom)

	deps := *bom.Dependencies
	var aEntry *cyclonedx.Dependency
	for i, d := range deps {
		if d.Ref == "a" {
			aEntry = &deps[i]
			break
		}
	}
	if aEntry == nil {
		t.Fatal("existing dep entry vanished")
	}
	if aEntry.Dependencies == nil || len(*aEntry.Dependencies) != 1 || (*aEntry.Dependencies)[0] != "b" {
		t.Errorf("existing a→b dependency clobbered, got %+v", aEntry.Dependencies)
	}
}

func TestInjectDepGraphCDX_NilSafe(t *testing.T) {
	injectDepGraphCDX(nil)
	injectDepGraphCDX(&cyclonedx.BOM{})
	injectDepGraphCDX(&cyclonedx.BOM{Components: &[]cyclonedx.Component{}})
}

func TestInjectDepGraphCDX_NoRootIsHandled(t *testing.T) {
	// If for any reason the BOM has no metadata.component, every component
	// still gets an entry (BSI requires it) and there's no root entry.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "a"},
			{BOMRef: "b"},
		},
	}
	injectDepGraphCDX(bom)
	if bom.Dependencies == nil || len(*bom.Dependencies) != 2 {
		t.Errorf("want 2 dependency entries (no root), got %v", bom.Dependencies)
	}
}
