// ABOUTME: Tests injectDepGraphCDX — synthesises the dependencies[] and compositions[] arrays.
// ABOUTME: Every component must appear in dependencies[]; completeness is declared via compositions[].
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
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

	injectDepGraphCDX(bom, nil)

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

	// Every non-root entry must exist with empty dependsOn.
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
	injectDepGraphCDX(bom, nil)

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
	injectDepGraphCDX(bom, nil)

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
	injectDepGraphCDX(nil, nil)
	injectDepGraphCDX(&cyclonedx.BOM{}, nil)
	injectDepGraphCDX(&cyclonedx.BOM{Components: &[]cyclonedx.Component{}}, nil)
}

func TestInjectDepGraphCDX_NoRootIsHandled(t *testing.T) {
	// If for any reason the BOM has no metadata.component, every component
	// still gets an entry (the spec requires it) and there's no root entry.
	bom := &cyclonedx.BOM{
		Components: &[]cyclonedx.Component{
			{BOMRef: "a"},
			{BOMRef: "b"},
		},
	}
	injectDepGraphCDX(bom, nil)
	if bom.Dependencies == nil || len(*bom.Dependencies) != 2 {
		t.Errorf("want 2 dependency entries (no root), got %v", bom.Dependencies)
	}
}

func TestInjectDepGraphCDX_RealEdgesFromGraphMap(t *testing.T) {
	// Lockfile-mined edges (graph.Map, purl-keyed on both ends) become each
	// component's dependsOn list — the CISA Component Dependency Relationship
	// with real transitive structure, not just the root presence claim. Edges
	// whose target purl matches no component are dropped (never invent a ref).
	bomDoc := &cyclonedx.BOM{
		Metadata: &cyclonedx.Metadata{
			Component: &cyclonedx.Component{BOMRef: "root-ref", Name: "my-repo"},
		},
		Components: &[]cyclonedx.Component{
			{BOMRef: "ref-app", Name: "my-app", PackageURL: "pkg:cargo/my-app@0.1.0"},
			{BOMRef: "ref-libc", Name: "libc", PackageURL: "pkg:cargo/libc@0.2.147"},
			{BOMRef: "ref-log", Name: "psr/log", PackageURL: "pkg:composer/psr%2Flog@3.0.0"},
		},
	}
	edges := graph.Map{
		"pkg:cargo/my-app@0.1.0": {
			"pkg:cargo/libc@0.2.147",
			"pkg:cargo/not-in-bom@9.9.9", // unknown target: dropped
		},
		// Keyed by the conventional purl; the component above carries scalibr's
		// %2F-escaped form, so this proves the normalized-purl join.
		"pkg:composer/psr/log@3.0.0": {"pkg:cargo/libc@0.2.147"},
	}

	injectDepGraphCDX(bomDoc, edges)

	byRef := map[string][]string{}
	for _, d := range *bomDoc.Dependencies {
		if d.Dependencies != nil {
			byRef[d.Ref] = *d.Dependencies
		}
	}
	if got := byRef["ref-app"]; len(got) != 1 || got[0] != "ref-libc" {
		t.Errorf("my-app dependsOn = %v, want [ref-libc]", got)
	}
	if got := byRef["ref-log"]; len(got) != 1 || got[0] != "ref-libc" {
		t.Errorf("psr/log dependsOn = %v, want [ref-libc] (normalized-purl join)", got)
	}
	// The root presence claim is unchanged: root depends on every component.
	if got := byRef["root-ref"]; len(got) != 3 {
		t.Errorf("root dependsOn = %v, want all 3 components", got)
	}
}
