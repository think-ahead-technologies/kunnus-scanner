// ABOUTME: Synthesises the CDX dependencies[] graph and compositions[] aggregate.
// ABOUTME: Honest about scan depth: root depends on every discovered component, transitive edges are unknown.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// injectDepGraphCDX backfills the BOM's `dependencies[]` array and adds a
// `compositions[]` entry declaring how complete that graph is:
//
//   - every component must appear in `dependencies[]`, even those
//     with no known transitive edges (with `dependsOn` empty/omitted).
//   - completeness of the dependency graph must be declared via
//     `compositions[].aggregate` — we say "incomplete" because our scan
//     observes presence-of-component, not transitive edges between them.
//
// Existing entries are preserved (defensive against future scalibr versions
// emitting real edges); missing entries are added with empty dependsOn.
func injectDepGraphCDX(bom *cyclonedx.BOM) {
	if bom == nil {
		return
	}

	var existing []cyclonedx.Dependency
	if bom.Dependencies != nil {
		existing = *bom.Dependencies
	}
	have := make(map[string]bool, len(existing))
	for _, d := range existing {
		have[d.Ref] = true
	}

	allRefs := make([]string, 0)
	rootRef := ""
	if bom.Metadata != nil && bom.Metadata.Component != nil && bom.Metadata.Component.BOMRef != "" {
		rootRef = bom.Metadata.Component.BOMRef
	}

	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.BOMRef == "" {
				continue
			}
			allRefs = append(allRefs, c.BOMRef)
		}
	}

	// Root component: depends on every discovered component (presence claim,
	// not a transitive-edge claim — composition.aggregate will mark this as
	// incomplete so consumers know not to over-interpret).
	if rootRef != "" && !have[rootRef] {
		refs := append([]string(nil), allRefs...)
		entry := cyclonedx.Dependency{Ref: rootRef}
		if len(refs) > 0 {
			entry.Dependencies = &refs
		}
		existing = append(existing, entry)
		have[rootRef] = true
	}

	// Every non-root component must have an entry; dependsOn stays empty
	// because we don't observe transitive edges.
	for _, ref := range allRefs {
		if have[ref] {
			continue
		}
		existing = append(existing, cyclonedx.Dependency{Ref: ref})
		have[ref] = true
	}

	bom.Dependencies = &existing

	// Composition completeness: reference every bom-ref we now have a
	// dependency entry for, so consumers can tie the "incomplete" assertion
	// to the specific graph.
	refs := make([]cyclonedx.BOMReference, 0, len(existing))
	for _, d := range existing {
		refs = append(refs, cyclonedx.BOMReference(d.Ref))
	}
	composition := cyclonedx.Composition{
		Aggregate:    cyclonedx.CompositionAggregateIncomplete,
		Dependencies: &refs,
	}
	if bom.Compositions == nil {
		bom.Compositions = &[]cyclonedx.Composition{composition}
	} else {
		*bom.Compositions = append(*bom.Compositions, composition)
	}
}
