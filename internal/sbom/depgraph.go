// ABOUTME: Synthesises the CDX dependencies[] graph and compositions[] aggregate per BSI claims 176-178.
// ABOUTME: Honest about scan depth: root depends on every discovered component, transitive edges are unknown.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// injectDepGraphCDX backfills the BOM's `dependencies[]` array and adds a
// `compositions[]` entry declaring how complete that graph is. The two-step
// rationale comes straight from TR-03183-2 v2.1:
//
//   - every component MUST appear in `dependencies[]`, even those
//     with no known transitive edges (with `dependsOn` empty/omitted).
//   - completeness of the dependency graph MUST be declared via
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

	// Every non-root component: empty dependsOn (per claim 177).
	for _, ref := range allRefs {
		if have[ref] {
			continue
		}
		existing = append(existing, cyclonedx.Dependency{Ref: ref})
		have[ref] = true
	}

	bom.Dependencies = &existing

	// Composition completeness — claim 176. Reference every bom-ref we now
	// have a dependency entry for, so consumers can tie the assertion to the
	// specific graph.
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
