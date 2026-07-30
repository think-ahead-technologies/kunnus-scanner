// ABOUTME: Synthesises the CDX dependencies[] graph and compositions[] aggregate.
// ABOUTME: Honest about scan depth: root depends on every discovered component, transitive edges are unknown.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
)

// injectDepGraphCDX backfills the BOM's `dependencies[]` array and adds a
// `compositions[]` entry declaring how complete that graph is:
//
//   - every component must appear in `dependencies[]`, even those
//     with no known transitive edges (with `dependsOn` empty/omitted).
//   - components whose purl appears in edges (lockfile-mined, keyed by
//     conventional purl on both ends — the CISA Component Dependency
//     Relationship element) get their real dependsOn list; an edge whose
//     target purl matches no component is dropped, never invented.
//   - completeness of the dependency graph must be declared via
//     `compositions[].aggregate` — we say "incomplete" because our scan
//     observes presence-of-component, and real edges exist only for the
//     lockfile formats kunnus mines (Cargo.lock, composer.lock today).
//
// Existing entries are preserved (defensive against future scalibr versions
// emitting real edges); missing entries are added with empty dependsOn.
func injectDepGraphCDX(bom *cyclonedx.BOM, edges graph.Map) {
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

	// Components whose purl has lockfile-mined edges get their real dependsOn
	// list. The join uses the conventional purl form on both sides: this stage
	// runs before normalizePURLsCDX, so a namespaced component still carries
	// scalibr's %2F-escaped purl while edge maps use the decoded form.
	refByPURL := make(map[string]string)
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.BOMRef != "" && c.PackageURL != "" {
				refByPURL[normalizePURL(c.PackageURL)] = c.BOMRef
			}
		}
	}
	dependsOn := make(map[string][]string)
	if bom.Components != nil {
		for _, c := range *bom.Components {
			if c.BOMRef == "" || c.PackageURL == "" {
				continue
			}
			for _, target := range edges[normalizePURL(c.PackageURL)] {
				if ref, ok := refByPURL[target]; ok && ref != c.BOMRef {
					dependsOn[c.BOMRef] = append(dependsOn[c.BOMRef], ref)
				}
			}
		}
	}

	// Every non-root component must have an entry; dependsOn stays empty for
	// components with no mined edges.
	for _, ref := range allRefs {
		if have[ref] {
			continue
		}
		entry := cyclonedx.Dependency{Ref: ref}
		if targets := dependsOn[ref]; len(targets) > 0 {
			entry.Dependencies = &targets
		}
		existing = append(existing, entry)
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
