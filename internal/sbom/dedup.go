// ABOUTME: Stage: collapses CDX components sharing a PURL into one entry with combined evidence.
// ABOUTME: Scalibr emits a separate component per extractor that finds a package; the spec asks for one.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// dedupCDXComponents collapses components that share a PURL into a single
// component carrying every distinct evidence occurrence. The first component
// for each PURL wins for bom-ref, name, and version. Empty fields on the
// winner are backfilled from any later duplicate that has them (so a duplicate
// carrying a Supplier we missed doesn't get thrown away).
//
// Components without a PURL pass through unchanged — we cannot prove two
// PURL-less entries describe the same artifact, so we keep them distinct.
func dedupCDXComponents(bom *cyclonedx.BOM) {
	if bom == nil || bom.Components == nil {
		return
	}
	comps := *bom.Components
	if len(comps) == 0 {
		return
	}

	index := make(map[string]int, len(comps))
	out := make([]cyclonedx.Component, 0, len(comps))

	for i := range comps {
		c := comps[i]
		if c.PackageURL == "" {
			out = append(out, c)
			continue
		}
		if existing, ok := index[c.PackageURL]; ok {
			mergeInto(&out[existing], &c)
			continue
		}
		index[c.PackageURL] = len(out)
		out = append(out, c)
	}

	*bom.Components = out
}

// mergeInto folds src into dst: backfills any zero-value identity fields on dst,
// concatenates evidence occurrences (dedup'd by location), merges properties by
// name, and appends external references and hashes.
func mergeInto(dst, src *cyclonedx.Component) {
	if dst.CPE == "" && src.CPE != "" {
		dst.CPE = src.CPE
	}
	if dst.Supplier == nil && src.Supplier != nil {
		dst.Supplier = src.Supplier
	}
	if dst.Manufacturer == nil && src.Manufacturer != nil {
		dst.Manufacturer = src.Manufacturer
	}
	if dst.Licenses == nil && src.Licenses != nil {
		dst.Licenses = src.Licenses
	}
	if dst.Description == "" && src.Description != "" {
		dst.Description = src.Description
	}

	dst.Evidence = mergeEvidence(dst.Evidence, src.Evidence)
	dst.Properties = mergePropertiesByName(dst.Properties, src.Properties)
	dst.ExternalReferences = mergeExternalRefs(dst.ExternalReferences, src.ExternalReferences)
	dst.Hashes = appendHashes(dst.Hashes, src.Hashes)
}

// mergeEvidence folds src into dst, deduplicating occurrences by location+symbol.
// Evidence-occurrence merging is dedup-specific; the generic CDX-slice helpers
// in cdx_slices.go don't fit because EvidenceOccurrence isn't pointer-wrapped.
func mergeEvidence(dst, src *cyclonedx.Evidence) *cyclonedx.Evidence {
	if src == nil {
		return dst
	}
	if dst == nil {
		return src
	}
	if src.Occurrences == nil {
		return dst
	}
	if dst.Occurrences == nil {
		dst.Occurrences = src.Occurrences
		return dst
	}
	seen := make(map[occurrenceKey]bool, len(*dst.Occurrences))
	for _, o := range *dst.Occurrences {
		seen[occKey(o)] = true
	}
	for _, o := range *src.Occurrences {
		if seen[occKey(o)] {
			continue
		}
		*dst.Occurrences = append(*dst.Occurrences, o)
		seen[occKey(o)] = true
	}
	return dst
}

type occurrenceKey struct {
	location string
	symbol   string
}

func occKey(o cyclonedx.EvidenceOccurrence) occurrenceKey {
	return occurrenceKey{location: o.Location, symbol: o.Symbol}
}
