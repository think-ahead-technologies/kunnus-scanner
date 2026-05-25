// ABOUTME: CycloneDX *[]T plumbing helpers shared across enrichment stages.
// ABOUTME: cyclonedx-go represents every slice as *[]T (nullable), so most append/merge work touches these.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// forEachComponent runs fn for each top-level component in the BOM, passing
// a mutable pointer so stages can edit in place. It is a no-op when the BOM
// or its Components slice is nil, which absorbs the guard most stages
// otherwise duplicate.
func forEachComponent(bom *cyclonedx.BOM, fn func(*cyclonedx.Component)) {
	if bom == nil || bom.Components == nil {
		return
	}
	for i := range *bom.Components {
		fn(&(*bom.Components)[i])
	}
}

// mergePropertiesByName folds src into dst, keeping the first Property seen
// for any given Name. dst nil + src non-nil produces a fresh slice.
func mergePropertiesByName(dst, src *[]cyclonedx.Property) *[]cyclonedx.Property {
	if src == nil {
		return dst
	}
	if dst == nil {
		out := make([]cyclonedx.Property, len(*src))
		copy(out, *src)
		return &out
	}
	seen := make(map[string]bool, len(*dst))
	for _, p := range *dst {
		seen[p.Name] = true
	}
	for _, p := range *src {
		if seen[p.Name] {
			continue
		}
		*dst = append(*dst, p)
		seen[p.Name] = true
	}
	return dst
}

// mergeExternalRefs folds src into dst, deduplicating on (URL, Type). dst nil
// + src non-nil produces a fresh slice.
func mergeExternalRefs(dst, src *[]cyclonedx.ExternalReference) *[]cyclonedx.ExternalReference {
	if src == nil {
		return dst
	}
	if dst == nil {
		out := make([]cyclonedx.ExternalReference, len(*src))
		copy(out, *src)
		return &out
	}
	type refKey struct {
		url  string
		kind cyclonedx.ExternalReferenceType
	}
	seen := make(map[refKey]bool, len(*dst))
	for _, r := range *dst {
		seen[refKey{r.URL, r.Type}] = true
	}
	for _, r := range *src {
		k := refKey{r.URL, r.Type}
		if seen[k] {
			continue
		}
		*dst = append(*dst, r)
		seen[k] = true
	}
	return dst
}

// appendHashes folds src into dst, deduplicating on (Algorithm, Value). dst
// nil + src non-nil produces a fresh slice.
func appendHashes(dst, src *[]cyclonedx.Hash) *[]cyclonedx.Hash {
	if src == nil {
		return dst
	}
	if dst == nil {
		out := make([]cyclonedx.Hash, len(*src))
		copy(out, *src)
		return &out
	}
	type hashKey struct {
		alg cyclonedx.HashAlgorithm
		val string
	}
	seen := make(map[hashKey]bool, len(*dst))
	for _, h := range *dst {
		seen[hashKey{h.Algorithm, h.Value}] = true
	}
	for _, h := range *src {
		k := hashKey{h.Algorithm, h.Value}
		if seen[k] {
			continue
		}
		*dst = append(*dst, h)
		seen[k] = true
	}
	return dst
}
