// ABOUTME: license.Map carries raw, un-normalized license strings keyed by purl, produced by offline lockfile parsers.
// ABOUTME: Mirrors hashes.Map so a single survey pass can fold every parser's output together before encoding.
package license

import "strings"

// Map is purl-string → raw license strings, the output of every offline license
// parser. Keys use the conventional (normalized) purl form so the SBOM encoder
// can match them against components after purl normalization. Raw values are
// normalized to SPDX later, by Normalize, at encode time — keeping parsers
// simple (read the field, hand it over).
type Map map[string][]string

// Add appends a raw license string under purl, ignoring blank values and
// deduplicating exact repeats so a parser that sees the same license twice does
// not bloat the slice.
func (m Map) Add(purl, raw string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	for _, existing := range m[purl] {
		if existing == raw {
			return
		}
	}
	m[purl] = append(m[purl], raw)
}

// Merge folds other into m, preserving Add's dedup semantics.
func (m Map) Merge(other Map) {
	for purl, raws := range other {
		for _, raw := range raws {
			m.Add(purl, raw)
		}
	}
}
