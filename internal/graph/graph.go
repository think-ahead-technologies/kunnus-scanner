// ABOUTME: graph.Map carries component dependency edges keyed by purl, produced by offline lockfile parsers.
// ABOUTME: Mirrors hashes.Map and license.Map so a single Survey pass can fold every parser's output together.
package graph

// Map is source purl → dependsOn purls, the output of every offline
// dependency-graph parser. Keys and values use the conventional (normalized)
// purl form so the SBOM encoder can match them against components after purl
// normalization. Only edges between packages the lockfile itself pins are
// recorded — a parser never invents a purl for a target it cannot resolve.
type Map map[string][]string

// Add records the edge from → to, ignoring blank endpoints and deduplicating
// exact repeats so a parser that sees the same requirement twice does not
// bloat the slice.
func (m Map) Add(from, to string) {
	if from == "" || to == "" {
		return
	}
	for _, existing := range m[from] {
		if existing == to {
			return
		}
	}
	m[from] = append(m[from], to)
}

// Merge folds other into m, preserving Add's dedup semantics.
func (m Map) Merge(other Map) {
	for from, tos := range other {
		for _, to := range tos {
			m.Add(from, to)
		}
	}
}
