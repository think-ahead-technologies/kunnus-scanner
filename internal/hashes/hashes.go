// ABOUTME: Shared types for hash extraction across every evidence source.
// ABOUTME: Source-specific code (lockfiles today, OS packages or binaries tomorrow) lives in subpackages.
package hashes

// Algorithm identifies a hash algorithm in the form CDX/SPDX expects.
type Algorithm string

const (
	AlgSHA512 Algorithm = "SHA-512"
	AlgSHA256 Algorithm = "SHA-256"
	AlgSHA1   Algorithm = "SHA-1"
	AlgMD5    Algorithm = "MD5"
)

// Hash pairs an algorithm with a lowercase hex digest. Path is optional and
// set only for per-file evidence (today: vendored C/C++ source files). When
// non-empty it participates in dedup so two distinct files that happen to
// share a digest both survive — without it, an MD5 collision (or two empty
// files) would silently collapse to one entry.
type Hash struct {
	Algorithm Algorithm
	Hex       string
	Path      string
}

// Map is the canonical return type of every hash source: purl-string → []Hash.
// One PURL can carry multiple digests because Python wheels, conda channels, and
// container manifests publish one hash per distribution file. CDX components
// natively accept multiple hashes — the slice round-trips into component.hashes[].
type Map map[string][]Hash

// Add appends h under purl, deduplicating on (Algorithm, Hex) so the slice
// stays free of identical entries even when multiple lockfiles agree on the
// same digest.
func (m Map) Add(purl string, h Hash) {
	for _, existing := range m[purl] {
		if existing == h {
			return
		}
	}
	m[purl] = append(m[purl], h)
}

// Merge folds other into m, deduplicating on (Algorithm, Hex). Two sources
// that publish the same digest for the same PURL collapse to one entry;
// disagreeing digests both survive — surfacing the discrepancy in the SBOM
// is more informative than silently dropping one.
func (m Map) Merge(other Map) {
	for k, hs := range other {
		for _, h := range hs {
			m.Add(k, h)
		}
	}
}
