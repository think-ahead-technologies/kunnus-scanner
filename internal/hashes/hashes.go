// ABOUTME: Shared types for hash extraction across every evidence source.
// ABOUTME: Source-specific code (lockfiles today, OS packages or binaries tomorrow) lives in subpackages.
package hashes

// Algorithm identifies a hash algorithm in the form CDX/SPDX expects.
type Algorithm string

const (
	AlgSHA512 Algorithm = "SHA-512"
	AlgSHA256 Algorithm = "SHA-256"
)

// Hash pairs an algorithm with a lowercase hex digest.
type Hash struct {
	Algorithm Algorithm
	Hex       string
}

// Map is the canonical return type of every hash source: purl-string → Hash.
// A zero-value Hash means we found no hash for that PURL.
type Map map[string]Hash

// Merge folds other into m. m wins on conflicts — callers compose sources in
// trust order, most-trusted first.
func (m Map) Merge(other Map) {
	for k, v := range other {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
}
