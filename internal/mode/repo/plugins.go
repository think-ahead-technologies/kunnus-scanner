// ABOUTME: Maps detected ecosystems to scalibr plugin names for source-code scans.
// ABOUTME: Ecosystem → plugins comes from internal/ecosystem; this file is now just override-intersection.
package repo

import (
	"slices"
)

// intersect returns the elements of a that also appear in b.
func intersect(a, b []string) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
