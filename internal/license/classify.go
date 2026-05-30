// ABOUTME: Full-text license classifier — identifies SPDX licences from licence prose (copyright/LICENSE files).
// ABOUTME: The probabilistic complement to Normalize; callers use it only as a fallback to structured parsing.
package license

import "github.com/google/licensecheck"

// Classify identifies the SPDX licences present in free-form licence text — a
// Debian copyright file, a LICENSE file, a JAR's bundled notice — using a
// full-text classifier (google/licensecheck). It is the probabilistic
// counterpart to Normalize: Normalize maps a declared identifier, Classify
// recognises licence prose. Because it is probabilistic, callers should use it
// only as a fallback when structured parsing finds no declared licence, so
// deterministic results never change.
//
// It returns the SPDX identifier of each licence the classifier matches with
// confidence (licensecheck applies its own per-licence coverage threshold),
// excluding bare URL matches, deduplicated in match order. Empty when no licence
// text is recognised. The returned identifiers are already SPDX, but callers may
// still run them through Normalize for a uniform pipeline.
func Classify(text []byte) []string {
	cov := licensecheck.Scan(text)
	var out []string
	seen := make(map[string]bool)
	for _, m := range cov.Match {
		if m.IsURL || seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		out = append(out, m.ID)
	}
	return out
}
