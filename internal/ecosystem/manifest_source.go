// ABOUTME: Offline license parsers for source manifests that declare the licence as a language assignment.
// ABOUTME: Lua .rockspec (license = "...") and Ruby .gemspec (s.license(s) = ...) — targeted regex, not a full interpreter.
package ecosystem

import (
	"io"
	"regexp"
)

// maxSourceManifestBytes caps how much of a .rockspec / .gemspec we read; these
// declarative manifests are small.
const maxSourceManifestBytes = 1 << 20 // 1 MiB

// rockspecLicenseRe matches a Lua rockspec `license = "MIT"` assignment (either
// quote style). The leading \b keeps it from matching "sublicense" and friends.
var rockspecLicenseRe = regexp.MustCompile(`\blicense\s*=\s*["']([^"']+)["']`)

// parseRockspecLicense extracts the licence declared in a Lua .rockspec. A
// rockspec is Lua source, so this matches the conventional `license = "..."`
// assignment rather than interpreting the file; a rockspec that computes its
// licence dynamically (rare) yields nothing.
func parseRockspecLicense(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSourceManifestBytes))
	if err != nil {
		return nil, err
	}
	if m := rockspecLicenseRe.FindSubmatch(data); m != nil {
		return []string{string(m[1])}, nil
	}
	return nil, nil
}

// Ruby gemspec licence assignments: `s.licenses = [...]` (array) preferred, then
// `s.license = "..."` (single). The block variable (s/spec/gem/...) varies, so
// these match on the `.license(s) =` suffix.
var (
	gemspecLicensesRe = regexp.MustCompile(`\.licenses\s*=\s*\[([^\]]*)\]`)
	gemspecLicenseRe  = regexp.MustCompile(`\.license\s*=\s*["']([^"']+)["']`)
	quotedStringRe    = regexp.MustCompile(`["']([^"']+)["']`)
)

// parseGemspecLicense extracts the licence(s) declared in a Ruby .gemspec. Like
// the rockspec parser it reads the conventional declarative assignment rather
// than executing Ruby; a gemspec that builds its licence list dynamically
// yields nothing.
func parseGemspecLicense(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSourceManifestBytes))
	if err != nil {
		return nil, err
	}
	if m := gemspecLicensesRe.FindSubmatch(data); m != nil {
		var out []string
		for _, q := range quotedStringRe.FindAllSubmatch(m[1], -1) {
			out = append(out, string(q[1]))
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if m := gemspecLicenseRe.FindSubmatch(data); m != nil {
		return []string{string(m[1])}, nil
	}
	return nil, nil
}
