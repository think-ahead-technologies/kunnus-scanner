// ABOUTME: Fuzz target for the vcpkg.json manifest parser — feeds arbitrary bytes and checks the dep contract.
// ABOUTME: parseManifest must never panic and every dep it returns must carry a non-empty name.
package vcpkg

import (
	"strings"
	"testing"
)

// FuzzParseManifest drives parseManifest with arbitrary manifest bytes. The
// invariant is the parser's own contract: every returned dep carries a
// non-empty name (an empty name would produce a malformed PURL). Malformed
// JSON, wrong-typed fields, and truncated input must return nil, not panic.
func FuzzParseManifest(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		"[1, 2, 3]",
		`{"dependencies": ["fmt", "zlib"]}`,
		`{"dependencies": [{"name": "openssl", "version>=": "3.3.2#1"}]}`,
		`{"dependencies": ["zlib"], "overrides": [{"name": "zlib", "version": "1.3.1"}]}`,
		`{"dependencies": [{"features": ["ssl"]}]}`,
		`{"dependencies": [`,
		`{"dependencies": [42, true, null]}`,
		`{"overrides": [{"name": "zlib"}]}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		for _, d := range parseManifest(strings.NewReader(data)) {
			if d.name == "" {
				t.Fatalf("parseManifest(%q) returned dep with empty name: %+v", data, d)
			}
		}
	})
}
