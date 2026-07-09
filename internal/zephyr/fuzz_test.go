// ABOUTME: Fuzz target for the west.yml manifest parser — arbitrary YAML must never panic.
// ABOUTME: Every returned spec must carry a known purl type and a non-empty name; github names must be owner/repo namespaced.
package zephyr

import (
	"strings"
	"testing"
)

// FuzzParseManifest drives parseManifest with arbitrary manifest bytes. The
// invariant is the parser's own contract: every returned spec carries a
// non-empty name with a known PURL type, and a github name is owner/repo
// namespaced. Malformed YAML must return nil, not panic.
func FuzzParseManifest(f *testing.F) {
	seeds := []string{
		"",
		"manifest:\n  remotes:\n    - name: up\n      url-base: https://github.com/org\n  projects:\n    - name: lib\n      revision: v1.0\n",
		"manifest:\n  defaults:\n    remote: up\n    revision: main\n  projects:\n    - name: lib\n",
		"manifest:\n  projects:\n    - name: lib\n      url: https://git.example.com/lib.git\n",
		"manifest:\n  projects:\n    - revision: v1.0\n",
		"manifest:\n  projects: 42\n",
		"manifest: []\n",
		"\t{{{",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		for _, s := range parseManifest(strings.NewReader(data)) {
			if s.name == "" {
				t.Fatalf("parseManifest(%q) returned spec with empty name: %+v", data, s)
			}
			switch s.purlType {
			case "generic":
			case "github":
				if !strings.Contains(s.name, "/") {
					t.Fatalf("parseManifest(%q) = github/%q without owner namespace", data, s.name)
				}
			default:
				t.Fatalf("parseManifest(%q) has unknown purl type %q", data, s.purlType)
			}
		}
	})
}
