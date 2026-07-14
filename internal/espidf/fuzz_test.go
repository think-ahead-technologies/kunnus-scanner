// ABOUTME: Fuzz targets for the ESP-IDF lockfile and manifest parsers — arbitrary YAML must never panic.
// ABOUTME: Both parsers must only return specs with a known purl type and a non-empty name.
package espidf

import (
	"strings"
	"testing"
)

// checkSpecs asserts the shared parser contract on every returned spec.
func checkSpecs(t *testing.T, input string, specs []pkgSpec) {
	t.Helper()
	for _, s := range specs {
		if s.name == "" {
			t.Fatalf("parser(%q) returned spec with empty name: %+v", input, s)
		}
		switch s.purlType {
		case "generic":
		case "github":
			if !strings.Contains(s.name, "/") {
				t.Fatalf("parser(%q) = github/%q without owner namespace", input, s.name)
			}
		default:
			t.Fatalf("parser(%q) has unknown purl type %q", input, s.purlType)
		}
	}
}

// FuzzParseLock drives parseLock with arbitrary lockfile bytes.
func FuzzParseLock(f *testing.F) {
	seeds := []string{
		"",
		"dependencies:\n  espressif/led_strip:\n    version: 2.5.5\n",
		"dependencies:\n  idf:\n    source:\n      type: idf\n    version: 5.3.1\n",
		"dependencies: []\n",
		"dependencies: 42\n",
		"\t{{{",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		checkSpecs(t, data, parseLock(strings.NewReader(data)))
	})
}

// FuzzParseManifest drives parseManifest with arbitrary manifest bytes.
func FuzzParseManifest(f *testing.F) {
	seeds := []string{
		"",
		"dependencies:\n  idf: \">=5.0\"\n",
		"dependencies:\n  mdns: \"*\"\n",
		"dependencies:\n  x:\n    git: https://github.com/owner/repo.git\n    version: v1.0\n",
		"dependencies:\n  common:\n    path: ../common\n",
		"dependencies:\n  a: [1, 2]\n",
		"dependencies: \"just a string\"\n",
		"\t{{{",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		checkSpecs(t, data, parseManifest(strings.NewReader(data)))
	})
}
