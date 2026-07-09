// ABOUTME: Fuzz targets for the Arduino parsers — arbitrary properties/YAML must never panic.
// ABOUTME: Both parsers must only return specs with a non-empty name.
package arduino

import (
	"strings"
	"testing"
)

// FuzzParseLibraryProperties drives parseLibraryProperties with arbitrary
// bytes. A non-nil spec must carry a non-empty name.
func FuzzParseLibraryProperties(f *testing.F) {
	seeds := []string{
		"",
		"name=Servo\nversion=1.2.1\n",
		"version=1.2.1\n",
		"# comment\nname = X \n",
		"=\n= =\nname==\n",
		"name=\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if p := parseLibraryProperties(strings.NewReader(data)); p != nil && p.name == "" {
			t.Fatalf("parseLibraryProperties(%q) returned spec with empty name", data)
		}
	})
}

// FuzzParseSketch drives parseSketch with arbitrary YAML. Every returned spec
// must carry a non-empty name.
func FuzzParseSketch(f *testing.F) {
	seeds := []string{
		"",
		"profiles:\n  p:\n    libraries:\n      - ArduinoJson (7.0.4)\n",
		"profiles:\n  p:\n    platforms:\n      - platform: esp32:esp32 (2.0.11)\n",
		"profiles:\n  p:\n    libraries:\n      - \" (1.0)\"\n",
		"profiles: 42\n",
		"\t{{{",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, p := range parseSketch(strings.NewReader(data)) {
			if p.name == "" {
				t.Fatalf("parseSketch(%q) returned spec with empty name", data)
			}
		}
	})
}
