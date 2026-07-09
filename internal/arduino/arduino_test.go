// ABOUTME: Tests for the Arduino extractor: real-fixture extraction over scalibr's walk plus unit tests for both formats.
// ABOUTME: Fixtures mirror real Arduino trees: vendored libraries with library.properties, and an arduino-cli sketch.yaml with profiles.
package arduino

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"
)

// libraryProperties is a real-shaped Arduino library metadata file (the
// ArduinoJson one, abbreviated).
const libraryProperties = `name=ArduinoJson
version=7.0.4
author=Benoit Blanchon <blog.benoitblanchon.fr>
maintainer=Benoit Blanchon <blog.benoitblanchon.fr>
sentence=A simple and efficient JSON library for embedded C++.
paragraph=ArduinoJson supports serialization, deserialization, MessagePack.
category=Data Processing
url=https://arduinojson.org/
architectures=*
repository=https://github.com/bblanchon/ArduinoJson.git
license=MIT
depends=SomeOtherLib
`

// sketchYAML is a real-shaped arduino-cli sketch project file: two profiles
// pinning platform cores and libraries.
const sketchYAML = `profiles:
  nanorp:
    fqbn: arduino:mbed_nano:nanorp2040connect
    platforms:
      - platform: arduino:mbed_nano (4.0.2)
    libraries:
      - ArduinoIoTCloud (1.12.0)
      - WiFiNINA (1.8.14)
  esp32:
    fqbn: esp32:esp32:esp32
    platforms:
      - platform: esp32:esp32 (2.0.11)
        platform_index_url: https://espressif.github.io/arduino-esp32/package_esp32_index.json
    libraries:
      - PubSubClient (2.8)

default_profile: nanorp
`

// TestExtract runs the extractor through scalibr's real filesystem walk over a
// sketch with a sketch.yaml and a vendored library, asserting both formats
// surface components. A decoy .properties file proves the FileRequired gate.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "sketch", "sketch.yaml"), sketchYAML)
	writeFile(t, filepath.Join(root, "sketch", "libraries", "ArduinoJson", "library.properties"), libraryProperties)
	writeFile(t, filepath.Join(root, "sketch", "gradle.properties"), "name=decoy\nversion=9.9.9\n")

	inv := run(t, root)

	want := map[string]string{ // name -> version
		"ArduinoJson":       "7.0.4",
		"ArduinoIoTCloud":   "1.12.0",
		"WiFiNINA":          "1.8.14",
		"PubSubClient":      "2.8",
		"arduino:mbed_nano": "4.0.2",
		"esp32:esp32":       "2.0.11",
	}
	got := map[string]string{}
	for _, p := range inv.Packages {
		if p.Name == "decoy" {
			t.Errorf("decoy gradle.properties was parsed: %+v", p)
		}
		if p.PURLType != "generic" {
			t.Errorf("package %q has PURLType %q, want generic", p.Name, p.PURLType)
		}
		got[p.Name] = p.Version
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages %v, want %d", len(got), got, len(want))
	}
	for name, ver := range want {
		gotVer, ok := got[name]
		if !ok {
			t.Errorf("package %q missing (all: %v)", name, got)
			continue
		}
		if gotVer != ver {
			t.Errorf("package %q version = %q, want %q", name, gotVer, ver)
		}
	}
}

// TestParseLibraryProperties covers the properties grammar: the two fields we
// read, missing fields, comments, and malformed lines.
func TestParseLibraryProperties(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantName string // "" = expect no package
		wantVer  string
	}{
		{"name and version", "name=Servo\nversion=1.2.1\n", "Servo", "1.2.1"},
		{"name only", "name=Servo\n", "Servo", ""},
		{"spaces trimmed", "name = Servo \nversion = 1.2.1\n", "Servo", "1.2.1"},
		{"comments skipped", "# a comment\nname=Servo\nversion=1.2.1\n", "Servo", "1.2.1"},
		{"no name", "version=1.2.1\nauthor=x\n", "", ""},
		{"empty", "", "", ""},
		{"garbage lines tolerated", "!!!\nname=Servo\n= =\nversion=1.2.1\n", "Servo", "1.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := parseLibraryProperties(strings.NewReader(tc.src))
			if tc.wantName == "" {
				if p != nil {
					t.Fatalf("parseLibraryProperties = %+v, want nil", p)
				}
				return
			}
			if p == nil || p.name != tc.wantName || p.version != tc.wantVer {
				t.Fatalf("parseLibraryProperties = %+v, want %s@%s", p, tc.wantName, tc.wantVer)
			}
		})
	}
}

// TestParseSketch covers the sketch.yaml grammar: parenthesized versions,
// version-less entries, platform entries in both scalar and mapping form, and
// malformed input.
func TestParseSketch(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want map[string]string // name -> version; nil = expect none
	}{
		{
			"library with version",
			"profiles:\n  p:\n    libraries:\n      - ArduinoJson (7.0.4)\n",
			map[string]string{"ArduinoJson": "7.0.4"},
		},
		{
			"library without version",
			"profiles:\n  p:\n    libraries:\n      - ArduinoJson\n",
			map[string]string{"ArduinoJson": ""},
		},
		{
			"library name with spaces",
			"profiles:\n  p:\n    libraries:\n      - Adafruit GFX Library (1.11.9)\n",
			map[string]string{"Adafruit GFX Library": "1.11.9"},
		},
		{
			"platform mapping form",
			"profiles:\n  p:\n    platforms:\n      - platform: esp32:esp32 (2.0.11)\n        platform_index_url: https://example.com/x.json\n",
			map[string]string{"esp32:esp32": "2.0.11"},
		},
		{
			"two profiles merge",
			"profiles:\n  a:\n    libraries:\n      - X (1.0)\n  b:\n    libraries:\n      - Y (2.0)\n",
			map[string]string{"X": "1.0", "Y": "2.0"},
		},
		{"no profiles", "default_profile: p\n", nil},
		{"malformed yaml", "\t{{{", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := parseSketch(strings.NewReader(tc.src))
			got := map[string]string{}
			for _, p := range pkgs {
				got[p.name] = p.version
			}
			if tc.want == nil {
				if len(pkgs) != 0 {
					t.Fatalf("parseSketch = %v, want none", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseSketch = %v, want %v", got, tc.want)
			}
			for name, ver := range tc.want {
				if got[name] != ver {
					t.Errorf("entry %q version = %q, want %q", name, got[name], ver)
				}
			}
		})
	}
}

func run(t *testing.T, root string) inventory.Inventory {
	t.Helper()
	inv, _, err := filesystem.Run(context.Background(), &filesystem.Config{
		Extractors: []filesystem.Extractor{New()},
		ScanRoots:  scalibrfs.RealFSScanRoots(root),
		Stats:      stats.NoopCollector{},
	})
	if err != nil {
		t.Fatalf("filesystem.Run: %v", err)
	}
	return inv
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
