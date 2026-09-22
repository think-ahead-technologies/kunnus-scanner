// ABOUTME: Tests for the PlatformIO extractor: real-fixture extraction over scalibr's walk plus unit tests for lib_deps entry parsing.
// ABOUTME: The fixture is a realistic platformio.ini exercising multi-env sections, both lib_deps forms, registry specs and VCS URLs.
package platformio

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

// fixtureINI is a realistic platformio.ini: two environments, the multi-line
// lib_deps form with owner/name registry specs (with and without spaces around
// @), a bare library name, a github VCS URL pinned to a tag, entries that must
// be skipped (local paths, interpolations), and a single-line lib_deps.
const fixtureINI = `; PlatformIO Project Configuration File
[platformio]
default_envs = esp32dev

[env:esp32dev]
platform = espressif32
board = esp32dev
framework = arduino
monitor_speed = 115200
lib_deps =
    bblanchon/ArduinoJson @ 6.21.5
    knolleary/PubSubClient@2.8
    ESP Async WebServer
    https://github.com/me-no-dev/AsyncTCP.git#v1.1.1
    file://../local-lib
    symlink://../other-lib
    ${common.lib_deps}

[env:native]
platform = native
lib_deps = fabiobatsilva/ArduinoFake @ 0.4.0
build_flags = -std=c++17
`

// TestExtract runs the extractor through scalibr's real filesystem walk,
// asserting registry specs, bare names, and github URLs surface with verbatim
// versions, across both env sections and both lib_deps layouts. A decoy .ini
// proves the FileRequired gate.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "platformio.ini"), fixtureINI)
	writeFile(t, filepath.Join(root, "proj", "other.ini"),
		"[env:x]\nlib_deps = decoy/Appear @ 1.0.0\n")

	inv := run(t, root)

	type pkg struct{ purlType, version string }
	want := map[string]pkg{
		"bblanchon/ArduinoJson":     {"generic", "6.21.5"},
		"knolleary/PubSubClient":    {"generic", "2.8"},
		"ESP Async WebServer":       {"generic", ""},
		"me-no-dev/AsyncTCP":        {"github", "v1.1.1"},
		"fabiobatsilva/ArduinoFake": {"generic", "0.4.0"},
	}

	got := map[string]pkg{}
	for _, p := range inv.Packages {
		if strings.Contains(p.Name, "Appear") {
			t.Errorf("decoy other.ini was parsed: %+v", p)
		}
		got[p.Name] = pkg{p.PURLType, p.Version}
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages %v, want %d", len(got), got, len(want))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("package %q missing (all: %v)", name, got)
			continue
		}
		if g != w {
			t.Errorf("package %q = %+v, want %+v", name, g, w)
		}
	}
}

// TestParseEntry covers the lib_deps entry grammar directly: every registry
// spec form, VCS URLs, and the local/interpolated entries that must be dropped.
func TestParseEntry(t *testing.T) {
	cases := []struct {
		name     string
		entry    string
		wantType string // "" means "expect no package"
		wantName string
		wantVer  string
	}{
		{"bare name", "PubSubClient", "generic", "PubSubClient", ""},
		{"name with spaces", "ESP Async WebServer", "generic", "ESP Async WebServer", ""},
		{"name at version", "PubSubClient@2.8", "generic", "PubSubClient", "2.8"},
		{"owner slash name", "bblanchon/ArduinoJson@^6.21.3", "generic", "bblanchon/ArduinoJson", "^6.21.3"},
		{"spaces around at", "bblanchon/ArduinoJson @ ~5.6,!=5.4", "generic", "bblanchon/ArduinoJson", "~5.6,!=5.4"},
		{"github https with tag", "https://github.com/me-no-dev/AsyncTCP.git#v1.1.1", "github", "me-no-dev/AsyncTCP", "v1.1.1"},
		{"github https no ref", "https://github.com/me-no-dev/AsyncTCP", "github", "me-no-dev/AsyncTCP", ""},
		{"git+https github", "git+https://github.com/owner/repo#main", "github", "owner/repo", "main"},
		{"non-github vcs", "https://gitlab.com/group/lib.git#v2.0", "generic", "lib", "v2.0"},
		{"zip archive url", "https://example.com/downloads/mylib.zip", "generic", "mylib.zip", ""},
		{"file url dropped", "file://../local-lib", "", "", ""},
		{"symlink url dropped", "symlink://../other-lib", "", "", ""},
		{"interpolation dropped", "${common.lib_deps}", "", "", ""},
		{"empty", "", "", "", ""},
		{"version only", "@1.0", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := parseEntry(tc.entry)
			if tc.wantType == "" {
				if p != nil {
					t.Fatalf("parseEntry(%q) = %+v, want nil", tc.entry, p)
				}
				return
			}
			if p == nil {
				t.Fatalf("parseEntry(%q) = nil, want %s/%s@%s", tc.entry, tc.wantType, tc.wantName, tc.wantVer)
			}
			if p.purlType != tc.wantType || p.name != tc.wantName || p.version != tc.wantVer {
				t.Errorf("parseEntry(%q) = %s/%s@%s, want %s/%s@%s",
					tc.entry, p.purlType, p.name, p.version, tc.wantType, tc.wantName, tc.wantVer)
			}
		})
	}
}

// TestParseINI covers the config layout: single-line values, multi-line
// continuations ended by the next key or section, comments, and lib_deps
// appearing in several sections.
func TestParseINI(t *testing.T) {
	cases := []struct {
		name string
		ini  string
		want []string
	}{
		{"single line", "[env:a]\nlib_deps = X@1.0\n", []string{"X@1.0"}},
		{
			"multi line ends at next key",
			"[env:a]\nlib_deps =\n    X@1.0\n    Y\nbuild_flags = -Os\n",
			[]string{"X@1.0", "Y"},
		},
		{
			"multi line ends at next section",
			"[env:a]\nlib_deps =\n    X@1.0\n[env:b]\nboard = uno\n",
			[]string{"X@1.0"},
		},
		{
			"two sections both collected",
			"[env:a]\nlib_deps = X@1.0\n[env:b]\nlib_deps =\n    Y@2.0\n",
			[]string{"X@1.0", "Y@2.0"},
		},
		{
			"comments skipped",
			"[env:a]\nlib_deps =\n    ; a comment\n    # another\n    X@1.0\n",
			[]string{"X@1.0"},
		},
		{"lib_deps of other key not matched", "[env:a]\nlib_deps_extra = X@1.0\n", nil},
		{"empty file", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseINI(strings.NewReader(tc.ini))
			if err != nil {
				t.Fatalf("parseINI: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseINI = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry[%d] = %q, want %q", i, got[i], tc.want[i])
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

// A config line past maxLineBytes ends the scan. parseINI must hand that back
// rather than let Extract report a half-read config as a complete one — the
// lib_deps of every section below the long line are simply absent otherwise.
func TestParseINI_TruncationIsReported(t *testing.T) {
	cfg := "[env:a]\nlib_deps = bblanchon/ArduinoJson@6.21.3\n" +
		"; " + strings.Repeat("x", maxLineBytes+1) + "\n" +
		"[env:b]\nlib_deps = knolleary/PubSubClient@2.8\n"

	got, err := parseINI(strings.NewReader(cfg))

	if err == nil {
		t.Fatal("parseINI: want an error on a line past maxLineBytes, got nil")
	}
	if want := []string{"bblanchon/ArduinoJson@6.21.3"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("parseINI = %v, want the entries read before truncation %v", got, want)
	}
}
