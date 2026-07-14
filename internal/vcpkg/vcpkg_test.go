// ABOUTME: Tests for the vcpkg extractor: real-fixture extraction over scalibr's walk plus unit tests for manifest parsing.
// ABOUTME: The fixture is a realistic manifest-mode vcpkg.json exercising string deps, object deps, version>= floors and overrides.
package vcpkg

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

// manifest is a realistic vcpkg.json covering every dependency form the parser
// must understand: bare string, object without version, object with a
// "version>=" floor, an override pinning an exact version (which must win over
// the floor), a platform-qualified dep, and a host tool.
const fixtureManifest = `{
  "name": "sensor-firmware",
  "version": "1.0.0",
  "builtin-baseline": "3426db05b996481ca31e95fff3734cf23e0f51bc",
  "dependencies": [
    "fmt",
    { "name": "zlib" },
    { "name": "openssl", "version>=": "3.3.2" },
    { "name": "curl", "features": ["ssl"], "platform": "!windows" },
    { "name": "nlohmann-json", "version>=": "3.11.3#1" },
    { "name": "vcpkg-cmake", "host": true }
  ],
  "overrides": [
    { "name": "zlib", "version": "1.3.1" },
    { "name": "openssl", "version": "3.0.8", "port-version": 1 }
  ]
}`

// TestExtract runs the extractor through scalibr's real filesystem walk,
// asserting each dependency surfaces as a pkg:vcpkg package with the resolved
// version. Decoys prove the FileRequired gate: vcpkg-configuration.json and a
// non-vcpkg *.json must not be parsed.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "vcpkg.json"), fixtureManifest)
	writeFile(t, filepath.Join(root, "proj", "vcpkg-configuration.json"),
		`{"default-registry": {"kind": "git", "repository": "https://github.com/microsoft/vcpkg", "baseline": "x"}}`)
	writeFile(t, filepath.Join(root, "proj", "package.json"),
		`{"dependencies": {"should-not-appear": "1.0.0"}}`)

	inv := run(t, root)

	want := map[string]string{ // name -> version ("" = no resolvable version)
		"fmt":           "",
		"zlib":          "1.3.1", // override pins it
		"openssl":       "3.0.8", // override wins over the version>= floor
		"curl":          "",
		"nlohmann-json": "3.11.3", // version>= floor, port-version suffix stripped
		"vcpkg-cmake":   "",
	}

	got := map[string]string{}
	for _, p := range inv.Packages {
		if p.Name == "should-not-appear" {
			t.Errorf("decoy package.json was parsed: %+v", p)
		}
		if p.PURLType != "vcpkg" {
			t.Errorf("package %q has PURLType %q, want vcpkg", p.Name, p.PURLType)
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

// TestParseManifest covers the manifest grammar directly: dependency forms,
// override resolution, version floors, and the malformed inputs that must yield
// nothing rather than fail.
func TestParseManifest(t *testing.T) {
	cases := []struct {
		name string
		json string
		want map[string]string // name -> version; nil means "expect no packages"
	}{
		{
			"string deps only",
			`{"dependencies": ["fmt", "zlib"]}`,
			map[string]string{"fmt": "", "zlib": ""},
		},
		{
			"override pins version",
			`{"dependencies": ["zlib"], "overrides": [{"name": "zlib", "version": "1.3.1"}]}`,
			map[string]string{"zlib": "1.3.1"},
		},
		{
			"version floor used without override",
			`{"dependencies": [{"name": "openssl", "version>=": "3.3.2"}]}`,
			map[string]string{"openssl": "3.3.2"},
		},
		{
			"override beats floor",
			`{"dependencies": [{"name": "openssl", "version>=": "3.3.2"}], "overrides": [{"name": "openssl", "version": "3.0.8"}]}`,
			map[string]string{"openssl": "3.0.8"},
		},
		{
			"port-version suffix stripped from floor",
			`{"dependencies": [{"name": "x", "version>=": "1.2.3#4"}]}`,
			map[string]string{"x": "1.2.3"},
		},
		{
			"empty-name object dep dropped",
			`{"dependencies": [{"features": ["ssl"]}, "fmt"]}`,
			map[string]string{"fmt": ""},
		},
		{
			"override for undeclared dep ignored",
			`{"dependencies": ["fmt"], "overrides": [{"name": "zlib", "version": "1.3.1"}]}`,
			map[string]string{"fmt": ""},
		},
		{"no dependencies key", `{"name": "app", "version": "1.0.0"}`, nil},
		{"malformed json", `{"dependencies": [`, nil},
		{"not an object", `[1, 2, 3]`, nil},
		{"empty input", ``, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := parseManifest(strings.NewReader(tc.json))
			got := map[string]string{}
			for _, d := range deps {
				got[d.name] = d.version
			}
			if tc.want == nil {
				if len(deps) != 0 {
					t.Fatalf("parseManifest = %v, want none", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseManifest = %v, want %v", got, tc.want)
			}
			for name, ver := range tc.want {
				if got[name] != ver {
					t.Errorf("dep %q version = %q, want %q", name, got[name], ver)
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
