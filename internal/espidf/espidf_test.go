// ABOUTME: Tests for the ESP-IDF extractor: real-fixture extraction over scalibr's walk plus unit tests for manifest parsing.
// ABOUTME: Fixtures mirror a real component-manager project: dependencies.lock at the project root, idf_component.yml under main/.
package espidf

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

const lockFixture = `dependencies:
  espressif/led_strip:
    component_hash: 384db8dd8f4d4d0dd5d941358588c4455bb783e6588e04fbcfdc27eab6d199a8
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 2.5.5
  espressif/mdns:
    component_hash: 32b5eb0ab00b8d17a30d2f5f5cd4bab5a1d1b8ed3f1d0d4a1e07a06f0f0e2a55
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 1.8.2
  idf:
    source:
      type: idf
    version: 5.3.1
direct_dependencies:
- espressif/led_strip
- espressif/mdns
- idf
manifest_hash: 8ed35f6b5e83e7cb1cbcc28f0b6cd9a26e59ab5aa9b83c8be0e3f4b2d5a1c377
target: esp32
version: 2.0.0
`

const manifestFixture = `dependencies:
  idf: ">=5.0"
  espressif/led_strip: "^2.4.1"
  mdns:
    version: "^1.2.0"
  protocol_examples_common:
    path: ../common
  my/git_comp:
    git: https://github.com/owner/git-comp.git
    version: v0.9.0
`

// TestExtract_LockPreferred runs the extractor over a project carrying both a
// dependencies.lock (root) and an idf_component.yml (main/). The lock's exact
// versions must win: the manifest is skipped entirely, so no range-versioned
// duplicates appear.
func TestExtract_LockPreferred(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "dependencies.lock"), lockFixture)
	writeFile(t, filepath.Join(root, "proj", "main", "idf_component.yml"), manifestFixture)

	inv := run(t, root)

	want := map[string]string{ // name -> version
		"espressif/led_strip": "2.5.5",
		"espressif/mdns":      "1.8.2",
		"idf":                 "5.3.1",
	}
	got := map[string]string{}
	for _, p := range inv.Packages {
		if p.PURLType != "generic" {
			t.Errorf("package %q has PURLType %q, want generic", p.Name, p.PURLType)
		}
		if strings.HasPrefix(p.Version, "^") || strings.HasPrefix(p.Version, ">=") {
			t.Errorf("manifest range leaked despite lockfile: %s@%s", p.Name, p.Version)
		}
		got[p.Name] = p.Version
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages %v, want %d", len(got), got, len(want))
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("package %q version = %q, want %q", name, got[name], ver)
		}
	}
}

// TestExtract_ManifestOnly proves the fallback: without a lockfile anywhere
// above, the manifest's declared dependencies surface with their constraints
// verbatim, the espressif/ default namespace applied to bare names, local
// path components dropped, and git sources classified by host.
func TestExtract_ManifestOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main", "idf_component.yml"), manifestFixture)

	inv := run(t, root)

	type pkg struct{ purlType, version string }
	want := map[string]pkg{
		"idf":                 {"generic", ">=5.0"},
		"espressif/led_strip": {"generic", "^2.4.1"},
		"espressif/mdns":      {"generic", "^1.2.0"}, // bare name gets the default namespace
		"owner/git-comp":      {"github", "v0.9.0"},
	}
	got := map[string]pkg{}
	for _, p := range inv.Packages {
		if strings.Contains(p.Name, "protocol_examples_common") {
			t.Errorf("local path component was emitted: %+v", p)
		}
		got[p.Name] = pkg{p.PURLType, p.Version}
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages %v, want %d", len(got), got, len(want))
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("package %q = %+v, want %+v", name, got[name], w)
		}
	}
}

// TestParseManifest covers the manifest grammar directly: scalar constraints,
// map form, the "*" wildcard, default namespacing, and entries that must drop.
func TestParseManifest(t *testing.T) {
	cases := []struct {
		name string
		yml  string
		want map[string]string // "purlType name" -> version; nil = expect none
	}{
		{
			"scalar constraint",
			"dependencies:\n  espressif/mdns: \"^1.0.3\"\n",
			map[string]string{"generic espressif/mdns": "^1.0.3"},
		},
		{
			"bare name gets espressif namespace",
			"dependencies:\n  mdns: \"1.0.0\"\n",
			map[string]string{"generic espressif/mdns": "1.0.0"},
		},
		{
			"idf stays bare",
			"dependencies:\n  idf: \">=5.0\"\n",
			map[string]string{"generic idf": ">=5.0"},
		},
		{
			"wildcard becomes versionless",
			"dependencies:\n  espressif/mdns: \"*\"\n",
			map[string]string{"generic espressif/mdns": ""},
		},
		{
			"map form with version",
			"dependencies:\n  espressif/mdns:\n    version: \"^1.2.0\"\n",
			map[string]string{"generic espressif/mdns": "^1.2.0"},
		},
		{
			"local path dropped",
			"dependencies:\n  common:\n    path: ../common\n",
			nil,
		},
		{
			"git github source",
			"dependencies:\n  x:\n    git: https://github.com/owner/repo.git\n    version: v1.0\n",
			map[string]string{"github owner/repo": "v1.0"},
		},
		{
			"git non-github source",
			"dependencies:\n  x:\n    git: https://gitlab.com/group/lib.git\n    version: abc123\n",
			map[string]string{"generic lib": "abc123"},
		},
		{"no dependencies", "targets: [esp32]\n", nil},
		{"malformed yaml", "\t{{{", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkgs := parseManifest(strings.NewReader(tc.yml))
			got := map[string]string{}
			for _, p := range pkgs {
				got[p.purlType+" "+p.name] = p.version
			}
			if tc.want == nil {
				if len(pkgs) != 0 {
					t.Fatalf("parseManifest = %v, want none", got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseManifest = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("dep %q version = %q, want %q", k, got[k], v)
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
