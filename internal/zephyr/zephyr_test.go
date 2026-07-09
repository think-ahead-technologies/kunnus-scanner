// ABOUTME: Tests for the Zephyr extractor: real-fixture extraction over scalibr's walk plus unit tests for west manifest resolution.
// ABOUTME: The fixture is a realistic west.yml exercising remotes, defaults, repo-path, explicit urls, and the self project.
package zephyr

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

const shaCMSIS = "4b96cbb174678dcd3ca86e11e1f24bc5f8726da0"

// fixtureWest is a realistic west manifest: a default remote, a project pinned
// to a tag, one pinned to a SHA under a repo-path, one with an explicit
// non-GitHub URL, one relying on the defaults' revision, and a self entry that
// must not become a component.
const fixtureWest = `manifest:
  defaults:
    remote: upstream
    revision: v3.7.0
  remotes:
    - name: upstream
      url-base: https://github.com/zephyrproject-rtos
  projects:
    - name: zephyr
      remote: upstream
      revision: v3.7.0
      import: true
    - name: cmsis
      remote: upstream
      repo-path: cmsis_5
      revision: ` + shaCMSIS + `
      path: modules/hal/cmsis
    - name: mylib
      url: https://gitlab.example.com/team/mylib
      revision: v1.2.3
    - name: hal_nordic
  self:
    path: application
`

// TestExtract runs the extractor through scalibr's real filesystem walk,
// asserting remote resolution (url-base + name or repo-path), defaults
// (remote and revision), explicit URLs, and that the self project is skipped.
// A decoy .yml proves the FileRequired gate.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ws", "west.yml"), fixtureWest)
	writeFile(t, filepath.Join(root, "ws", "other.yml"),
		"manifest:\n  projects:\n    - name: decoy\n      url: https://github.com/x/decoy\n")

	inv := run(t, root)

	type pkg struct{ purlType, version string }
	want := map[string]pkg{
		"zephyrproject-rtos/zephyr":     {"github", "v3.7.0"},
		"zephyrproject-rtos/cmsis_5":    {"github", shaCMSIS}, // repo-path wins over name
		"mylib":                         {"generic", "v1.2.3"},
		"zephyrproject-rtos/hal_nordic": {"github", "v3.7.0"}, // defaults fill remote and revision
	}
	got := map[string]pkg{}
	for _, p := range inv.Packages {
		if strings.Contains(p.Name, "decoy") {
			t.Errorf("decoy other.yml was parsed: %+v", p)
		}
		if strings.Contains(p.Name, "application") {
			t.Errorf("self project was emitted: %+v", p)
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

// TestParseManifest covers manifest resolution directly: single-remote
// implicit default, missing revision, unknown remote, and malformed input.
func TestParseManifest(t *testing.T) {
	cases := []struct {
		name string
		yml  string
		want map[string]string // "purlType name" -> version; nil = expect none
	}{
		{
			"single remote is the implicit default",
			"manifest:\n  remotes:\n    - name: up\n      url-base: https://github.com/org\n  projects:\n    - name: lib\n      revision: v1.0\n",
			map[string]string{"github org/lib": "v1.0"},
		},
		{
			"no revision anywhere is versionless",
			"manifest:\n  remotes:\n    - name: up\n      url-base: https://github.com/org\n  projects:\n    - name: lib\n",
			map[string]string{"github org/lib": ""},
		},
		{
			"unknown remote falls back to generic name",
			"manifest:\n  remotes:\n    - name: up\n      url-base: https://github.com/org\n  projects:\n    - name: lib\n      remote: nope\n      revision: v1.0\n",
			map[string]string{"generic lib": "v1.0"},
		},
		{
			"two remotes and no default needs an explicit remote",
			"manifest:\n  remotes:\n    - name: a\n      url-base: https://github.com/orga\n    - name: b\n      url-base: https://github.com/orgb\n  projects:\n    - name: lib\n      remote: b\n      revision: v1.0\n",
			map[string]string{"github orgb/lib": "v1.0"},
		},
		{
			"explicit url beats remotes",
			"manifest:\n  remotes:\n    - name: up\n      url-base: https://github.com/org\n  projects:\n    - name: lib\n      url: https://git.example.com/lib.git\n      revision: v1.0\n",
			map[string]string{"generic lib": "v1.0"},
		},
		{"nameless project dropped", "manifest:\n  projects:\n    - revision: v1.0\n", nil},
		{"no projects", "manifest:\n  self:\n    path: app\n", nil},
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
					t.Errorf("project %q version = %q, want %q", k, got[k], v)
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
