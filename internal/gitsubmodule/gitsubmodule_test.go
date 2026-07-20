// ABOUTME: Tests for the git-submodule extractor: real-fixture extraction over scalibr's walk plus unit tests for URL classification.
// ABOUTME: The .git/index fixtures are encoded with go-git's real index encoder, so gitlink SHA resolution is exercised against the true binary format.
package gitsubmodule

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"
)

const gitmodules = `[submodule "libs/fmt"]
	path = libs/fmt
	url = https://github.com/fmtlib/fmt.git
[submodule "libs/freertos"]
	path = libs/freertos
	url = git@github.com:FreeRTOS/FreeRTOS-Kernel.git
	branch = main
[submodule "libs/internal-sdk"]
	path = libs/internal-sdk
	url = https://gitlab.example.com/firmware/internal-sdk.git
`

const (
	shaFmt      = "a33701196adfad74917046096bf5a2aa0ab0bb50"
	shaFreertos = "dbf70559b27d39c1fdb68dfb9a32140b6a6777a0"
)

// TestExtract runs the extractor through scalibr's real filesystem walk over a
// superproject with a .gitmodules and a real (go-git-encoded) .git/index.
// Gitlink entries resolve each submodule's pinned commit; a submodule with no
// index entry (not yet registered) surfaces versionless, and a non-GitHub
// remote surfaces as pkg:generic.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", ".gitmodules"), gitmodules)
	writeIndex(t, filepath.Join(root, "proj", ".git", "index"), &index.Index{
		Version: 2,
		Entries: []*index.Entry{
			{Name: "libs/fmt", Mode: filemode.Submodule, Hash: plumbing.NewHash(shaFmt)},
			{Name: "libs/freertos", Mode: filemode.Submodule, Hash: plumbing.NewHash(shaFreertos)},
			// Decoy: a regular tracked file must not be treated as a gitlink.
			{Name: "libs/internal-sdk", Mode: filemode.Regular, Hash: plumbing.NewHash("ffffffffffffffffffffffffffffffffffffffff")},
		},
	})

	inv := run(t, root)

	type pkg struct{ purlType, version string }
	want := map[string]pkg{
		"fmtlib/fmt":               {"github", shaFmt},
		"FreeRTOS/FreeRTOS-Kernel": {"github", shaFreertos},
		"internal-sdk":             {"generic", ""}, // non-github remote, gitlink shadowed by regular-file decoy
	}

	got := map[string]pkg{}
	for _, p := range inv.Packages {
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

// TestExtract_NoIndex proves the exported-tarball fallback: a .gitmodules with
// no .git directory still yields components, just without pinned versions.
func TestExtract_NoIndex(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".gitmodules"),
		"[submodule \"fmt\"]\n\tpath = third_party/fmt\n\turl = https://github.com/fmtlib/fmt\n")

	inv := run(t, root)

	if len(inv.Packages) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(inv.Packages), inv.Packages)
	}
	p := inv.Packages[0]
	if p.Name != "fmtlib/fmt" || p.PURLType != "github" || p.Version != "" {
		t.Errorf("package = %s/%s@%q, want github/fmtlib/fmt@\"\"", p.PURLType, p.Name, p.Version)
	}
}

// TestClassifyURL covers the remote-URL grammar directly: https and scp-like
// forms, .git suffixes, non-GitHub hosts, and the relative/degenerate URLs that
// must fall back to a generic name (or be dropped when nothing names them).
func TestClassifyURL(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		wantType    string // "" means "expect no package"
		wantPkgName string
	}{
		{"https github", "https://github.com/fmtlib/fmt.git", "github", "fmtlib/fmt"},
		{"https github no suffix", "https://github.com/fmtlib/fmt", "github", "fmtlib/fmt"},
		{"scp-like github", "git@github.com:FreeRTOS/FreeRTOS-Kernel.git", "github", "FreeRTOS/FreeRTOS-Kernel"},
		{"ssh github", "ssh://git@github.com/owner/repo.git", "github", "owner/repo"},
		{"case-insensitive host", "https://GitHub.com/Owner/Repo.git", "github", "Owner/Repo"},
		{"gitlab https", "https://gitlab.example.com/group/sdk.git", "generic", "sdk"},
		{"scp-like non-github", "git@gitlab.com:group/sdk.git", "generic", "sdk"},
		{"relative url", "../shared/libfoo.git", "generic", "libfoo"},
		{"name ending in git", "https://github.com/owner/mylibgit", "github", "owner/mylibgit"},
		{"github owner only", "https://github.com/onlyowner", "generic", "onlyowner"},
		{"empty", "", "", ""},
		{"slashes only", "///", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			purlType, name := classifyURL(tc.url)
			if tc.wantType == "" {
				if name != "" {
					t.Fatalf("classifyURL(%q) = %s/%s, want none", tc.url, purlType, name)
				}
				return
			}
			if purlType != tc.wantType || name != tc.wantPkgName {
				t.Errorf("classifyURL(%q) = %s/%s, want %s/%s", tc.url, purlType, name, tc.wantType, tc.wantPkgName)
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

func writeIndex(t *testing.T, path string, idx *index.Index) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := index.NewEncoder(f).Encode(idx); err != nil {
		t.Fatalf("encode index: %v", err)
	}
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
