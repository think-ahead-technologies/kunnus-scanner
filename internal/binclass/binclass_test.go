// ABOUTME: Tests for the binary-classifier extractor: real-fixture extraction plus catalog and glob invariants.
// ABOUTME: The memcached fixture is a slice of the real memcached:latest binary, so byte scanning is exercised for real.
package binclass

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/stats"
)

// TestExtractMemcached runs the extractor through scalibr's real filesystem walk
// over a tree holding the memcached fixture, asserting it surfaces a
// pkg:generic/memcached package at the embedded version. The fixture is real
// bytes of the memcached:latest binary — its ELF header followed by the
// version-string region — so this exercises genuine magic-gating and byte
// scanning, not a synthesised string. Two decoys prove the gates:
//   - notes.txt carries "memcached 9.9.9" but its name fails the glob;
//   - a plain-text file named "memcached" matches the glob but fails the ELF
//     magic check.
//
// Neither must produce a package.
func TestExtractMemcached(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "local", "bin", "memcached"), readFixture(t, "memcached"))
	writeFile(t, filepath.Join(root, "usr", "share", "doc", "notes.txt"), []byte("memcached 9.9.9\n"))
	writeFile(t, filepath.Join(root, "opt", "fake", "memcached"), []byte("memcached 9.9.9 not an elf\n"))

	inv, _, err := filesystem.Run(context.Background(), &filesystem.Config{
		Extractors: []filesystem.Extractor{New()},
		ScanRoots:  scalibrfs.RealFSScanRoots(root),
		Stats:      stats.NoopCollector{},
	})
	if err != nil {
		t.Fatalf("filesystem.Run: %v", err)
	}

	var got []*extractor.Package
	for _, p := range inv.Packages {
		if p.Name == "memcached" {
			got = append(got, p)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d memcached packages, want 1 (decoy must be ignored); packages=%+v", len(got), inv.Packages)
	}
	if got[0].Version != "1.6.42" {
		t.Errorf("version = %q, want 1.6.42", got[0].Version)
	}
	if purl := got[0].PURL(); purl == nil || purl.String() != "pkg:generic/memcached@1.6.42" {
		t.Errorf("purl = %v, want pkg:generic/memcached@1.6.42", purl)
	}
}

// TestCatalogInvariants is a drift guard: every classifier must have at least
// one glob and one pattern, every pattern must carry a "version" capture group,
// and every PURL template must decompose into a non-empty type and name. A new
// catalog entry that violates these turns the suite red.
func TestCatalogInvariants(t *testing.T) {
	for _, c := range defaultCatalog() {
		if len(c.globs) == 0 {
			t.Errorf("%s: no globs", c.purl)
		}
		if len(c.res) == 0 {
			t.Errorf("%s: no patterns", c.purl)
		}
		for _, re := range c.res {
			if re.SubexpIndex("version") <= 0 {
				t.Errorf("%s: pattern %q has no (?P<version>) group", c.purl, re.String())
			}
		}
		typ, name := splitPURLTemplate(c.purl)
		if typ == "" || name == "" || strings.Contains(name, "@version") {
			t.Errorf("%s: bad PURL template -> type=%q name=%q", c.purl, typ, name)
		}
		for _, cp := range c.cpes {
			if !strings.HasPrefix(cp, "cpe:2.3:") {
				t.Errorf("%s: malformed CPE %q", c.purl, cp)
			}
		}
	}
}

// TestGlobMatch covers the "**/<suffix>" matching, including multi-segment
// suffixes and single-character wildcards that the catalog relies on.
func TestGlobMatch(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"**/memcached", "usr/local/bin/memcached", true},
		{"**/memcached", "memcached", true},
		{"**/memcached", "usr/bin/memcachedx", false},
		{"**/go", "usr/local/go/bin/go", true},
		{"**/go", "usr/local/go", true}, // glob matches any basename "go"; dir-vs-file is a runtime distinction
		{"**/go", "usr/local/gofmt", false},
		{"**/elixir/ebin/elixir.app", "usr/lib/elixir/ebin/elixir.app", true},
		{"**/elixir/ebin/elixir.app", "usr/lib/elixir/elixir.app", false},
		{"**/libstd-????????????????.so", "lib/libstd-0123456789abcdef.so", true},
		{"**/libstd-????????????????.so", "lib/libstd-short.so", false},
		{"**/composer*", "usr/bin/composer.phar", true},
	}
	for _, tc := range cases {
		if got := globMatch(tc.glob, tc.path); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.glob, tc.path, got, tc.want)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
