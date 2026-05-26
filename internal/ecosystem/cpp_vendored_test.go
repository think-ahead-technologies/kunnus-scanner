// ABOUTME: Tests for VendoredSurvey — detects C/C++ vendored dirs (third_party/, libs/, …)
// ABOUTME: Walks into directories the global fswalk.SkipDir blocks, so it has its own coverage.
package ecosystem

import (
	"crypto/md5" //nolint:gosec // fingerprint, not security
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// md5Hex returns the lowercase hex MD5 of s — fixture helper, keeps test
// assertions side-by-side with the bytes that produced them.
func md5Hex(s string) string {
	h := md5.Sum([]byte(s)) //nolint:gosec
	return hex.EncodeToString(h[:])
}

func TestVendoredSurvey_BasicCppTree(t *testing.T) {
	root := t.TempDir()
	writeAt(t, root, "third_party/zlib/deflate.c", "// deflate impl\n")
	writeAt(t, root, "third_party/zlib/inflate.c", "// inflate impl\n")
	writeAt(t, root, "third_party/zlib/zlib.h", "// header\n")

	hits, hashMap := VendoredSurvey(root, nil)

	if len(hits) != 1 {
		t.Fatalf("expected 1 vendored hit, got %d: %+v", len(hits), hits)
	}
	h := hits[0]
	if h.Name != "zlib" {
		t.Errorf("Name = %q, want %q", h.Name, "zlib")
	}
	wantRel := filepath.Join("third_party", "zlib")
	if h.RelPath != wantRel {
		t.Errorf("RelPath = %q, want %q", h.RelPath, wantRel)
	}
	wantPURL := "pkg:generic/zlib?vendored_path=" + filepath.ToSlash(wantRel)
	if h.PURL != wantPURL {
		t.Errorf("PURL = %q, want %q", h.PURL, wantPURL)
	}

	hs := hashMap[wantPURL]
	if len(hs) != 3 {
		t.Fatalf("expected 3 file hashes, got %d: %+v", len(hs), hs)
	}
	// Spot-check one — algorithm MD5, hex matches the literal file contents.
	var deflate hashes.Hash
	for _, e := range hs {
		if e.Path == "deflate.c" {
			deflate = e
		}
	}
	if deflate.Algorithm != hashes.AlgMD5 {
		t.Errorf("deflate algorithm = %q, want MD5", deflate.Algorithm)
	}
	if deflate.Hex != md5Hex("// deflate impl\n") {
		t.Errorf("deflate hex = %q, want %q", deflate.Hex, md5Hex("// deflate impl\n"))
	}
}

func TestVendoredSurvey_NoCppFilesSkipsDir(t *testing.T) {
	// "vendor" directory exists but contains only non-C/C++ files. This is the
	// common Go / Python case and must NOT produce a vendored component.
	root := t.TempDir()
	writeAt(t, root, "vendor/golang.org/x/sys/unix/syscall.go", "package unix\n")
	writeAt(t, root, "vendor/modules.txt", "# explicit\n")

	hits, hashMap := VendoredSurvey(root, nil)

	if len(hits) != 0 {
		t.Errorf("expected 0 hits for non-C/C++ vendor dir, got %d: %+v", len(hits), hits)
	}
	if len(hashMap) != 0 {
		t.Errorf("expected empty hashMap, got %d entries", len(hashMap))
	}
}

func TestVendoredSurvey_NestedVendoredCollapses(t *testing.T) {
	// A vendored lib that itself ships a vendored sub-tree must not produce a
	// second component — duplicate matches across layered scanning is a known
	// source of false positives (mirrors v1 vendored.go:165).
	root := t.TempDir()
	writeAt(t, root, "third_party/libfoo/foo.c", "// outer\n")
	writeAt(t, root, "third_party/libfoo/external/libbar/bar.c", "// nested\n")

	hits, _ := VendoredSurvey(root, nil)

	if len(hits) != 1 {
		t.Fatalf("expected 1 hit (outer only), got %d: %+v", len(hits), hits)
	}
	if hits[0].Name != "libfoo" {
		t.Errorf("Name = %q, want %q (outer dir wins)", hits[0].Name, "libfoo")
	}
}

func TestVendoredSurvey_GitInsideVendoredLibSkipped(t *testing.T) {
	// Vendored libs sometimes ship a .git/ pseudo-checkout. We skip them to
	// avoid double-counting against any future git scanning we ever do, and to
	// keep BOM size sane (.git can contain thousands of packed objects).
	root := t.TempDir()
	writeAt(t, root, "third_party/libfoo/foo.c", "// real source\n")
	writeAt(t, root, "third_party/libfoo/.git/objects/00/aa", "junk binary\n")
	writeAt(t, root, "third_party/libfoo/.git/HEAD", "ref: refs/heads/main\n")

	_, hashMap := VendoredSurvey(root, nil)

	for purl, hs := range hashMap {
		for _, h := range hs {
			if filepath.Dir(h.Path) == ".git" || strings.HasPrefix(h.Path, ".git/") {
				t.Errorf("hash for .git-internal file leaked: purl=%s path=%s", purl, h.Path)
			}
		}
	}
}

func TestVendoredSurvey_NonCppFilesIgnored(t *testing.T) {
	// .py / .go / .md inside an otherwise valid C++ vendored lib are skipped —
	// only the C/C++ source counts toward the fingerprint.
	root := t.TempDir()
	writeAt(t, root, "third_party/zlib/zlib.c", "// keep\n")
	writeAt(t, root, "third_party/zlib/README.md", "# skip\n")
	writeAt(t, root, "third_party/zlib/build.py", "# skip\n")

	_, hashMap := VendoredSurvey(root, nil)

	wantPURL := "pkg:generic/zlib?vendored_path=" + filepath.ToSlash(filepath.Join("third_party", "zlib"))
	hs := hashMap[wantPURL]
	if len(hs) != 1 {
		t.Fatalf("expected 1 file hash (zlib.c only), got %d: %+v", len(hs), hs)
	}
	if hs[0].Path != "zlib.c" {
		t.Errorf("path = %q, want %q", hs[0].Path, "zlib.c")
	}
}

func TestVendoredSurvey_AllDirNameVariants(t *testing.T) {
	// Every dir name in vendoredDirNames must trigger the scan. Drift here
	// silently shrinks coverage, so we lock the full list in one test.
	root := t.TempDir()
	names := []string{
		"3rdparty", "dep", "deps", "thirdparty", "third-party", "third_party",
		"libs", "external", "externals", "vendor", "vendored",
	}
	for _, n := range names {
		writeAt(t, root, filepath.Join(n, "libfoo", "foo.c"), "// src\n")
	}

	hits, _ := VendoredSurvey(root, nil)

	gotDirs := make([]string, 0, len(hits))
	for _, h := range hits {
		gotDirs = append(gotDirs, filepath.Dir(h.RelPath))
	}
	sort.Strings(gotDirs)
	sort.Strings(names)
	if len(gotDirs) != len(names) {
		t.Errorf("got %d hits, want %d (one per vendored name variant)\ngot: %v\nwant: %v",
			len(gotDirs), len(names), gotDirs, names)
	}
}

func TestVendoredSurvey_AllExtVariants(t *testing.T) {
	// Lock the file-extension list. Same drift concern as TestAllDirNameVariants.
	root := t.TempDir()
	exts := []string{".c", ".cc", ".cpp", ".h", ".hh", ".hpp"}
	for i, e := range exts {
		writeAt(t, root, filepath.Join("third_party", "lib1", "f"+string(rune('a'+i))+e), "// src\n")
	}

	_, hashMap := VendoredSurvey(root, nil)
	wantPURL := "pkg:generic/lib1?vendored_path=" + filepath.ToSlash(filepath.Join("third_party", "lib1"))
	hs := hashMap[wantPURL]
	if len(hs) != len(exts) {
		t.Errorf("expected %d hashes (one per extension), got %d: %+v", len(exts), len(hs), hs)
	}
}
