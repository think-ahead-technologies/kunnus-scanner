// ABOUTME: Tests for the shared skip-dir list.
// ABOUTME: Locks down both the membership and the absolute-path form.
package fswalk

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestSkipDir_KnownNames(t *testing.T) {
	for _, name := range []string{
		".git", "node_modules", "vendor", "target", "dist", "build",
		".venv", "__pycache__", ".idea",
	} {
		if !SkipDir(name) {
			t.Errorf("SkipDir(%q) = false, want true", name)
		}
	}
}

func TestSkipDir_UnknownNamesNotSkipped(t *testing.T) {
	for _, name := range []string{"src", "lib", "cmd", "pkg", "internal", ""} {
		if SkipDir(name) {
			t.Errorf("SkipDir(%q) = true, want false", name)
		}
	}
}

func TestSkipDir_CaseSensitive(t *testing.T) {
	if SkipDir("Node_Modules") {
		t.Error("SkipDir is case-sensitive: Node_Modules must not match node_modules")
	}
}

func TestIsVendoredDir_KnownNamesCaseInsensitive(t *testing.T) {
	for _, name := range []string{
		"vendor", "vendored", "third_party", "third-party", "thirdparty",
		"3rdparty", "dep", "deps", "libs", "external", "externals",
		// Case-insensitive: historical v1 behaviour.
		"Vendor", "THIRD_PARTY", "LiBs",
	} {
		if !IsVendoredDir(name) {
			t.Errorf("IsVendoredDir(%q) = false, want true", name)
		}
	}
}

func TestIsVendoredDir_UnknownNames(t *testing.T) {
	for _, name := range []string{"src", "lib", "node_modules", ".git", ""} {
		if IsVendoredDir(name) {
			t.Errorf("IsVendoredDir(%q) = true, want false", name)
		}
	}
}

func TestSkipDirForVendoredSearch_DescendsVendoredFamilies(t *testing.T) {
	// The whole point: SkipDir says skip vendor/, but the vendored search
	// must descend into it. Same goes for any other vendored family name.
	for _, name := range []string{"vendor", "third_party", "libs", "external", "3rdparty"} {
		if SkipDirForVendoredSearch(name) {
			t.Errorf("SkipDirForVendoredSearch(%q) = true; search must descend into vendored families", name)
		}
	}
}

func TestSkipDirForVendoredSearch_StillSkipsBuildAndVCS(t *testing.T) {
	// Skip everything SkipDir would skip *except* the vendored families.
	// .git inside a vendored library would otherwise leak into the hash set.
	for _, name := range []string{".git", ".hg", "node_modules", "target", "dist", "build", ".venv", "__pycache__"} {
		if !SkipDirForVendoredSearch(name) {
			t.Errorf("SkipDirForVendoredSearch(%q) = false; non-vendored skips must still apply", name)
		}
	}
}

// TestAbsoluteSkipPathsExcept_KeepsNamedDirs covers the carve-out a caller needs
// when one of the blanket-skipped directories holds the only manifest for an
// ecosystem — a Go vendor tree's vendor/modules.txt.
func TestAbsoluteSkipPathsExcept_KeepsNamedDirs(t *testing.T) {
	root := "/tmp/scan"
	if runtime.GOOS == "windows" {
		root = `C:\scan`
	}
	got := AbsoluteSkipPathsExcept(root, []string{"vendor"})

	for _, p := range got {
		if p == filepath.Join(root, "vendor") {
			t.Errorf("AbsoluteSkipPathsExcept kept %q; the exception must remove it\ngot: %v", p, got)
		}
	}
	// Every other skip must survive: the exception is one name, not a reset.
	want := filepath.Join(root, "node_modules")
	if !slices.Contains(got, want) {
		t.Errorf("AbsoluteSkipPathsExcept(%q) missing %q\ngot: %v", root, want, got)
	}
	if len(got) != len(AbsoluteSkipPaths(root))-1 {
		t.Errorf("got %d paths, want exactly one fewer than the full set (%d)",
			len(got), len(AbsoluteSkipPaths(root)))
	}
}

// TestAbsoluteSkipPathsExcept_NoExceptionsMatchesFullSet pins the degenerate
// case, since AbsoluteSkipPaths is defined in terms of this function.
func TestAbsoluteSkipPathsExcept_NoExceptionsMatchesFullSet(t *testing.T) {
	root := "/tmp/scan"
	if !slices.Equal(AbsoluteSkipPathsExcept(root, nil), AbsoluteSkipPaths(root)) {
		t.Error("AbsoluteSkipPathsExcept(root, nil) must equal AbsoluteSkipPaths(root)")
	}
}

func TestAbsoluteSkipPaths_JoinsUnderRoot(t *testing.T) {
	root := "/tmp/scan"
	if runtime.GOOS == "windows" {
		root = `C:\scan`
	}
	got := AbsoluteSkipPaths(root)

	if len(got) == 0 {
		t.Fatal("AbsoluteSkipPaths returned empty slice")
	}
	want := filepath.Join(root, "node_modules")
	found := false
	for _, p := range got {
		if p == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AbsoluteSkipPaths(%q) missing %q\ngot: %v", root, want, got)
	}
}
