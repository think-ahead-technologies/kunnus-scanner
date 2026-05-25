// ABOUTME: Tests for the shared skip-dir list.
// ABOUTME: Locks down both the membership and the absolute-path form.
package fswalk

import (
	"path/filepath"
	"runtime"
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
