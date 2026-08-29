// ABOUTME: Drift guard: every Fuzz* target in the tree must be listed in the Makefile's FUZZ_TARGETS.
// ABOUTME: A hand-maintained list silently stops covering new parsers; this is what catches that.
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	// reFuzzFunc matches a fuzz target's declaration in a _test.go file.
	reFuzzFunc = regexp.MustCompile(`(?m)^func (Fuzz[A-Za-z0-9_]+)\(`)
	// reMakefileTarget matches one "<package>:<FuzzName>" entry, wherever it
	// sits in the Makefile — the entries are what matters, not the block shape.
	reMakefileTarget = regexp.MustCompile(`\./[A-Za-z0-9_/]+:Fuzz[A-Za-z0-9_]+`)
)

// TestFuzzTargets_MakefileMatchesTheTree keeps `make fuzz` honest in both
// directions: a new fuzz target that nobody added to FUZZ_TARGETS is never
// actually fuzzed (only its seed corpus runs, as part of the normal test job),
// and an entry left behind after a rename fails the whole run.
func TestFuzzTargets_MakefileMatchesTheTree(t *testing.T) {
	root := moduleRoot(t)

	inTree := fuzzTargetsInTree(t, root)
	if len(inTree) == 0 {
		t.Fatal("found no Fuzz* functions in the tree; the scan is broken, not the Makefile")
	}
	listed := fuzzTargetsInMakefile(t, root)

	for _, target := range inTree {
		if !slices.Contains(listed, target) {
			t.Errorf("%s is never actively fuzzed: add it to FUZZ_TARGETS in the Makefile", target)
		}
	}
	for _, target := range listed {
		if !slices.Contains(inTree, target) {
			t.Errorf("FUZZ_TARGETS lists %s, which no longer exists", target)
		}
	}
}

// fuzzTargetsInTree walks internal/ for Fuzz* declarations and returns them as
// the "./internal/pkg:FuzzName" form the Makefile uses. Every fuzz target lives
// under internal/ — the parsers are the things worth fuzzing — so the walk does
// not descend cmd/.
func fuzzTargetsInTree(t *testing.T, root string) []string {
	t.Helper()
	var out []string

	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path) //nolint:gosec // path comes from our own walk
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := "./" + filepath.ToSlash(rel)
		for _, m := range reFuzzFunc.FindAllStringSubmatch(string(src), -1) {
			out = append(out, pkg+":"+m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/: %v", err)
	}

	slices.Sort(out)
	return slices.Compact(out)
}

// fuzzTargetsInMakefile returns every target entry the Makefile names.
func fuzzTargetsInMakefile(t *testing.T, root string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	out := reMakefileTarget.FindAllString(string(data), -1)
	slices.Sort(out)
	return slices.Compact(out)
}
