// ABOUTME: Registry-driven integration test: every ecosystem in the registry must have a fixture and scan to its expected components.
// ABOUTME: Plans with mode/repo and runs real scalibr — the fast, rich-assertion tier beneath the binary e2e.
package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/mode/repo"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// TestEcosystems_EndToEnd walks ecosystem.All() and, for each registered
// ecosystem, requires a fixture directory under testdata/ecosystems/<name>/
// containing a real manifest/lockfile plus a want.txt of expected component
// substrings. It plans the scan exactly as the CLI does (repo.Plan) and runs
// real scalibr, then asserts every wanted substring appears in the inventory.
//
// The loop over ecosystem.All() is the anti-drift guard: adding a new ecosystem
// to the registry without adding its fixture turns this test red.
func TestEcosystems_EndToEnd(t *testing.T) {
	corpus := corpusDir(t)

	for _, eco := range ecosystem.All() {
		t.Run(eco.Name, func(t *testing.T) {
			dir := filepath.Join(corpus, eco.Name)
			wants, err := readWants(dir)
			if err != nil {
				t.Fatalf("ecosystem %q: %v\nadd a fixture: testdata/ecosystems/%s/ with a real manifest/lockfile and want.txt",
					eco.Name, err, eco.Name)
			}
			if len(wants) == 0 {
				t.Fatalf("ecosystem %q: want.txt has no expected components", eco.Name)
			}

			plan, err := repo.New().Plan(context.Background(), dir, mode.Overrides{})
			if err != nil {
				t.Fatalf("Plan(%s): %v", dir, err)
			}
			res, err := scan.Run(context.Background(), plan.Config)
			if err != nil {
				t.Fatalf("Run(%s): %v", dir, err)
			}

			haystack := packageHaystack(res)
			for _, w := range wants {
				if !strings.Contains(haystack, strings.ToLower(w)) {
					t.Errorf("expected component %q in inventory; got packages:\n%s", w, haystack)
				}
			}
		})
	}
}

// packageHaystack returns a newline-joined, lowercased dump of every package
// name in the scan result, for substring matching against want.txt entries.
func packageHaystack(res *scan.Result) string {
	var b strings.Builder
	for _, p := range res.Inventory.Packages {
		b.WriteString(strings.ToLower(p.Name))
		b.WriteByte('\n')
	}
	return b.String()
}

// readWants reads want.txt from dir and returns the expected component
// substrings: one per non-blank, non-comment line. A missing want.txt is an
// error — fixtures without expectations are not coverage.
func readWants(dir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "want.txt"))
	if err != nil {
		return nil, err
	}
	var wants []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		wants = append(wants, line)
	}
	return wants, nil
}

// corpusDir resolves <module-root>/testdata/ecosystems by walking up from the
// test's working directory to the directory containing go.mod. The corpus lives
// at the module root so both this tier and the binary e2e tier share one set of
// fixtures.
func corpusDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "ecosystems")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (go.mod) above test working directory")
		}
		dir = parent
	}
}
