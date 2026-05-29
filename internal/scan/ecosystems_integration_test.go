// ABOUTME: Registry-driven integration test: every ecosystem in the registry must have a fixture and scan to its expected packages.
// ABOUTME: Plans with mode/repo and runs real scalibr — the fast, rich-assertion tier beneath the binary e2e.
package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/mode/repo"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// TestEcosystems_EndToEnd walks ecosystem.All() and, for each registered
// ecosystem, requires a fixture directory under testdata/ecosystems/<name>/
// containing a real manifest/lockfile plus a want.txt of expected packages. It
// plans the scan exactly as the CLI does (repo.Plan) and runs real scalibr,
// then asserts every wanted purl appears in the inventory with the exact
// type/namespace/name/version the platform will consume.
//
// CPEs are synthesized later, during SBOM encoding, so they are asserted by the
// binary e2e tier (TestCLI_SBOM_Repo_AllEcosystems), not here.
//
// The loop over ecosystem.All() is the anti-drift guard: adding a new ecosystem
// to the registry without adding its fixture turns this test red.
func TestEcosystems_EndToEnd(t *testing.T) {
	corpus := corpusDir(t)

	for _, eco := range ecosystem.All() {
		t.Run(eco.Name, func(t *testing.T) {
			dir := filepath.Join(corpus, eco.Name)
			want, err := readWants(dir)
			if err != nil {
				t.Fatalf("ecosystem %q: %v\nadd a fixture: testdata/ecosystems/%s/ with a real manifest/lockfile and want.txt",
					eco.Name, err, eco.Name)
			}
			if len(want.purls) == 0 {
				t.Fatalf("ecosystem %q: want.txt declares no expected purls", eco.Name)
			}

			plan, err := repo.New().Plan(context.Background(), dir, mode.Overrides{})
			if err != nil {
				t.Fatalf("Plan(%s): %v", dir, err)
			}
			res, err := scan.Run(context.Background(), plan.Config)
			if err != nil {
				t.Fatalf("Run(%s): %v", dir, err)
			}

			got := inventoryPURLs(res)
			for _, p := range want.purls {
				if !got[p] {
					t.Errorf("expected purl %q in inventory; got:\n  %s",
						p, strings.Join(sortedKeys(got), "\n  "))
				}
			}
		})
	}
}

// inventoryPURLs returns the set of purl strings emitted by the scan, in the
// exact canonical form (p.PURL().String()) that the SBOM encoder indexes by.
func inventoryPURLs(res *scan.Result) map[string]bool {
	set := make(map[string]bool)
	for _, p := range res.Inventory.Packages {
		if u := p.PURL(); u != nil {
			set[u.String()] = true
		}
	}
	return set
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// wants holds the expected purls and cpes declared in a fixture's want.txt.
type wants struct {
	purls []string
	cpes  []string
}

// readWants parses dir/want.txt. Each non-blank, non-comment line is
// "<kind> <value>" where kind is "purl" or "cpe". A missing want.txt is an
// error — fixtures without expectations are not coverage.
func readWants(dir string) (wants, error) {
	data, err := os.ReadFile(filepath.Join(dir, "want.txt"))
	if err != nil {
		return wants{}, err
	}
	var w wants
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, found := strings.Cut(line, " ")
		value = strings.TrimSpace(value)
		if !found || value == "" {
			return wants{}, &parseError{line: line}
		}
		switch kind {
		case "purl":
			w.purls = append(w.purls, value)
		case "cpe":
			w.cpes = append(w.cpes, value)
		default:
			return wants{}, &parseError{line: line}
		}
	}
	return w, nil
}

type parseError struct{ line string }

func (e *parseError) Error() string {
	return "malformed want.txt line (want \"purl <value>\" or \"cpe <value>\"): " + e.line
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
