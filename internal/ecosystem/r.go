// ABOUTME: R ecosystem. Detected via renv.lock; scanned by scalibr's r/renvlock.
// ABOUTME: Mines renv.lock Requirements for dependency edges; no kunnus-side hash parser yet.
package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
)

var r = Ecosystem{
	Name:           "r",
	Filenames:      []string{"renv.lock"},
	ScalibrPlugins: []string{renvlock.Name},
	GraphParsers: []GraphParser{
		{Name: "renv", Filenames: []string{"renv.lock"}, Parse: parseRenvLockGraph},
	},
}

// renvLockGraphFile is the renv.lock shape the graph parser reads: each
// package's own name, locked version, and the packages it requires.
type renvLockGraphFile struct {
	Packages map[string]renvLockGraphEntry `json:"Packages"`
}

type renvLockGraphEntry struct {
	Package      string   `json:"Package"`
	Version      string   `json:"Version"`
	Requirements []string `json:"Requirements"`
}

// parseRenvLockGraph mines dependency edges from renv.lock. Each package's
// Requirements array holds bare package names, which resolve against the
// lock's own Packages map — so base and recommended R packages renv does not
// pin (including the "R" entry itself) drop out without a denylist. A
// requirement the lock does not pin is dropped: the parser never invents a
// purl.
func parseRenvLockGraph(r io.Reader) (graph.Map, error) {
	var lock renvLockGraphFile
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse renv.lock: %w", err)
	}

	// Index by the entry's own Package field, which is what a requirement
	// names; fall back to the map key when the field is absent.
	versionByName := make(map[string]string, len(lock.Packages))
	nameFor := func(key string, e renvLockGraphEntry) string {
		if e.Package != "" {
			return e.Package
		}
		return key
	}
	for key, e := range lock.Packages {
		if e.Version != "" {
			versionByName[nameFor(key, e)] = e.Version
		}
	}

	out := make(graph.Map)
	// Sorted for deterministic append order (see the npm parser).
	for _, key := range slices.Sorted(maps.Keys(lock.Packages)) {
		e := lock.Packages[key]
		if e.Version == "" {
			continue
		}
		from := cranPURL(nameFor(key, e), e.Version)
		for _, req := range e.Requirements {
			v, ok := versionByName[req]
			if !ok {
				continue
			}
			out.Add(from, cranPURL(req, v))
		}
	}
	return out, nil
}

// cranPURL matches scalibr's CRAN purl form for renv-locked packages.
func cranPURL(name, version string) string {
	return "pkg:cran/" + name + "@" + version
}
