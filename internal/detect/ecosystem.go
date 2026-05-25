// ABOUTME: Walks a directory tree to recognise which language ecosystems are present.
// ABOUTME: Filename → ecosystem mapping is delegated to internal/ecosystem; this file owns the filesystem walk.
package detect

import (
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
)

// Ecosystems walks scanRoot and returns the set of language ecosystems it found,
// inferred from manifest and lockfile names. The walk skips common heavy
// directories (.git, node_modules, vendor, target, dist, build) to keep
// detection fast on large monorepos.
func Ecosystems(scanRoot string) ([]string, error) {
	found := make(map[string]struct{})

	err := filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission errors on subtrees should not fail detection.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if fswalk.SkipDir(d.Name()) && path != scanRoot {
				return fs.SkipDir
			}
			return nil
		}
		if eco := ecosystem.ForFile(d.Name()); eco != "" {
			found[eco] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(found))
	for eco := range found {
		out = append(out, eco)
	}
	slices.Sort(out)
	return out, nil
}
