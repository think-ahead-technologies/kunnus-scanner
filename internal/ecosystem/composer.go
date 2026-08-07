// ABOUTME: PHP/Composer ecosystem. Mines composer.lock for per-package licences and dist.shasum (SHA-1) hashes.
// ABOUTME: PHP is not on deps.dev, so the lockfile is the only offline source for both.
package ecosystem

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
)

var composer = Ecosystem{
	Name:           "composer",
	Filenames:      []string{"composer.json", "composer.lock"},
	ScalibrPlugins: []string{composerlock.Name},
	HashParsers: []Parser{
		{Name: "composer", Filenames: []string{"composer.lock"}, Parse: parseComposerLockHashes},
	},
	LicenseParsers: []LicenseParser{
		{Name: "composer", Filenames: []string{"composer.lock"}, Parse: parseComposerLock},
	},
	GraphParsers: []GraphParser{
		{Name: "composer", Filenames: []string{"composer.lock"}, Parse: parseComposerLockGraph},
	},
}

// composerLicense unmarshals composer.lock's "license" field, which is an array
// of SPDX-ish identifiers but is occasionally written as a bare string.
type composerLicense []string

func (c *composerLicense) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*c = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*c = arr
	return nil
}

type composerPackage struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	License composerLicense `json:"license"`
	Dist    struct {
		Shasum string `json:"shasum"`
	} `json:"dist"`
}

// composerPURL builds the conventional composer purl
// (pkg:composer/<vendor>/<name>@<version>) both lockfile parsers key on, so
// their maps match the SBOM component after purl normalization.
func composerPURL(name, version string) string {
	return "pkg:composer/" + name + "@" + version
}

// composerLock unmarshals the two package arrays of a composer.lock; both
// parsers cover "packages" and "packages-dev".
type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

func parseComposerLockfile(r io.Reader) ([]composerPackage, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock: %w", err)
	}
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}
	return append(lock.Packages, lock.PackagesDev...), nil
}

// parseComposerLockHashes mines the per-package dist.shasum from a
// composer.lock — the SHA-1 of the dist archive Composer verifies on install.
// Registries that serve their own archives (Private Packagist, Satis) populate
// it; GitHub-zipball dists ship it empty, and path/git installs carry no dist
// at all — those are skipped. The source/dist "reference" fields are git commit
// ids, not artifact digests, so they are deliberately not emitted.
func parseComposerLockHashes(r io.Reader) (hashes.Map, error) {
	pkgs, err := parseComposerLockfile(r)
	if err != nil {
		return nil, err
	}

	out := make(hashes.Map)
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" || p.Dist.Shasum == "" {
			continue
		}
		// Composer writes lowercase hex SHA-1: 40 chars. Anything else is
		// either malformed or a future format change — skip rather than
		// emit junk.
		if len(p.Dist.Shasum) != 40 {
			continue
		}
		if _, err := hex.DecodeString(p.Dist.Shasum); err != nil {
			continue
		}
		out.Add(composerPURL(p.Name, p.Version), hashes.Hash{
			Algorithm: hashes.AlgSHA1,
			Hex:       p.Dist.Shasum,
		})
	}
	return out, nil
}

// parseComposerLock mines the per-package licence array from a composer.lock.
// It covers both "packages" and "packages-dev"; licences are keyed by the
// conventional composer purl (pkg:composer/<vendor>/<name>@<version>) so they
// match the SBOM component after purl normalization.
func parseComposerLock(r io.Reader) (license.Map, error) {
	pkgs, err := parseComposerLockfile(r)
	if err != nil {
		return nil, err
	}

	out := make(license.Map)
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		for _, l := range p.License {
			out.Add(composerPURL(p.Name, p.Version), l)
		}
	}
	return out, nil
}

// parseComposerLockGraph mines composer.lock's per-package require maps into
// purl edges. A require key resolves only against the lock's own packages, so
// platform requirements (php, ext-*, composer-plugin-api) drop out naturally
// — they are not packages the lock pins.
func parseComposerLockGraph(r io.Reader) (graph.Map, error) {
	var lock composerGraphLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}
	pkgs := slices.Concat(lock.Packages, lock.PackagesDev)

	versionByName := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		if p.Name != "" && p.Version != "" {
			versionByName[p.Name] = p.Version
		}
	}

	out := make(graph.Map)
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		// Sorted: see the npm parser — deterministic SBOM output.
		for _, dep := range slices.Sorted(maps.Keys(p.Require)) {
			v, ok := versionByName[dep]
			if !ok {
				continue
			}
			out.Add(composerPURL(p.Name, p.Version), composerPURL(dep, v))
		}
	}
	return out, nil
}

// composerGraphLock is the composer.lock shape the graph parser reads — name,
// version, and the require map of each package.
type composerGraphLock struct {
	Packages    []composerGraphPackage `json:"packages"`
	PackagesDev []composerGraphPackage `json:"packages-dev"`
}

type composerGraphPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}
