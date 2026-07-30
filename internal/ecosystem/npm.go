// ABOUTME: JavaScript ecosystem aggregate + helpers shared by every npm-family parser (npm, pnpm, yarn, bun).
// ABOUTME: Hosts the SRI decoder, npm spec splitter, and PURL builder all four parsers reuse.
package ecosystem

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
)

var npm = Ecosystem{
	Name:             "npm",
	Filenames:        []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"},
	ScalibrPlugins:   []string{packagejson.Name, packagelockjson.Name, pnpmlock.Name, yarnlock.Name, bunlock.Name},
	InstalledPlugins: []string{packagejson.Name},
	HashParsers: []Parser{
		{Name: "npm", Filenames: []string{"package-lock.json", "npm-shrinkwrap.json"}, Parse: parseNPMLock},
		{Name: "pnpm", Filenames: []string{"pnpm-lock.yaml"}, Parse: parsePNPMLock},
		{Name: "yarn", Filenames: []string{"yarn.lock"}, Parse: parseYarnLock},
		{Name: "bun", Filenames: []string{"bun.lock"}, Parse: parseBunLock},
	},
	GraphParsers: []GraphParser{
		{Name: "npm", Filenames: []string{"package-lock.json", "npm-shrinkwrap.json"}, Parse: parseNpmLockGraph},
	},
}

// npmPURL builds the same PURL form scalibr emits for npm packages. Scoped
// packages percent-encode the "@" in the scope to "%40". Shared with the other
// npm-family parsers (pnpm, yarn, bun).
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		// "@babel/core" → "%40babel/core"
		name = "%40" + name[1:]
	}
	return "pkg:npm/" + name + "@" + version
}

// splitNpmSpec parses a "[@scope/]name@version" specifier into its components.
// Scoped packages have two "@" characters ("@babel/core@7.0.0") so the version
// boundary is the LAST "@" — that rule is the same for bun, pnpm, and yarn.
func splitNpmSpec(spec string) (name, version string, ok bool) {
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return "", "", false
	}
	name = spec[:at]
	version = spec[at+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// decodeSRI converts a Subresource-Integrity string (e.g. "sha512-<base64>")
// into a hex digest. Returns ("", err) for non-SHA-512 inputs because BSI
// requires SHA-512 specifically; weaker digests would still fail the check.
// Used by every npm-family parser.
func decodeSRI(sri string) (string, error) {
	sri = strings.TrimSpace(sri)
	if sri == "" {
		return "", errors.New("empty integrity string")
	}
	const prefix = "sha512-"
	if !strings.HasPrefix(sri, prefix) {
		return "", errors.New("integrity is not sha512")
	}
	raw, err := base64.StdEncoding.DecodeString(sri[len(prefix):])
	if err != nil {
		return "", err
	}
	if len(raw) != sha512.Size {
		return "", errors.New("decoded sha512 digest is wrong size")
	}
	return hex.EncodeToString(raw), nil
}

// npmLockGraphFile is the package-lock.json shape the graph parser reads:
// lockfileVersion 2/3's path-keyed packages map. A v1-only lockfile has no
// packages map and yields no edges (see parseNpmLockGraph).
type npmLockGraphFile struct {
	LockfileVersion int                          `json:"lockfileVersion"`
	Packages        map[string]npmLockGraphEntry `json:"packages"`
}

type npmLockGraphEntry struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// parseNpmLockGraph mines dependency edges from a package-lock.json (or
// npm-shrinkwrap.json) of lockfileVersion 2 or 3, whose "packages" map states
// each installed copy's path outright. A dependency name resolves by node's
// own rule — the nearest <dir>/node_modules/<name> walking up from the
// depending package — so two copies of one library at different versions get
// distinct, correct edges.
//
// The "" entry is the scanned project itself, not a component, so it is never
// an edge source (the root component's presence claim already covers it).
// Names that resolve to no packages entry are dropped: the parser never
// invents a purl. lockfileVersion 1 (npm 6, superseded in 2020) carries only a
// nested tree of ranges whose nesting semantics must be inferred; it is
// deliberately not parsed, since no edges beats wrong edges.
func parseNpmLockGraph(r io.Reader) (graph.Map, error) {
	var lock npmLockGraphFile
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	out := make(graph.Map)
	// Paths are walked in sorted order: two install paths can hold the same
	// name@version, so append order must be stable too.
	for _, path := range slices.Sorted(maps.Keys(lock.Packages)) {
		entry := lock.Packages[path]
		if path == "" || entry.Version == "" {
			continue
		}
		name := npmNameFromPath(path)
		if name == "" {
			continue
		}
		from := npmPURL(name, entry.Version)
		for _, deps := range []map[string]string{entry.Dependencies, entry.OptionalDependencies} {
			// Sorted: map iteration order is randomised, and an SBOM's
			// dependsOn list must be byte-identical across runs of one scan.
			for _, dep := range slices.Sorted(maps.Keys(deps)) {
				target, ok := npmResolve(lock.Packages, path, dep)
				if !ok {
					continue
				}
				out.Add(from, target)
			}
		}
	}
	return out, nil
}

// npmResolve applies node's module resolution to find which packages entry a
// dependency of the package at fromPath binds to: try
// <fromPath>/node_modules/<name>, then walk up one node_modules level at a
// time to the root. Returns the resolved purl.
func npmResolve(packages map[string]npmLockGraphEntry, fromPath, name string) (string, bool) {
	dir := fromPath
	for {
		candidate := "node_modules/" + name
		if dir != "" {
			candidate = dir + "/node_modules/" + name
		}
		if entry, ok := packages[candidate]; ok && entry.Version != "" {
			return npmPURL(name, entry.Version), true
		}
		if dir == "" {
			return "", false
		}
		// Strip the trailing "/node_modules/<pkg>" to step out one nesting
		// level; at the outermost level this empties dir, giving the root a
		// final look-in.
		i := strings.LastIndex(dir, "/node_modules/")
		if i < 0 {
			dir = ""
			continue
		}
		dir = dir[:i]
	}
}

// npmNameFromPath recovers a package's name from its lockfile path: the text
// after the last "node_modules/" segment, which keeps a scope intact
// ("node_modules/@babel/core" → "@babel/core").
func npmNameFromPath(path string) string {
	i := strings.LastIndex(path, "node_modules/")
	if i < 0 {
		return ""
	}
	return path[i+len("node_modules/"):]
}
