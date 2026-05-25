// ABOUTME: Extracts SHA-512 hashes from npm package-lock.json (and npm-shrinkwrap.json).
// ABOUTME: Supports lockfile v1 (dependencies) and v2/v3 (packages) shapes.
package hashes

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// npmLockfile captures the subset of package-lock.json we read. Both v1 and
// v2/v3 are described — only one branch will be non-empty for a given file.
type npmLockfile struct {
	// v2/v3 — keyed by install path (e.g. "node_modules/lodash" or
	// "node_modules/@babel/core"). The empty string "" is the project root
	// and carries no integrity.
	Packages map[string]npmPackageEntry `json:"packages"`
	// v1 — keyed by package name; nested dependencies recurse the same shape.
	Dependencies map[string]npmDepEntry `json:"dependencies"`
}

type npmPackageEntry struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
	Link      bool   `json:"link"`
}

type npmDepEntry struct {
	Version      string                 `json:"version"`
	Integrity    string                 `json:"integrity"`
	Dependencies map[string]npmDepEntry `json:"dependencies"`
}

func parseNPMLock(path string) (Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(Map)

	for installPath, entry := range lock.Packages {
		if installPath == "" || entry.Link || entry.Integrity == "" || entry.Version == "" {
			continue
		}
		name := npmNameFromInstallPath(installPath)
		if name == "" {
			continue
		}
		digest, derr := decodeSRI(entry.Integrity)
		if derr != nil {
			continue
		}
		out[npmPURL(name, entry.Version)] = Hash{Algorithm: AlgSHA512, Hex: digest}
	}

	collectV1Deps(lock.Dependencies, out)
	return out, nil
}

func collectV1Deps(deps map[string]npmDepEntry, out Map) {
	for name, entry := range deps {
		if entry.Integrity != "" && entry.Version != "" {
			if digest, err := decodeSRI(entry.Integrity); err == nil {
				out[npmPURL(name, entry.Version)] = Hash{Algorithm: AlgSHA512, Hex: digest}
			}
		}
		if len(entry.Dependencies) > 0 {
			collectV1Deps(entry.Dependencies, out)
		}
	}
}

// npmNameFromInstallPath strips the leading "node_modules/" and handles
// nested installs (e.g. "node_modules/foo/node_modules/bar" → "bar").
// The last "node_modules/" segment marks the boundary between path prefix
// and the actual package name.
func npmNameFromInstallPath(installPath string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(installPath, marker)
	if idx < 0 {
		return ""
	}
	return installPath[idx+len(marker):]
}

// npmPURL builds the same PURL form scalibr emits for npm packages.
// Scoped packages percent-encode the "@" in the scope to "%40".
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		// "@babel/core" → "%40babel/core"
		name = "%40" + name[1:]
	}
	return "pkg:npm/" + name + "@" + version
}
