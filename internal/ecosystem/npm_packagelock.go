// ABOUTME: npm parser — package-lock.json (and npm-shrinkwrap.json) SHA-512 SRI extraction.
// ABOUTME: Covers both v2/v3 ("packages") and v1 ("dependencies") schemas.
package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
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

func parseNPMLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)

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
		out.Add(npmPURL(name, entry.Version), hashes.Hash{Algorithm: hashes.AlgSHA512, Hex: digest})
	}

	collectV1Deps(lock.Dependencies, out)
	return out, nil
}

func collectV1Deps(deps map[string]npmDepEntry, out hashes.Map) {
	for name, entry := range deps {
		if entry.Integrity != "" && entry.Version != "" {
			if digest, err := decodeSRI(entry.Integrity); err == nil {
				out.Add(npmPURL(name, entry.Version), hashes.Hash{Algorithm: hashes.AlgSHA512, Hex: digest})
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
