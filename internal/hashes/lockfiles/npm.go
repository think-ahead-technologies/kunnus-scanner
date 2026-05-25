// ABOUTME: Extracts SHA-512 hashes from npm package-lock.json (and npm-shrinkwrap.json).
// ABOUTME: Also hosts the npm-family helpers (SRI decoder, spec splitter, PURL builder) shared with pnpm/yarn/bun.
package lockfiles

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var npmParser = Parser{
	Name:      "npm",
	Filenames: []string{"package-lock.json", "npm-shrinkwrap.json"},
	Parse:     parseNPMLock,
}

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

func parseNPMLock(path string) (hashes.Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
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
