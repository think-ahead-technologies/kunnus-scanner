// ABOUTME: Extracts native package-content hashes from ecosystem lockfiles.
// ABOUTME: Workaround for scalibr v0.4.5 dropping every hash an extractor sees.
package hashes

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

// Algorithm identifies a hash algorithm in the form CDX/SPDX expects.
type Algorithm string

const (
	AlgSHA512 Algorithm = "SHA-512"
	AlgSHA256 Algorithm = "SHA-256"
)

// Hash pairs an algorithm with a lowercase hex digest.
type Hash struct {
	Algorithm Algorithm
	Hex       string
}

// Map is the canonical return type of every parser: purl-string → Hash.
// A zero-value Hash means we found no hash for that PURL.
type Map map[string]Hash

// Merge folds other into m, with m winning on conflicts (callers usually pass
// the most-trusted source first).
func (m Map) Merge(other Map) {
	for k, v := range other {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
}

// FromLockfiles walks scanRoot, hands every recognised lockfile to its parser,
// and returns the merged hash map. Filesystem errors on individual files are
// swallowed (the BSI hash-injection is best-effort — a single unreadable
// lockfile must not break the whole SBOM).
func FromLockfiles(scanRoot string) Map {
	out := make(Map)
	abs, err := filepath.Abs(scanRoot)
	if err != nil {
		return out
	}

	_ = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) && path != abs {
				return fs.SkipDir
			}
			return nil
		}

		var parsed Map
		switch d.Name() {
		case "package-lock.json", "npm-shrinkwrap.json":
			parsed, _ = parseNPMLock(path)
		case "pnpm-lock.yaml":
			parsed, _ = parsePNPMLock(path)
		case "yarn.lock":
			parsed, _ = parseYarnLock(path)
		case "packages.lock.json":
			parsed, _ = parseNuGetLock(path)
		}
		out.Merge(parsed)
		return nil
	})

	return out
}

// skipDir mirrors detect/ecosystem.go's skip set so we don't waste time
// re-reading vendored copies of lockfiles.
func skipDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn",
		"node_modules", "bower_components",
		"vendor", "target", "dist", "build", "out",
		".venv", "venv", "__pycache__",
		".gradle", ".idea", ".vscode":
		return true
	}
	return false
}

// decodeSRI converts a Subresource-Integrity string (e.g. "sha512-<base64>")
// into a hex digest. Returns ("", err) for non-SHA-512 inputs because BSI
// requires SHA-512 specifically; weaker digests would still fail the check.
func decodeSRI(sri string) (string, error) {
	sri = strings.TrimSpace(sri)
	if sri == "" {
		return "", errors.New("empty integrity string")
	}
	prefix := "sha512-"
	if !strings.HasPrefix(sri, prefix) {
		return "", errors.New("integrity is not sha512")
	}
	raw, err := base64.StdEncoding.DecodeString(sri[len(prefix):])
	if err != nil {
		return "", err
	}
	if len(raw) != 64 {
		return "", errors.New("decoded sha512 digest is not 64 bytes")
	}
	return hex.EncodeToString(raw), nil
}
