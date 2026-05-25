// ABOUTME: Extracts SHA-512 hashes from pnpm-lock.yaml.
// ABOUTME: pnpm uses the same Subresource-Integrity format as npm in resolution.integrity.
package lockfiles

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var pnpmParser = Parser{
	Name:      "pnpm",
	Filenames: []string{"pnpm-lock.yaml"},
	Parse:     parsePNPMLock,
}

type pnpmLockfile struct {
	Packages map[string]pnpmPackageEntry `yaml:"packages"`
}

type pnpmPackageEntry struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

func parsePNPMLock(path string) (hashes.Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(hashes.Map)
	for key, entry := range lock.Packages {
		if entry.Resolution.Integrity == "" {
			continue
		}
		name, version, ok := pnpmSplitKey(key)
		if !ok {
			continue
		}
		digest, err := decodeSRI(entry.Resolution.Integrity)
		if err != nil {
			continue
		}
		out[npmPURL(name, version)] = hashes.Hash{Algorithm: hashes.AlgSHA512, Hex: digest}
	}
	return out, nil
}

// pnpmSplitKey parses a pnpm package key into (name, version).
// Recognised shapes:
//
//	/<name>@<version>            (v6 — leading slash)
//	/<name>@<version>(peer-info) (v6/v7 with peer-dep suffix)
//	<name>@<version>             (v9 — no slash)
//	/@scope/name@<version>       (scoped, leading slash)
//	@scope/name@<version>        (scoped, no slash)
//
// pnpm-specific prefix/suffix handling lives here; the actual "split on last @"
// rule comes from splitNpmSpec.
func pnpmSplitKey(key string) (string, string, bool) {
	key = strings.TrimPrefix(key, "/")
	// Strip peer-dep suffix like "(react@18.0.0)" trailing the version.
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	return splitNpmSpec(key)
}
