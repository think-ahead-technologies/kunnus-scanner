// ABOUTME: Extracts SHA-512 hashes from pnpm-lock.yaml.
// ABOUTME: pnpm uses the same Subresource-Integrity format as npm in resolution.integrity.
package hashes

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type pnpmLockfile struct {
	Packages map[string]pnpmPackageEntry `yaml:"packages"`
}

type pnpmPackageEntry struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

func parsePNPMLock(path string) (Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(Map)
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
		out[npmPURL(name, version)] = Hash{Algorithm: AlgSHA512, Hex: digest}
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
// The version is the substring after the LAST '@' before any '(' suffix.
func pnpmSplitKey(key string) (string, string, bool) {
	key = strings.TrimPrefix(key, "/")
	// Strip peer-dep suffix like "(react@18.0.0)" trailing the version.
	if i := strings.Index(key, "("); i >= 0 {
		key = key[:i]
	}
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return "", "", false
	}
	name := key[:at]
	version := key[at+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}
