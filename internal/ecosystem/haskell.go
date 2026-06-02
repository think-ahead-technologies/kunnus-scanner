// ABOUTME: Haskell ecosystem. Extracts SHA-256 hashes from stack.yaml.lock hackage pins.
// ABOUTME: cabal.project.freeze carries version constraints only — no integrity values to mine there.
package ecosystem

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/stacklock"
	"gopkg.in/yaml.v3"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var haskell = Ecosystem{
	Name:           "haskell",
	Filenames:      []string{"cabal.project.freeze", "stack.yaml.lock"},
	ScalibrPlugins: []string{cabal.Name, stacklock.Name},
	HashParsers: []Parser{
		{Name: "stack", Filenames: []string{"stack.yaml.lock"}, Parse: parseStackYamlLock},
	},
}

// stackLockfile unmarshals the packages array of a stack.yaml.lock. Only the
// completed.hackage locator is read; the original: section repeats the pin
// (sometimes without the hash) and the snapshots: section pins the resolver,
// not a package.
type stackLockfile struct {
	Packages []struct {
		Completed struct {
			Hackage string `yaml:"hackage"`
		} `yaml:"completed"`
	} `yaml:"packages"`
}

// parseStackYamlLock mines the per-package hackage locator from a
// stack.yaml.lock — `name-version@sha256:<hash>,<size>`, where the hash is the
// SHA-256 of the package's revisioned .cabal file as published on Hackage (the
// integrity value stack/pantry verify on fetch). The pantry-tree sha256 is a
// pantry-internal source-tree key, not reproducible with standard tools, so it
// is deliberately not emitted. Git/path-sourced packages carry no hackage pin
// and are skipped.
func parseStackYamlLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock stackLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, p := range lock.Packages {
		nameVer, rest, ok := strings.Cut(p.Completed.Hackage, "@sha256:")
		if !ok {
			continue
		}
		hexDigest, _, _ := strings.Cut(rest, ",")
		// Pantry writes lowercase hex SHA-256: 64 chars. Anything else is
		// either malformed or a future format change — skip rather than
		// emit junk.
		if len(hexDigest) != 64 {
			continue
		}
		if _, err := hex.DecodeString(hexDigest); err != nil {
			continue
		}
		name, version, ok := splitHackagePin(nameVer)
		if !ok {
			continue
		}
		out.Add("pkg:haskell/"+name+"@"+version, hashes.Hash{
			Algorithm: hashes.AlgSHA256,
			Hex:       hexDigest,
		})
	}
	return out, nil
}

// splitHackagePin splits a `name-version` pin at the last dash, mirroring how
// scalibr's stacklock extractor derives the purl: Hackage versions are strictly
// dotted numerals, so the trailing segment must look like one or the pin is
// rejected (and scalibr would not have emitted a matching component anyway).
func splitHackagePin(nameVer string) (name, version string, ok bool) {
	i := strings.LastIndex(nameVer, "-")
	if i <= 0 || i == len(nameVer)-1 {
		return "", "", false
	}
	name, version = nameVer[:i], nameVer[i+1:]
	for _, c := range version {
		if (c < '0' || c > '9') && c != '.' {
			return "", "", false
		}
	}
	return name, version, true
}
