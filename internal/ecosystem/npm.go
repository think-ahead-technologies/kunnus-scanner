// ABOUTME: JavaScript ecosystem aggregate + helpers shared by every npm-family parser (npm, pnpm, yarn, bun).
// ABOUTME: Hosts the SRI decoder, npm spec splitter, and PURL builder all four parsers reuse.
package ecosystem

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
)

var npm = Ecosystem{
	Name:           "npm",
	Filenames:      []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"},
	ScalibrPlugins: []string{packagejson.Name, packagelockjson.Name, pnpmlock.Name, yarnlock.Name, bunlock.Name},
	HashParsers: []Parser{
		{Name: "npm", Filenames: []string{"package-lock.json", "npm-shrinkwrap.json"}, Parse: parseNPMLock},
		{Name: "pnpm", Filenames: []string{"pnpm-lock.yaml"}, Parse: parsePNPMLock},
		{Name: "yarn", Filenames: []string{"yarn.lock"}, Parse: parseYarnLock},
		{Name: "bun", Filenames: []string{"bun.lock"}, Parse: parseBunLock},
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
