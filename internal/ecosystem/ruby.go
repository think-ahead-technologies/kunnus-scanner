// ABOUTME: Ruby ecosystem. Extracts SHA-256 hashes from Gemfile.lock CHECKSUMS sections (Bundler >= 2.6).
// ABOUTME: Older lockfiles have no CHECKSUMS section and yield no hashes; detection and scanning are unaffected.
package ecosystem

import (
	"bufio"
	"encoding/hex"
	"io"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var ruby = Ecosystem{
	Name:             "ruby",
	Filenames:        []string{"Gemfile", "Gemfile.lock"},
	FilenameSuffixes: []string{".gemspec"},
	ScalibrPlugins:   []string{gemfilelock.Name, gemspec.Name},
	InstalledPlugins: []string{gemspec.Name},
	HashParsers: []Parser{
		{Name: "bundler", Filenames: []string{"Gemfile.lock"}, Parse: parseGemfileLockChecksums},
	},
}

// gemChecksumLineRe matches one CHECKSUMS entry: `name (version[-platform])
// checksums`. The version group stops at the first dash, mirroring how
// scalibr's gemfilelock extractor derives the purl version — the platform
// suffix of a platform-specific gem (e.g. 1.16.0-arm64-darwin) is dropped, so
// every platform artifact's digest lands on the same pkg:gem purl. Bare
// `name (version)` lines (no checksum recorded) deliberately do not match.
var gemChecksumLineRe = regexp.MustCompile(`^(\S+) \(([^-)]*)(?:-[^)]*)?\) (.+)$`)

// parseGemfileLockChecksums mines the CHECKSUMS section Bundler >= 2.6 writes
// into Gemfile.lock — one line per locked gem artifact, each carrying the
// comma-separated `algo=hexdigest` values Bundler verifies on install. Only
// sha256 is accepted (the sole algorithm Bundler emits); pre-2.6 lockfiles
// have no CHECKSUMS section and yield an empty map.
func parseGemfileLockChecksums(r io.Reader) (hashes.Map, error) {
	out := make(hashes.Map)
	scanner := bufio.NewScanner(r)
	inChecksums := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// A line without indentation starts a new section.
		if line[0] != ' ' {
			inChecksums = strings.TrimSpace(line) == "CHECKSUMS"
			continue
		}
		if !inChecksums {
			continue
		}
		m := gemChecksumLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		name, version, sums := m[1], m[2], m[3]
		for _, tok := range strings.Split(sums, ",") {
			algo, hexDigest, ok := strings.Cut(tok, "=")
			if !ok || algo != "sha256" {
				continue
			}
			// Bundler writes lowercase hex SHA-256: 64 chars. Anything else
			// is either malformed or a future format change — skip rather
			// than emit junk.
			if len(hexDigest) != 64 {
				continue
			}
			if _, err := hex.DecodeString(hexDigest); err != nil {
				continue
			}
			out.Add("pkg:gem/"+name+"@"+version, hashes.Hash{
				Algorithm: hashes.AlgSHA256,
				Hex:       hexDigest,
			})
		}
	}
	return out, scanner.Err()
}
