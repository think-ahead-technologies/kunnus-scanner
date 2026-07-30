// ABOUTME: Ruby ecosystem. Extracts SHA-256 hashes from Gemfile.lock CHECKSUMS sections (Bundler >= 2.6).
// ABOUTME: Older lockfiles have no CHECKSUMS section and yield no hashes; detection and scanning are unaffected.
package ecosystem

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
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
	GraphParsers: []GraphParser{
		{Name: "bundler", Filenames: []string{"Gemfile.lock"}, Parse: parseGemfileLockGraph},
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

// gemSpecLineRe matches a specs-block gem line: four spaces, then
// `name (version[-platform])`. The version group stops at the first dash so a
// platform-specific gem (nokogiri 1.19.1-arm64-darwin) keys the same
// pkg:gem purl scalibr's gemfilelock extractor builds.
var gemSpecLineRe = regexp.MustCompile(`^ {4}(\S+) \(([^-)]*)(?:-[^)]*)?\)$`)

// gemSpecDepLineRe matches a gem's requirement line: six spaces, then a gem
// name and an optional parenthesised constraint. The constraint is ignored —
// the lockfile already pins one version of the named gem, and that pin is the
// edge's target.
var gemSpecDepLineRe = regexp.MustCompile(`^ {6}(\S+)(?: \(.*\))?$`)

// parseGemfileLockGraph mines the dependency edges Bundler records inside each
// specs: block of a Gemfile.lock (GEM, PATH and GIT sections alike): every
// 4-space gem line owns the 6-space requirement lines that follow it. A
// requirement naming a gem the lockfile does not pin (bundler itself, an
// unresolved platform gem) is dropped — the parser never invents a purl.
func parseGemfileLockGraph(r io.Reader) (graph.Map, error) {
	type spec struct {
		name    string
		version string
		deps    []string
	}
	var specs []spec
	versionByName := make(map[string]string)

	inSpecs := false
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		// A non-indented line starts a new top-level section (GEM, DEPENDENCIES,
		// CHECKSUMS, …), which ends any specs block.
		if !strings.HasPrefix(line, " ") {
			inSpecs = false
			continue
		}
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		if m := gemSpecLineRe.FindStringSubmatch(line); m != nil {
			specs = append(specs, spec{name: m[1], version: m[2]})
			versionByName[m[1]] = m[2]
			continue
		}
		if m := gemSpecDepLineRe.FindStringSubmatch(line); m != nil && len(specs) > 0 {
			last := &specs[len(specs)-1]
			last.deps = append(last.deps, m[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Gemfile.lock: %w", err)
	}

	out := make(graph.Map)
	for _, s := range specs {
		from := gemPURL(s.name, s.version)
		for _, dep := range s.deps {
			v, ok := versionByName[dep]
			if !ok {
				continue
			}
			out.Add(from, gemPURL(dep, v))
		}
	}
	return out, nil
}

// gemPURL builds the conventional gem purl the SBOM components carry.
func gemPURL(name, version string) string {
	return "pkg:gem/" + name + "@" + version
}
