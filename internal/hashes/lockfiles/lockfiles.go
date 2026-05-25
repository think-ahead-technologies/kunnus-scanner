// ABOUTME: Lockfile-based hash extraction: walks a scan root and dispatches each known lockfile to its parser.
// ABOUTME: Adding a new ecosystem is one new file plus one Parsers entry — the walker is untouched.
package lockfiles

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// Parser describes one lockfile format. Each ecosystem file in this package
// declares a package-level Parser var and lists it in Parsers below.
type Parser struct {
	Name      string                                // diagnostic name ("npm", "cargo")
	Filenames []string                              // basenames this parser claims
	Parse     func(path string) (hashes.Map, error) // file → hash map
}

// Parsers is the single list of every lockfile format we recognise.
// Add a new ecosystem: create <lang>.go with a `var <lang>Parser = Parser{...}`,
// then append it here. The walker dispatches automatically.
var Parsers = []Parser{
	bunParser,
	cargoParser,
	conanParser,
	goSumParser,
	npmParser,
	nugetParser,
	pnpmParser,
	yarnParser,
}

// parserByFilename indexes Parsers by basename for O(1) dispatch in the walker.
var parserByFilename = buildIndex(Parsers)

func buildIndex(parsers []Parser) map[string]*Parser {
	m := make(map[string]*Parser, len(parsers))
	for i := range parsers {
		for _, name := range parsers[i].Filenames {
			m[name] = &parsers[i]
		}
	}
	return m
}

// Hashes walks scanRoot for known lockfiles and returns the merged hash map.
// Per-parser failures are reported to logOut (nil writer means silent) but
// never fail the walk — a single broken lockfile must not block SBOM output.
func Hashes(scanRoot string, logOut io.Writer) hashes.Map {
	out := make(hashes.Map)
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
			if fswalk.SkipDir(d.Name()) && path != abs {
				return fs.SkipDir
			}
			return nil
		}
		p, ok := parserByFilename[d.Name()]
		if !ok {
			return nil
		}
		m, err := p.Parse(path)
		if err != nil && logOut != nil {
			_, _ = fmt.Fprintf(logOut, "hashes: %s parser failed on %s: %v\n", p.Name, path, err)
		}
		out.Merge(m)
		return nil
	})
	return out
}
