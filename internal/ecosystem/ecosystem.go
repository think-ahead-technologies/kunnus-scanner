// ABOUTME: Single source of truth for every language ecosystem kunnus understands.
// ABOUTME: Detection, scalibr plugin selection, and lockfile hash extraction all derive from one registry.
package ecosystem

import (
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// Ecosystem captures everything kunnus knows about one language ecosystem:
// how to detect its presence on disk, which scalibr extractors handle it, and
// which (if any) lockfiles kunnus mines for native integrity hashes.
type Ecosystem struct {
	// Name is the stable identifier used in CLI flags and detection output.
	Name string

	// Filenames lists marker basenames that flag this ecosystem. Matched
	// case-insensitively. Every Parser's filenames MUST appear here too —
	// an invariant test catches drift between detection and hash extraction.
	Filenames []string

	// FilenameSuffixes are case-insensitive extensions/suffixes that flag this
	// ecosystem (e.g. ".csproj"). Checked only after exact-name lookup misses.
	FilenameSuffixes []string

	// ScalibrPlugins are the scalibr extractor names enabled when this
	// ecosystem is detected.
	ScalibrPlugins []string

	// HashParsers is the optional set of lockfile parsers kunnus runs to
	// extract native digests. nil for ecosystems we detect and scan via
	// scalibr but do not deep-hash ourselves.
	HashParsers []Parser
}

// Parser describes one lockfile format kunnus mines for native digests.
// The Filenames it claims must be a subset of the owning Ecosystem.Filenames;
// see TestEcosystems_ParserFilenamesAreDetectable for the enforcement.
type Parser struct {
	Name      string
	Filenames []string
	Parse     func(path string) (hashes.Map, error)
}

// all is the master list. Adding or removing an ecosystem is one entry here
// plus one file declaring the aggregate — there is no other registration
// site to keep in sync.
var all = []Ecosystem{
	cargo,
	composer,
	cpp,
	dotnet,
	golang,
	gradle,
	haskell,
	maven,
	npm,
	python,
	r,
	ruby,
	swift,
}

// All returns the registered ecosystems.
func All() []Ecosystem { return all }

// ForFile returns the ecosystem Name claimed by a marker filename
// (case-insensitive), or "" if no ecosystem matches.
func ForFile(name string) string {
	lower := strings.ToLower(name)
	for _, eco := range all {
		for _, f := range eco.Filenames {
			if strings.ToLower(f) == lower {
				return eco.Name
			}
		}
	}
	for _, eco := range all {
		for _, suf := range eco.FilenameSuffixes {
			if strings.HasSuffix(lower, strings.ToLower(suf)) {
				return eco.Name
			}
		}
	}
	return ""
}

// PluginsFor returns the deduplicated, sorted scalibr plugin names enabled
// by the given ecosystem names. Unknown names are silently ignored — callers
// (mode/repo) already validate user-supplied --ecosystems values.
func PluginsFor(ecosystems []string) []string {
	seen := make(map[string]struct{})
	for _, name := range ecosystems {
		for _, eco := range all {
			if eco.Name != name {
				continue
			}
			for _, p := range eco.ScalibrPlugins {
				seen[p] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// parsersByFilename is the walker's O(1) dispatch table, built once over
// every HashParser in every ecosystem.
var parsersByFilename = buildParsersByFilename(all)

func buildParsersByFilename(ecos []Ecosystem) map[string]*Parser {
	m := make(map[string]*Parser)
	for i := range ecos {
		for j := range ecos[i].HashParsers {
			p := &ecos[i].HashParsers[j]
			for _, f := range p.Filenames {
				m[f] = p
			}
		}
	}
	return m
}

// Hashes walks scanRoot for known lockfiles and returns the merged hash map.
// Per-parser failures are reported to logOut (nil writer is silent) but never
// fail the walk — a single broken lockfile must not block SBOM output.
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
		p, ok := parsersByFilename[d.Name()]
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
