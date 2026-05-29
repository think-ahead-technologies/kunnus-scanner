// ABOUTME: Single source of truth for every language ecosystem kunnus understands.
// ABOUTME: Detection, scalibr plugin selection, and lockfile hash extraction all derive from one registry.
package ecosystem

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"sort"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/pluginset"
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
	// ecosystem is detected. Used for repo scans, where lockfiles and manifests
	// describe the dependencies a project declares.
	ScalibrPlugins []string

	// InstalledPlugins is the subset of ScalibrPlugins that report packages
	// actually installed on disk (compiled binaries, unpacked archives, package
	// metadata) rather than merely declared in a lockfile or manifest. Container
	// scans use only these, so an image's SBOM lists what is present in it, not
	// what a stray lockfile happens to declare. Empty for ecosystems whose
	// installed state scalibr cannot extract (it has only source extractors).
	// An invariant test enforces InstalledPlugins ⊆ ScalibrPlugins.
	InstalledPlugins []string

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
	Parse     func(r io.Reader) (hashes.Map, error)
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
	lua,
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
	var lists [][]string
	for _, name := range ecosystems {
		for _, eco := range all {
			if eco.Name == name {
				lists = append(lists, eco.ScalibrPlugins)
			}
		}
	}
	return pluginset.Union(lists...)
}

// AllInstalledPlugins returns the deduplicated, sorted union of every
// ecosystem's InstalledPlugins — the extractors that report packages actually
// present on disk. Container scans enable this set (plus the OS extractors) so
// an image's SBOM reflects what is installed in it rather than what a lockfile
// declares. scalibr's per-extractor FileRequired then decides what the image
// filesystem actually matches.
func AllInstalledPlugins() []string {
	var lists [][]string
	for _, eco := range all {
		lists = append(lists, eco.InstalledPlugins)
	}
	return pluginset.Union(lists...)
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

// Survey walks fsys once and returns both the ecosystems detected from marker
// filenames and the merged native-digest map mined from lockfiles. One pass
// replaces the previous detect+hash double walk. Operating on an fs.FS lets the
// same detection serve a real directory (os.DirFS) and any virtual filesystem.
//
// Per-parser failures are logged at warn level via slog.Default() but never
// fail the walk — a single broken lockfile must not block SBOM output.
// Permission errors on subtrees are skipped, not surfaced.
func Survey(fsys fs.FS) (ecosystems []string, digests hashes.Map) {
	digests = make(hashes.Map)
	found := make(map[string]struct{})

	_ = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if fswalk.SkipDir(d.Name()) && path != "." {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if eco := ForFile(name); eco != "" {
			found[eco] = struct{}{}
		}
		if p, ok := parsersByFilename[name]; ok {
			m, perr := parseFile(fsys, path, p)
			if perr != nil {
				slog.Warn("lockfile parser failed",
					"ecosystem", p.Name,
					"path", path,
					"err", perr,
				)
			}
			digests.Merge(m)
		}
		return nil
	})

	ecosystems = make([]string, 0, len(found))
	for e := range found {
		ecosystems = append(ecosystems, e)
	}
	sort.Strings(ecosystems)
	return ecosystems, digests
}

// parseFile opens path within fsys and runs the lockfile parser over its
// contents, so parsers stay pure (io.Reader in, hashes out) and Survey owns the
// filesystem access.
func parseFile(fsys fs.FS, path string, p *Parser) (hashes.Map, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return p.Parse(f)
}
