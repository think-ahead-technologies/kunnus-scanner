// ABOUTME: Single source of truth for every language ecosystem kunnus understands.
// ABOUTME: Detection, scalibr plugin selection, and lockfile hash extraction all derive from one registry.
package ecosystem

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"slices"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
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

	// LicenseParsers is the optional set of lockfile/manifest parsers kunnus
	// runs to extract licences offline — for ecosystems whose lockfile embeds
	// per-package licence data (e.g. composer.lock) and which scalibr does not
	// surface. nil for ecosystems with no offline licence source. Each Parser's
	// Filenames must be a subset of the owning Ecosystem.Filenames.
	LicenseParsers []LicenseParser
}

// LicenseParser describes one lockfile/manifest format kunnus mines for licences
// offline. Parse returns a license.Map keyed by the conventional (normalized)
// purl form, so the SBOM encoder matches it after purl normalization.
type LicenseParser struct {
	Name      string
	Filenames []string
	Parse     func(r io.Reader) (license.Map, error)
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

// indexByFilename builds a filename→value dispatch table over every ecosystem.
// For each ecosystem it invokes entries, which reports the (filename, value)
// pairs that ecosystem contributes by calling add. The skeleton (allocate the
// map, walk every ecosystem) lives here once; each caller's closure owns its own
// quirk — case-folding for detection, the slice-of-parsers walk for the hash and
// licence tables — so the three dispatch tables share one shape without forcing
// their differences into a single rigid signature.
func indexByFilename[V any](ecos []Ecosystem, entries func(eco *Ecosystem, add func(filename string, val V))) map[string]V {
	m := make(map[string]V)
	for i := range ecos {
		entries(&ecos[i], func(filename string, val V) {
			m[filename] = val
		})
	}
	return m
}

// ecosystemByFilename is the O(1) exact-name dispatch table for detection,
// built once over every marker filename in every ecosystem. Keys are
// lowercased so lookups are case-insensitive. Mirrors parsersByFilename, which
// does the same for hash parsers.
var ecosystemByFilename = indexByFilename(all, func(eco *Ecosystem, add func(string, string)) {
	for _, f := range eco.Filenames {
		add(strings.ToLower(f), eco.Name)
	}
})

// ForFile returns the ecosystem Name claimed by a marker filename
// (case-insensitive), or "" if no ecosystem matches. Exact-name matches are an
// O(1) map lookup; suffixes (a small set) fall back to a linear scan.
func ForFile(name string) string {
	lower := strings.ToLower(name)
	if eco, ok := ecosystemByFilename[lower]; ok {
		return eco
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
// every HashParser in every ecosystem. Keys are matched exactly (the walker
// dispatches on the entry's basename), unlike the case-folded detection table.
var parsersByFilename = indexByFilename(all, func(eco *Ecosystem, add func(string, *Parser)) {
	for j := range eco.HashParsers {
		p := &eco.HashParsers[j]
		for _, f := range p.Filenames {
			add(f, p)
		}
	}
})

// licenseParsersByFilename is the walker's O(1) dispatch table for offline
// licence extraction, built once over every LicenseParser in every ecosystem.
var licenseParsersByFilename = indexByFilename(all, func(eco *Ecosystem, add func(string, *LicenseParser)) {
	for j := range eco.LicenseParsers {
		p := &eco.LicenseParsers[j]
		for _, f := range p.Filenames {
			add(f, p)
		}
	}
})

// Survey walks fsys once and returns the ecosystems detected from marker
// filenames, the merged native-digest map mined from lockfiles, and the merged
// licence map mined from lockfiles that embed licence data. One pass covers
// detection, hashes, and licences. Operating on an fs.FS lets the same survey
// serve a real directory (os.DirFS) and any virtual filesystem.
//
// Per-parser failures are logged at warn level via slog.Default() but never
// fail the walk — a single broken lockfile must not block SBOM output.
// Permission errors on subtrees are skipped, not surfaced.
func Survey(fsys fs.FS) (ecosystems []string, digests hashes.Map, licenses license.Map) {
	digests = make(hashes.Map)
	licenses = make(license.Map)
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
		if p, ok := licenseParsersByFilename[name]; ok {
			m, perr := parseLicenseFile(fsys, path, p)
			if perr != nil {
				slog.Warn("licence parser failed",
					"ecosystem", p.Name,
					"path", path,
					"err", perr,
				)
			}
			licenses.Merge(m)
		}
		return nil
	})

	ecosystems = make([]string, 0, len(found))
	for e := range found {
		ecosystems = append(ecosystems, e)
	}
	slices.Sort(ecosystems)
	return ecosystems, digests, licenses
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

// parseLicenseFile opens path within fsys and runs the licence parser over its
// contents, mirroring parseFile so licence parsers stay pure (io.Reader in,
// license.Map out) and Survey owns the filesystem access.
func parseLicenseFile(fsys fs.FS, path string, p *LicenseParser) (license.Map, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return p.Parse(f)
}
