// ABOUTME: Single source of truth for every language ecosystem kunnus understands.
// ABOUTME: Detection, scalibr plugin selection, and lockfile hash extraction all derive from one registry.
package ecosystem

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	pathpkg "path"
	"slices"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/graph"
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

	// NativeExtractor marks an ecosystem whose components come from a
	// kunnus-native filesystem.Extractor that the scanning mode appends directly
	// (like internal/binclass), not from a scalibr-registry plugin. Such an
	// ecosystem legitimately carries no ScalibrPlugins: detection still flags it,
	// and the mode wires in the extractor. The completeness invariant requires
	// either ScalibrPlugins or this flag, so an ecosystem can never be detected
	// yet produce nothing. The ecosystem package stays scalibr-free — it names no
	// extractor instance; the mode owns that mapping.
	NativeExtractor bool

	// InstalledPlugins is the subset of ScalibrPlugins that report packages
	// actually installed on disk (compiled binaries, unpacked archives, package
	// metadata) rather than merely declared in a lockfile or manifest. Container
	// scans use only these, so an image's SBOM lists what is present in it, not
	// what a stray lockfile happens to declare. Empty for ecosystems whose
	// installed state scalibr cannot extract (it has only source extractors).
	// An invariant test enforces InstalledPlugins ⊆ ScalibrPlugins.
	InstalledPlugins []string

	// Supersedes declares extractors a resolved lockfile in the scanned tree makes
	// redundant, so they are never enabled: without this, the manifest extractor
	// and the lockfile extractor both report the same dependency — once at its
	// declared range, once at the resolved pin — under two different PURLs that
	// dedup cannot collapse. Survey evaluates each rule against the files it
	// actually saw and the scanning mode subtracts the result before applying user
	// overrides, so an explicit --enable of a superseded plugin still wins.
	//
	// Only for lockfiles whose authority covers every manifest below them (a
	// Cargo.lock resolves its whole workspace). Where a lockfile speaks for one
	// directory only — NuGet's opt-in packages.lock.json, a python lock beside its
	// project — a whole-scan switch is the wrong instrument, because the manifests
	// it silences may include ones no resolver ever saw; those ecosystems drop the
	// redundant component per path after the scan instead (internal/sbom/declared.go).
	Supersedes []Supersede

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

	// GraphParsers is the optional set of lockfile parsers kunnus runs to mine
	// component→component dependency edges (the CISA Component Dependency
	// Relationship element) — for lockfiles that pin the full resolved graph
	// (e.g. Cargo.lock, composer.lock). nil for ecosystems whose lockfile
	// carries no per-package edge data. Each parser's Filenames must be a
	// subset of the owning Ecosystem.Filenames.
	GraphParsers []GraphParser
}

// GraphParser describes one lockfile format kunnus mines for dependency
// edges. Parse returns a graph.Map keyed by the conventional (normalized)
// purl form, so the SBOM encoder matches it after purl normalization.
type GraphParser struct {
	Name      string
	Filenames []string
	Parse     func(r io.Reader) (graph.Map, error)
}

// LicenseParser describes one lockfile/manifest format kunnus mines for licences
// offline. Parse returns a license.Map keyed by the conventional (normalized)
// purl form, so the SBOM encoder matches it after purl normalization.
type LicenseParser struct {
	Name      string
	Filenames []string
	Parse     func(r io.Reader) (license.Map, error)
}

// Supersede is one ecosystem's "a resolved lockfile makes this extractor
// redundant" rule (see Ecosystem.Supersedes).
//
// The rule fires only when Lock was found somewhere in the tree AND every
// Manifest found sits in, or below, a directory holding a Lock. That coverage
// condition is what makes a whole-scan switch safe: in a repository where one
// project is locked and another is not, the rule stays quiet and the unlocked
// project keeps its declared dependencies. Losing a component is worse than
// listing one twice.
//
// Lock and Manifests must appear in the owning Ecosystem.Filenames (detection
// and superseding cannot drift), and Plugins in its ScalibrPlugins; an invariant
// test enforces all three.
type Supersede struct {
	// Lock is the resolved-lockfile basename whose presence supersedes Plugins.
	Lock string

	// Manifests are the basenames of the files Plugins read — the ones Lock must
	// cover for the rule to fire.
	Manifests []string

	// Plugins are the scalibr extractor names to leave disabled.
	Plugins []string
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
	arduino,
	cargo,
	cmake,
	cmsis,
	composer,
	cpp,
	dotnet,
	espidf,
	gitsubmodule,
	golang,
	gradle,
	haskell,
	lua,
	maven,
	modustoolbox,
	npm,
	platformio,
	python,
	r,
	ruby,
	swift,
	vcpkg,
	zephyr,
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

// supersedeRules is the flat list of every ecosystem's superseding rules, so the
// walker evaluates them without re-walking the registry per file.
var supersedeRules = func() []Supersede {
	var out []Supersede
	for _, eco := range all {
		out = append(out, eco.Supersedes...)
	}
	return out
}()

// supersedeTracker accumulates, over one filesystem walk, what a single
// Supersede rule needs to decide: where the lockfiles are, and which manifest
// directories they must cover.
type supersedeTracker struct {
	lockDirs     map[string]bool
	manifestDirs map[string]bool
}

// observe records a file the walk reached, if the rule cares about it.
func (t *supersedeTracker) observe(rule *Supersede, dir, basename string) {
	if strings.EqualFold(basename, rule.Lock) {
		t.lockDirs[dir] = true
		return
	}
	for _, m := range rule.Manifests {
		if strings.EqualFold(basename, m) {
			t.manifestDirs[dir] = true
			return
		}
	}
}

// fires reports whether the rule's plugins are redundant: at least one lockfile
// was found, and every manifest directory has one at or above it.
func (t *supersedeTracker) fires() bool {
	if len(t.lockDirs) == 0 {
		return false
	}
	for dir := range t.manifestDirs {
		if !t.covered(dir) {
			return false
		}
	}
	return true
}

// covered reports whether dir, or one of its ancestors, holds a lockfile.
func (t *supersedeTracker) covered(dir string) bool {
	for {
		if t.lockDirs[dir] {
			return true
		}
		if dir == "." || dir == "/" {
			return false
		}
		dir = pathpkg.Dir(dir)
	}
}

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
// graphParsersByFilename is the filename → parser dispatch table for offline
// dependency-edge extraction, built once over every GraphParser in every
// ecosystem.
var graphParsersByFilename = indexByFilename(all, func(eco *Ecosystem, add func(string, *GraphParser)) {
	for j := range eco.GraphParsers {
		p := &eco.GraphParsers[j]
		for _, fn := range p.Filenames {
			add(fn, p)
		}
	}
})

var licenseParsersByFilename = indexByFilename(all, func(eco *Ecosystem, add func(string, *LicenseParser)) {
	for j := range eco.LicenseParsers {
		p := &eco.LicenseParsers[j]
		for _, f := range p.Filenames {
			add(f, p)
		}
	}
})

// Survey walks fsys once and returns the ecosystems detected from marker
// filenames, the merged native-digest map mined from lockfiles, the merged
// licence map mined from lockfiles that embed licence data, the mined dependency
// edges, and the scalibr plugins the files present make redundant (see
// Ecosystem.PluginsSupersededBy). One pass covers all five. Operating on an fs.FS
// lets the same survey serve a real directory (os.DirFS) and any virtual
// filesystem.
//
// Per-parser failures are logged at warn level via slog.Default() but never
// fail the walk — a single broken lockfile must not block SBOM output.
// Permission errors on subtrees are skipped, not surfaced.
func Survey(fsys fs.FS) (ecosystems []string, digests hashes.Map, licenses license.Map, deps graph.Map, superseded []string) {
	digests = make(hashes.Map)
	licenses = make(license.Map)
	deps = make(graph.Map)
	found := make(map[string]struct{})

	trackers := make([]supersedeTracker, len(supersedeRules))
	for i := range trackers {
		trackers[i] = supersedeTracker{lockDirs: map[string]bool{}, manifestDirs: map[string]bool{}}
	}

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
		for i := range supersedeRules {
			trackers[i].observe(&supersedeRules[i], pathpkg.Dir(path), name)
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
		if p, ok := graphParsersByFilename[name]; ok {
			m, perr := parseGraphFile(fsys, path, p)
			if perr != nil {
				slog.Warn("dependency-graph parser failed",
					"ecosystem", p.Name,
					"path", path,
					"err", perr,
				)
			}
			deps.Merge(m)
		}
		return nil
	})

	ecosystems = make([]string, 0, len(found))
	for e := range found {
		ecosystems = append(ecosystems, e)
	}
	slices.Sort(ecosystems)

	var supersededLists [][]string
	for i := range supersedeRules {
		if trackers[i].fires() {
			supersededLists = append(supersededLists, supersedeRules[i].Plugins)
		}
	}
	return ecosystems, digests, licenses, deps, pluginset.Union(supersededLists...)
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

// parseGraphFile opens path within fsys and runs the dependency-graph parser
// over its contents, so parsers stay pure (io.Reader in, edges out) and
// Survey owns the filesystem access.
func parseGraphFile(fsys fs.FS, path string, p *GraphParser) (graph.Map, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return p.Parse(f)
}
