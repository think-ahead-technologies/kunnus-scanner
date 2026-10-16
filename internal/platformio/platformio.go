// ABOUTME: PlatformIO extractor — surfaces library dependencies declared in platformio.ini lib_deps options.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for PlatformIO): registry specs -> pkg:generic, github VCS URLs -> pkg:github.
package platformio

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/url"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the PlatformIO extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/platformio"

// configName is the project configuration file PlatformIO reads at a project
// root.
const configName = "platformio.ini"

// maxConfigBytes bounds how much of a matched file we read. Real configs are a
// few KiB; this guards against an unrelated giant platformio.ini being slurped.
const maxConfigBytes = 1 << 20 // 1 MiB

// maxLineBytes bounds a single config line while scanning.
const maxLineBytes = 64 << 10 // 64 KiB

// Extractor surfaces PlatformIO library dependencies. Each environment section
// of platformio.ini may declare a lib_deps option listing registry specs
// ("owner/name @ version", bare names) and VCS URLs; those become pkg:generic
// (registry) or pkg:github (github URL) packages. Versions and version ranges
// are kept verbatim — a range is the declared truth and inventing a resolution
// would be wrong without PlatformIO's registry (network access the scanner
// forbids).
type Extractor struct{}

// New returns a PlatformIO extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a PlatformIO project configuration (a
// file named platformio.ini, matched case-insensitively).
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	return strings.EqualFold(path.Base(api.Path()), configName)
}

// Extract collects every lib_deps entry across all sections and emits one
// package per parseable entry. Duplicate declarations across environments
// collapse later in the SBOM dedup stage. A malformed config yields no packages
// (and no error): a single bad platformio.ini must not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var pkgs []*extractor.Package
	entries, err := parseINI(input.Reader)
	if err != nil {
		slog.Warn("platformio config truncated; some lib_deps entries will be missing", "path", input.Path, "err", err)
	}
	for _, entry := range entries {
		p := parseEntry(entry)
		if p == nil {
			continue
		}
		pkgs = append(pkgs, &extractor.Package{
			Name:     p.name,
			Version:  p.version,
			PURLType: p.purlType,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// parseINI scans the config and returns the raw lib_deps entries from every
// section, in file order. PlatformIO's ini dialect (python configparser)
// continues a value on indented lines, so a "lib_deps =" key collects entries
// until the next non-indented line; the single-line "lib_deps = x" form yields
// its value directly. Comment lines (";", "#") are skipped.
//
// A line past maxLineBytes ends the scan. The entries read so far are still
// returned — a partial dependency list beats none — and the error goes back to
// Extract, which logs it rather than dropping the remaining sections silently.
func parseINI(r io.Reader) ([]string, error) {
	var entries []string
	inLibDeps := false
	sc := bufio.NewScanner(io.LimitReader(r, maxConfigBytes))
	sc.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for sc.Scan() {
		line := sc.Text()
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indented {
			if inLibDeps {
				entries = append(entries, trimmed)
			}
			continue
		}
		inLibDeps = false
		if strings.HasPrefix(trimmed, "[") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "lib_deps") {
			continue
		}
		inLibDeps = true
		// An inline value that is only a comment ("lib_deps = ; none") is blank.
		if v := strings.TrimSpace(value); v != "" && !strings.HasPrefix(v, ";") && !strings.HasPrefix(v, "#") {
			entries = append(entries, v)
		}
	}
	return entries, sc.Err()
}

// pkgSpec is one parsed lib_deps entry: the PURL type, the (possibly
// owner-namespaced) name, and the declared version, ref, or range verbatim.
type pkgSpec struct {
	purlType string
	name     string
	version  string
}

// parseEntry parses one lib_deps entry. The grammar (PlatformIO package
// specifications) mixes registry specs — "name", "owner/name", either followed
// by "@ <version-or-range>" with optional spaces — and source URLs with an
// optional "#<ref>". github.com URLs become pkg:github with the owner/repo
// namespaced name; other remote URLs become pkg:generic named by the last path
// segment. Local sources (file://, symlink://) and interpolations
// ("${common.lib_deps}") describe no third-party component and are dropped.
func parseEntry(s string) *pkgSpec {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, "${") {
		return nil
	}
	if strings.Contains(s, "://") {
		return parseSourceURL(s)
	}
	name, version, _ := strings.Cut(s, "@")
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	return &pkgSpec{purlType: "generic", name: name, version: strings.TrimSpace(version)}
}

// parseSourceURL parses a VCS/archive source entry of the form
// "[git+]<scheme>://<host>/<path>[#<ref>]".
func parseSourceURL(s string) *pkgSpec {
	base, ref, _ := strings.Cut(s, "#")
	base = strings.TrimPrefix(strings.TrimSpace(base), "git+")
	u, err := url.Parse(base)
	if err != nil {
		return nil
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "file" || scheme == "symlink" {
		return nil
	}
	var segs []string
	for _, seg := range strings.Split(u.Path, "/") {
		if seg != "" {
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return nil
	}
	repo := strings.TrimSuffix(segs[len(segs)-1], ".git")
	if repo == "" {
		return nil
	}
	ref = strings.TrimSpace(ref)
	if strings.EqualFold(u.Hostname(), "github.com") && len(segs) >= 2 {
		return &pkgSpec{purlType: "github", name: segs[len(segs)-2] + "/" + repo, version: ref}
	}
	return &pkgSpec{purlType: "generic", name: repo, version: ref}
}
