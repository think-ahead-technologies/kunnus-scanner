// ABOUTME: Git-submodule extractor — surfaces dependencies a superproject vendors as submodules declared in .gitmodules.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin covers submodule manifests): each stanza -> a pkg:github or pkg:generic package pinned to the gitlink SHA from .git/index.
package gitsubmodule

import (
	"context"
	"io"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/filemode"
	gitcfg "github.com/go-git/go-git/v5/plumbing/format/config"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the git-submodule extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/gitsubmodule"

// manifestName is the submodule manifest git writes at a superproject root.
const manifestName = ".gitmodules"

// maxManifestBytes bounds how much of a matched file we read. Real .gitmodules
// files are tiny; this guards against an unrelated giant file being slurped.
const maxManifestBytes = 1 << 20 // 1 MiB

// Extractor surfaces git submodules. The .gitmodules manifest names each
// submodule's path and remote URL; the pinned commit is not in the manifest but
// in the superproject's index as a gitlink entry, so Extract also decodes
// .git/index (when present) to version each component with the exact SHA the
// superproject tracks — no checkout of the submodule itself is needed.
type Extractor struct{}

// New returns a git-submodule extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a submodule manifest (a file named
// .gitmodules, matched case-insensitively). Backups and similar near-names do
// not match.
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	return strings.EqualFold(path.Base(api.Path()), manifestName)
}

// Extract parses the manifest's submodule stanzas and emits one package per
// remote: pkg:github for github.com URLs (owner/repo namespaced, like
// modustoolbox), pkg:generic otherwise. Versions come from the sibling
// .git/index gitlink entries; without an index (an exported tree) the
// components are emitted versionless. A malformed manifest yields no packages
// (and no error): a single bad .gitmodules must not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	subs := parseGitmodules(input.Reader)
	if len(subs) == 0 {
		return inventory.Inventory{}, nil
	}
	shas := submoduleSHAs(input.FS, path.Dir(input.Path))
	pkgs := make([]*extractor.Package, 0, len(subs))
	for _, s := range subs {
		purlType, name := classifyURL(s.url)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, &extractor.Package{
			Name:     name,
			Version:  shas[s.path],
			PURLType: purlType,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// submodule is one .gitmodules stanza: the worktree path the superproject
// mounts it at (the key gitlink entries are found under) and its remote URL.
type submodule struct {
	path string
	url  string
}

// parseGitmodules decodes the git-config-format manifest via go-git's config
// decoder and returns each submodule stanza that names both a path and a URL.
// Malformed input yields nil.
func parseGitmodules(r io.Reader) []submodule {
	cfg := gitcfg.New()
	if err := gitcfg.NewDecoder(io.LimitReader(r, maxManifestBytes)).Decode(cfg); err != nil {
		return nil
	}
	var subs []submodule
	for _, sec := range cfg.Section("submodule").Subsections {
		p, u := sec.Option("path"), sec.Option("url")
		if p == "" || u == "" {
			continue
		}
		subs = append(subs, submodule{path: p, url: u})
	}
	return subs
}

// submoduleSHAs decodes the superproject index at dir/.git/index and returns
// the gitlink (submodule-mode) entries as a worktree-path → full-SHA map. Any
// failure — no .git (exported tarball), a worktree .git file instead of a
// directory, an undecodable index — yields nil, and the caller emits
// versionless components instead.
func submoduleSHAs(fsys fs.FS, dir string) map[string]string {
	f, err := fsys.Open(path.Join(dir, ".git", "index"))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var idx index.Index
	if err := index.NewDecoder(f).Decode(&idx); err != nil {
		return nil
	}
	shas := make(map[string]string)
	for _, e := range idx.Entries {
		if e.Mode == filemode.Submodule {
			shas[e.Name] = e.Hash.String()
		}
	}
	return shas
}

// classifyURL maps a submodule remote URL to a PURL type and package name:
// github.com remotes (https, ssh, or scp-like) become pkg:github with the
// "owner/repo" namespaced name; anything else — other hosts, relative URLs —
// becomes pkg:generic named by the URL's last path segment. A URL naming
// nothing returns an empty name and the submodule is dropped.
func classifyURL(raw string) (purlType, name string) {
	host, p := splitHostPath(strings.TrimSpace(raw))
	var segs []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		return "", ""
	}
	repo := strings.TrimSuffix(segs[len(segs)-1], ".git")
	if repo == "" {
		return "", ""
	}
	if strings.EqualFold(host, "github.com") && len(segs) >= 2 {
		return "github", segs[len(segs)-2] + "/" + repo
	}
	return "generic", repo
}

// splitHostPath separates a remote URL into host and path, understanding the
// three forms git remotes take: scheme URLs (https://, ssh://, git://),
// scp-like "user@host:path" shorthand, and scheme-less relative/local paths
// (which have no host).
func splitHostPath(raw string) (host, p string) {
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", raw
		}
		return u.Hostname(), u.Path
	}
	// scp-like: [user@]host:path — the colon comes before any slash.
	if i := strings.IndexByte(raw, ':'); i >= 0 && !strings.Contains(raw[:i], "/") {
		userHost := raw[:i]
		if j := strings.LastIndexByte(userHost, '@'); j >= 0 {
			userHost = userHost[j+1:]
		}
		return userHost, raw[i+1:]
	}
	return "", raw
}
