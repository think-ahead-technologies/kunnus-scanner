// ABOUTME: Zephyr extractor — surfaces the RTOS modules a west.yml manifest pins for a workspace.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for Zephyr/west): each project -> a pkg:github or pkg:generic package at its pinned revision.
package zephyr

import (
	"context"
	"io"
	"net/url"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the Zephyr extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/zephyr"

// The west manifest filenames ("west.yml" canonically; the .yaml spelling
// also appears in the wild).
var manifestNames = []string{"west.yml", "west.yaml"}

// maxManifestBytes bounds how much of a matched file we read. Real manifests
// are a few KiB (Zephyr's own upstream one is ~30 KiB); this guards against an
// unrelated giant file being slurped.
const maxManifestBytes = 4 << 20 // 4 MiB

// Extractor surfaces Zephyr workspace modules. A west manifest lists every
// project (repository) the workspace is built from — the zephyr tree itself,
// HALs, crypto and filesystem modules — each pinned to a git revision (tag or
// SHA), which maps directly to a versioned package. Revisions are kept
// verbatim, the modustoolbox rule. Manifest import resolution (projects
// pulling in further west manifests from other repositories) needs those
// repositories on disk and is out of scope; the components declared by the
// scanned manifest itself are always emitted.
type Extractor struct{}

// New returns a Zephyr extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a west manifest (west.yml or west.yaml,
// matched case-insensitively).
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := path.Base(api.Path())
	for _, name := range manifestNames {
		if strings.EqualFold(base, name) {
			return true
		}
	}
	return false
}

// Extract parses the manifest's projects and emits one package per module. A
// malformed manifest yields no packages (and no error): a single bad west.yml
// must not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	specs := parseManifest(input.Reader)
	pkgs := make([]*extractor.Package, 0, len(specs))
	for _, s := range specs {
		pkgs = append(pkgs, &extractor.Package{
			Name:     s.name,
			Version:  s.version,
			PURLType: s.purlType,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// pkgSpec is one resolved project: the PURL type, the (owner/repo namespaced
// for GitHub) name, and the pinned git revision verbatim.
type pkgSpec struct {
	purlType string
	name     string
	version  string
}

// westManifest mirrors the west.yml fields the parser reads. The self entry
// describes the scanned tree itself and produces no component; import lists
// are ignored (see the Extractor doc).
type westManifest struct {
	Manifest struct {
		Defaults struct {
			Remote   string `yaml:"remote"`
			Revision string `yaml:"revision"`
		} `yaml:"defaults"`
		Remotes []struct {
			Name    string `yaml:"name"`
			URLBase string `yaml:"url-base"`
		} `yaml:"remotes"`
		Projects []struct {
			Name     string `yaml:"name"`
			Remote   string `yaml:"remote"`
			RepoPath string `yaml:"repo-path"`
			URL      string `yaml:"url"`
			Revision string `yaml:"revision"`
		} `yaml:"projects"`
	} `yaml:"manifest"`
}

// parseManifest resolves each project to a repository URL and revision per
// west's rules: an explicit url wins; otherwise the project's remote (falling
// back to defaults.remote, or the sole remote when only one is declared)
// contributes its url-base joined with repo-path or the project name. The
// revision falls back to defaults.revision, else the component is versionless —
// west's own fallback is a moving branch head, which is not a pin worth
// recording. github.com repositories become pkg:github (owner/repo namespaced);
// everything else, including projects whose remote cannot be resolved, becomes
// pkg:generic under the project name.
func parseManifest(r io.Reader) []pkgSpec {
	data, err := io.ReadAll(io.LimitReader(r, maxManifestBytes))
	if err != nil {
		return nil
	}
	var m westManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil
	}

	urlBases := make(map[string]string, len(m.Manifest.Remotes))
	for _, rem := range m.Manifest.Remotes {
		if rem.Name != "" && rem.URLBase != "" {
			urlBases[rem.Name] = rem.URLBase
		}
	}
	defaultRemote := m.Manifest.Defaults.Remote
	if defaultRemote == "" && len(m.Manifest.Remotes) == 1 {
		defaultRemote = m.Manifest.Remotes[0].Name
	}

	var specs []pkgSpec
	for _, p := range m.Manifest.Projects {
		if p.Name == "" {
			continue
		}
		repoURL := p.URL
		if repoURL == "" {
			remote := p.Remote
			if remote == "" {
				remote = defaultRemote
			}
			if base := urlBases[remote]; base != "" {
				repo := p.RepoPath
				if repo == "" {
					repo = p.Name
				}
				repoURL = strings.TrimSuffix(base, "/") + "/" + repo
			}
		}
		revision := p.Revision
		if revision == "" {
			revision = m.Manifest.Defaults.Revision
		}
		purlType, name := classifyRepoURL(repoURL, p.Name)
		specs = append(specs, pkgSpec{purlType: purlType, name: name, version: revision})
	}
	return specs
}

// classifyRepoURL maps a resolved repository URL to a PURL type and package
// name: github.com URLs become pkg:github with the owner/repo namespaced name;
// anything else — other hosts, or a project whose remote could not be resolved
// — becomes pkg:generic under the west project name.
func classifyRepoURL(repoURL, projectName string) (purlType, name string) {
	u, err := url.Parse(repoURL)
	if err == nil && strings.EqualFold(u.Hostname(), "github.com") {
		var segs []string
		for _, seg := range strings.Split(u.Path, "/") {
			if seg != "" {
				segs = append(segs, seg)
			}
		}
		if len(segs) >= 2 {
			repo := strings.TrimSuffix(segs[len(segs)-1], ".git")
			if repo != "" {
				return "github", segs[len(segs)-2] + "/" + repo
			}
		}
	}
	return "generic", projectName
}
