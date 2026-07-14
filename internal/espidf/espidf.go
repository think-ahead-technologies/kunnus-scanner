// ABOUTME: ESP-IDF extractor — surfaces Espressif component-manager dependencies from dependencies.lock and idf_component.yml.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for ESP-IDF): lockfile components -> exact pkg:generic versions; manifests are the range-versioned fallback when no lock exists.
package espidf

import (
	"context"
	"io"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the ESP-IDF extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/espidf"

// The two component-manager files: the manifest declares dependencies (with
// constraints), the lockfile records what the manager resolved them to.
const (
	manifestName = "idf_component.yml"
	lockName     = "dependencies.lock"
)

// maxFileBytes bounds how much of a matched file we read. Real manifests and
// lockfiles are a few KiB; this guards against an unrelated giant file being
// slurped.
const maxFileBytes = 4 << 20 // 4 MiB

// maxLockSearchDepth bounds how far up from a manifest Extract looks for the
// project lockfile. IDF manifests live at most a few levels below the project
// root (main/, components/<x>/, managed_components/<ns>__<x>/).
const maxLockSearchDepth = 8

// Extractor surfaces ESP-IDF component-manager dependencies. dependencies.lock
// is authoritative when present: it pins exact versions for the whole project
// (direct and transitive, including the idf framework itself), so manifests
// under a locked project are skipped entirely — emitting their ranges alongside
// the lock's pins would duplicate every component under two purls. A project
// without a lockfile falls back to its manifests' declared constraints,
// verbatim (resolving a range needs the Espressif component registry, i.e.
// network access the scanner forbids).
type Extractor struct{}

// New returns an ESP-IDF extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a component-manager file (an
// idf_component.yml manifest or a dependencies.lock, matched
// case-insensitively).
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := path.Base(api.Path())
	return strings.EqualFold(base, manifestName) || strings.EqualFold(base, lockName)
}

// Extract parses the matched file and emits one package per component. A
// malformed file yields no packages (and no error): a single bad manifest must
// not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var specs []pkgSpec
	if strings.EqualFold(path.Base(input.Path), lockName) {
		specs = parseLock(input.Reader)
	} else if !lockExistsAbove(input.FS, path.Dir(input.Path)) {
		specs = parseManifest(input.Reader)
	}
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

// pkgSpec is one parsed component: the PURL type, the (usually
// namespace/name) component name, and the resolved version or declared
// constraint verbatim.
type pkgSpec struct {
	purlType string
	name     string
	version  string
}

// lockExistsAbove reports whether a dependencies.lock sits in dir or any
// ancestor up to the scan root (bounded by maxLockSearchDepth). When it does,
// the lock covers this manifest's components with exact versions.
func lockExistsAbove(fsys fs.FS, dir string) bool {
	for range maxLockSearchDepth {
		if f, err := fsys.Open(path.Join(dir, lockName)); err == nil {
			_ = f.Close()
			return true
		}
		if dir == "." {
			return false
		}
		dir = path.Dir(dir)
	}
	return false
}

// espidfLock mirrors the dependencies.lock fields the parser reads. The
// top-level version field is the lockfile schema version and is ignored.
type espidfLock struct {
	Dependencies map[string]struct {
		Version string `yaml:"version"`
	} `yaml:"dependencies"`
}

// parseLock reads the resolved dependency set: every component the manager
// installed, keyed "namespace/name" (or the bare "idf" framework
// pseudo-component), at its exact version. All become pkg:generic — the lock
// records only registry/idf sources by name.
func parseLock(r io.Reader) []pkgSpec {
	var lock espidfLock
	if err := yaml.Unmarshal(readAll(r), &lock); err != nil {
		return nil
	}
	var specs []pkgSpec
	for name, dep := range lock.Dependencies {
		if name == "" || dep.Version == "" {
			continue
		}
		specs = append(specs, pkgSpec{purlType: "generic", name: name, version: dep.Version})
	}
	return specs
}

// espidfManifest mirrors the idf_component.yml fields the parser reads. A
// dependency value is either a scalar constraint or a mapping, so entries
// decode via yaml.Node.
type espidfManifest struct {
	Dependencies map[string]yaml.Node `yaml:"dependencies"`
}

// manifestDep is the mapping form of a dependency entry.
type manifestDep struct {
	Version string `yaml:"version"`
	Git     string `yaml:"git"`
	Path    string `yaml:"path"`
}

// parseManifest reads a manifest's declared dependencies. A bare component
// name (other than the idf framework itself) implies the espressif/ registry
// namespace. Constraints stay verbatim except the "*" wildcard, which means
// "any" and becomes versionless. Local path components describe project-
// internal code and are dropped; git sources are classified by host like every
// other kunnus extractor (github.com → pkg:github, else pkg:generic).
func parseManifest(r io.Reader) []pkgSpec {
	var m espidfManifest
	if err := yaml.Unmarshal(readAll(r), &m); err != nil {
		return nil
	}
	var specs []pkgSpec
	for name, node := range m.Dependencies {
		if name == "" {
			continue
		}
		var dep manifestDep
		switch node.Kind {
		case yaml.ScalarNode:
			dep.Version = node.Value
		case yaml.MappingNode:
			if err := node.Decode(&dep); err != nil {
				continue
			}
		default:
			continue
		}
		if dep.Version == "*" {
			dep.Version = ""
		}
		switch {
		case dep.Git != "":
			if s := classifyGit(dep.Git, dep.Version); s != nil {
				specs = append(specs, *s)
			}
		case dep.Path != "":
			// A project-internal component, not a third-party dependency.
		default:
			if name != "idf" && !strings.Contains(name, "/") {
				name = "espressif/" + name
			}
			specs = append(specs, pkgSpec{purlType: "generic", name: name, version: dep.Version})
		}
	}
	return specs
}

// classifyGit maps a git source URL to a package: github.com URLs become
// pkg:github with the owner/repo namespaced name, other hosts pkg:generic named
// by the last path segment. The version is the manifest's declared git ref.
func classifyGit(gitURL, version string) *pkgSpec {
	u, err := url.Parse(strings.TrimSpace(gitURL))
	if err != nil {
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
	if strings.EqualFold(u.Hostname(), "github.com") && len(segs) >= 2 {
		return &pkgSpec{purlType: "github", name: segs[len(segs)-2] + "/" + repo, version: version}
	}
	return &pkgSpec{purlType: "generic", name: repo, version: version}
}

// readAll drains r up to maxFileBytes, returning nil on error so callers'
// yaml.Unmarshal fails cleanly.
func readAll(r io.Reader) []byte {
	data, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
	if err != nil {
		return nil
	}
	return data
}
