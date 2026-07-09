// ABOUTME: vcpkg extractor — surfaces C/C++ dependencies declared in a manifest-mode vcpkg.json.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for vcpkg): each dependency -> a pkg:generic package, versioned from overrides or "version>=" floors.
package vcpkg

import (
	"context"
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name is the scalibr plugin name for the vcpkg extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/vcpkg"

// manifestName is the manifest-mode marker vcpkg reads at a project root.
const manifestName = "vcpkg.json"

// maxManifestBytes bounds how much of a matched file we read. Real manifests
// are a few KiB; this guards against an unrelated giant vcpkg.json being
// slurped whole.
const maxManifestBytes = 4 << 20 // 4 MiB

// Extractor surfaces vcpkg dependencies. A manifest declares dependency names,
// optionally with a "version>=" floor; exact pins live in the top-level
// "overrides" array. vcpkg has no lockfile, and resolving the "builtin-baseline"
// commit to concrete versions needs the vcpkg registry (network access the
// scanner forbids), so the version emitted is the best offline data: the
// override pin, else the declared floor, else none.
type Extractor struct{}

// New returns a vcpkg extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is a vcpkg manifest (a file named
// vcpkg.json, matched case-insensitively). vcpkg-configuration.json and other
// registry bookkeeping are not manifests and do not match.
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	return strings.EqualFold(path.Base(api.Path()), manifestName)
}

// Extract parses the manifest and emits one pkg:generic package per declared
// dependency. A malformed manifest yields no packages (and no error): a single
// bad vcpkg.json must not fail the scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	deps := parseManifest(input.Reader)
	if len(deps) == 0 {
		return inventory.Inventory{}, nil
	}
	pkgs := make([]*extractor.Package, 0, len(deps))
	for _, d := range deps {
		pkgs = append(pkgs, &extractor.Package{
			Name:     d.name,
			Version:  d.version,
			PURLType: "generic",
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// dep is one declared dependency with the best version knowable offline
// (override pin > "version>=" floor > empty).
type dep struct {
	name    string
	version string
}

// manifest mirrors the vcpkg.json fields the parser reads. Dependencies mix
// bare strings and objects, so they decode via json.RawMessage.
type manifest struct {
	Dependencies []json.RawMessage `json:"dependencies"`
	Overrides    []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"overrides"`
}

// depObject is the object form of a dependency entry. Only the fields that
// contribute to identification are read; "features", "platform", "host" and
// "default-features" select build variants, not different components.
type depObject struct {
	Name       string `json:"name"`
	VersionGte string `json:"version>="`
}

// parseManifest reads a vcpkg.json and returns its declared dependencies with
// versions resolved from "overrides" first (exact pins), then each dependency's
// own "version>=" floor. Malformed JSON or a manifest without dependencies
// yields nil. A "#N" port-version suffix on a floor is stripped: the port
// revision is vcpkg packaging metadata, not an upstream version.
func parseManifest(r io.Reader) []dep {
	var m manifest
	if err := json.NewDecoder(io.LimitReader(r, maxManifestBytes)).Decode(&m); err != nil {
		return nil
	}
	pins := make(map[string]string, len(m.Overrides))
	for _, o := range m.Overrides {
		if o.Name != "" && o.Version != "" {
			pins[o.Name] = o.Version
		}
	}
	var deps []dep
	for _, raw := range m.Dependencies {
		name, floor := parseDependency(raw)
		if name == "" {
			continue
		}
		version := pins[name]
		if version == "" {
			version = floor
		}
		deps = append(deps, dep{name: name, version: version})
	}
	return deps
}

// parseDependency decodes one entry of the "dependencies" array, which is
// either a bare port name or an object carrying "name" and optionally a
// "version>=" floor. Unparseable entries yield an empty name.
func parseDependency(raw json.RawMessage) (name, floor string) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, ""
	}
	var o depObject
	if err := json.Unmarshal(raw, &o); err != nil {
		return "", ""
	}
	floor, _, _ = strings.Cut(o.VersionGte, "#")
	return o.Name, floor
}
