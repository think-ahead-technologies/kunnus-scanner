// ABOUTME: Defines the Mode interface that the two scan flavours (repo, os) implement.
// ABOUTME: A Mode turns a target path plus user overrides into a ready-to-run scalibr ScanConfig.
package mode

import (
	"context"
	"slices"
	"sort"

	scalibr "github.com/google/osv-scalibr"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// Mode is a scan flavour. Implementations live in subpackages (mode/repo, mode/os).
//
// The contract is intentionally narrow: a Mode plans a scan and describes what it
// will produce. It does not run the scan, encode the SBOM, or talk to the network.
// Those concerns live in internal/scan, internal/sbom, and internal/upload.
type Mode interface {
	// Name returns the user-facing mode name ("repo" or "os").
	Name() string

	// Plan inspects the target and the overrides, then returns a fully-populated
	// scalibr ScanConfig together with the root component metadata and any
	// native digests harvested during planning.
	//
	// Plan must not perform the scan itself. It may read the filesystem for
	// auto-detection (e.g. /etc/os-release, walking for lockfiles), but must
	// not invoke any scalibr plugin.
	Plan(ctx context.Context, path string, overrides Overrides) (*Plan, error)
}

// Plan is everything a Mode produces from one planning pass: the scalibr
// ScanConfig, the root component metadata, and any native deployable hashes
// the mode harvested while it was already walking the tree. Hashes is nil for
// modes that have no per-package hash sources (e.g. OS scans).
//
// ExtraComponents covers components scalibr did not produce — today, vendored
// C/C++ directories surfaced by the kunnus walker. The SBOM encoder appends
// these alongside scalibr's components; per-component hashes ride in Hashes
// under the same PURL so the standard injector picks them up.
type Plan struct {
	Config          *scalibr.ScanConfig
	Component       ComponentInfo
	Hashes          hashes.Map
	ExtraComponents []ExtraComponent
}

// ExtraComponent is one BOM component sourced outside scalibr. The fields are
// the minimum a CycloneDX library entry needs; everything else (hashes,
// per-file properties) flows through Hashes keyed on PURL.
type ExtraComponent struct {
	// PURL is the package-url for the component. Vendored libs use the
	// pkg:generic type with a vendored_path qualifier.
	PURL string

	// Name is the short human-readable name (the vendored directory's basename).
	Name string

	// Type is the CycloneDX component type — "library" for vendored sources.
	Type string

	// BomRef is a stable identifier within the BOM ("vendored:<rel-path>").
	BomRef string
}

// Overrides captures user-facing flags that adjust what auto-detection chose.
// They are applied after detection so the user can surgically add or remove
// plugins without disabling the helpful defaults.
type Overrides struct {
	// TargetOS forces a specific OS for plugin selection. Empty means auto-detect.
	// Accepted values: "linux", "windows", "mac".
	TargetOS string

	// Ecosystems restricts repo-mode auto-detection to the listed ecosystems.
	// Empty means "use whatever detection found". Ignored by os mode.
	Ecosystems []string

	// EnablePlugins adds the named scalibr plugins to the selection.
	EnablePlugins []string

	// DisablePlugins removes the named scalibr plugins from the selection.
	DisablePlugins []string
}

// Component type values for ComponentInfo.Type. These are the CycloneDX
// `metadata.component.type` strings; we list them here because mode is the
// canonical place that decides which type a scan produces.
const (
	ComponentTypeApplication = "application"
	ComponentTypeOS          = "operating-system"
	ComponentTypeFirmware    = "firmware"
	ComponentTypeLibrary     = "library"
)

// ComponentInfo describes the root component of the resulting SBOM.
// CycloneDX puts this in metadata.component.
type ComponentInfo struct {
	Name    string
	Version string
	Type    string // one of ComponentType* constants above
}

// ApplyOverrides folds ov.EnablePlugins and ov.DisablePlugins into the given
// plugin list. The result is sorted and free of names listed in DisablePlugins.
// Duplicates are not introduced — names already in plugins are not re-added.
func ApplyOverrides(plugins []string, ov Overrides) []string {
	for _, add := range ov.EnablePlugins {
		if !slices.Contains(plugins, add) {
			plugins = append(plugins, add)
		}
	}
	plugins = slices.DeleteFunc(plugins, func(p string) bool {
		return slices.Contains(ov.DisablePlugins, p)
	})
	sort.Strings(plugins)
	return plugins
}
