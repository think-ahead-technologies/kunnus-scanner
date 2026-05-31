// ABOUTME: Defines the Mode interface that every scan flavour (repo, os, container) implements.
// ABOUTME: A Mode turns a target (path or image ref) plus user overrides into a ready-to-run scalibr scan plan.
package mode

import (
	"context"
	"slices"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
	"github.com/think-ahead/kunnus-scanner/internal/ownership"
)

// Mode is a scan flavour. Implementations live in subpackages (mode/repo,
// mode/os, mode/container).
//
// The contract is intentionally narrow: a Mode plans a scan and describes what
// it will produce. It does not run the scan, encode the SBOM, or upload.
// Those concerns live in internal/scan, internal/sbom, and internal/upload.
type Mode interface {
	// Name returns the user-facing mode name ("repo", "os", or "container").
	Name() string

	// Plan resolves the target and the overrides into a fully-populated Plan:
	// the scalibr ScanConfig, the root component metadata, and any native digests
	// harvested during planning. The target is a filesystem path for the
	// path-based modes (repo, os) and an image reference for container.
	//
	// Plan must not invoke any scalibr extractor — running the scan is
	// internal/scan's job. It may read the filesystem for auto-detection (e.g.
	// /etc/os-release, walking for lockfiles) and, for the container mode, open
	// the target image (which for a remote reference pulls it). When the scan
	// kind needs an opened image, Plan sets Plan.Image; the runner dispatches on
	// it.
	Plan(ctx context.Context, target string, overrides Overrides) (*Plan, error)
}

// Plan is everything a Mode produces from one planning pass: the scalibr
// ScanConfig, the root component metadata, and any native deployable hashes
// the mode harvested while it was already walking the tree. Hashes is nil for
// modes that have no planning-time hash sources (e.g. OS scans).
//
// ExtraComponents covers components scalibr did not produce — today, vendored
// C/C++ directories surfaced by the kunnus walker. The SBOM encoder appends
// these alongside scalibr's components; per-component hashes ride in Hashes
// under the same PURL so the standard injector picks them up.
type Plan struct {
	Config          *scalibr.ScanConfig
	Component       bom.ComponentInfo
	Hashes          hashes.Map
	ExtraComponents []bom.ExtraComponent

	// Image is the opened container image to scan. Non-nil selects a container
	// scan (scalibr ScanContainer over the image's layers); nil selects a
	// filesystem scan over Config.ScanRoots. Only the container mode sets it.
	Image image.Image

	// PostScanHashes recovers native digests that are only knowable once the
	// scan has produced its inventory — keyed, like Hashes, by the conventional
	// purl. nil for modes whose digests are all harvested during planning (repo,
	// os). The runner invokes it with the scan inventory and merges the result
	// into Hashes.
	PostScanHashes func(inventory.Inventory) hashes.Map

	// Licenses holds raw licences mined offline from lockfiles during planning
	// (e.g. composer.lock), keyed by conventional purl. The SBOM encoder
	// normalizes and merges these with any licences scalibr put in the
	// inventory. nil for modes/scans with no offline licence source.
	Licenses license.Map

	// OwnedFiles is the set of paths the scan root's OS package manager records
	// as owned (read from the dpkg/apk databases during planning). The SBOM
	// encoder uses it to suppress binary-classifier pkg:generic components that
	// duplicate a packaged binary. nil for modes with no OS package database
	// (repo).
	OwnedFiles ownership.Set
}

// Overrides captures user-facing flags that adjust what auto-detection chose.
// They are applied after detection so the user can surgically add or remove
// plugins without disabling the helpful defaults.
type Overrides struct {
	// TargetOS forces a specific OS for plugin selection. Empty means auto-detect.
	// Accepted values: "linux", "windows", "mac". Used by os mode.
	TargetOS string

	// Ecosystems restricts repo-mode auto-detection to the listed ecosystems.
	// Empty means "use whatever detection found". Used by repo mode.
	Ecosystems []string

	// Source selects how the container mode resolves an image reference:
	// "auto" (or empty), "remote", "tarball", or "docker". Used by container
	// mode; ignored by the path-based modes.
	Source string

	// EnablePlugins adds the named scalibr plugins to the selection.
	EnablePlugins []string

	// DisablePlugins removes the named scalibr plugins from the selection.
	DisablePlugins []string

	// OnlineLicenses opts into deps.dev licence enrichment. Off by default: this
	// is the only feature that makes network calls, so it is never enabled
	// implicitly. See OnlineLicenseEnricher.
	OnlineLicenses bool

	// LicenseAPIURL overrides the deps.dev gRPC endpoint used when OnlineLicenses
	// is set. Empty means DefaultLicenseAPI. Must speak the deps.dev Insights API.
	LicenseAPIURL string
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
	slices.Sort(plugins)
	return plugins
}
