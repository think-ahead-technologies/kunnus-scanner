// ABOUTME: Defines the Mode interface that the two scan flavours (repo, os) implement.
// ABOUTME: A Mode turns a target path plus user overrides into a ready-to-run scalibr ScanConfig.
package mode

import (
	"context"

	scalibr "github.com/google/osv-scalibr"
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
	// scalibr ScanConfig along with metadata describing the root SBOM component.
	//
	// Plan must not perform the scan itself. It may read the filesystem for
	// auto-detection (e.g. /etc/os-release, walking for lockfiles), but must
	// not invoke any scalibr plugin.
	Plan(ctx context.Context, path string, overrides Overrides) (*scalibr.ScanConfig, ComponentInfo, error)
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

// ComponentInfo describes the root component of the resulting SBOM.
// SPDX puts this in the DocumentName; CycloneDX puts it in metadata.component.
type ComponentInfo struct {
	Name    string
	Version string
	Type    string // "application" | "operating-system" | "firmware"
}
