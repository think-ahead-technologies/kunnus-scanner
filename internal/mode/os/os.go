// ABOUTME: OS/firmware scan mode. Targets a filesystem root (live host or extracted firmware).
// ABOUTME: Auto-detects host OS and Linux distro, picks the matching scalibr extractors.
package os

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	scalibr "github.com/google/osv-scalibr"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/think-ahead/kunnus-scanner/internal/binclass"
	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/detect"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/osfamily"
	"github.com/think-ahead/kunnus-scanner/internal/ownership"
)

// Mode implements mode.Mode for OS-package scans.
type Mode struct{}

// New returns a fresh os mode.
func New() *Mode { return &Mode{} }

// Name returns the user-facing name.
func (*Mode) Name() string { return "os" }

// Plan picks plugins based on the target OS (auto-detected from runtime.GOOS,
// overridable via ov.TargetOS) and, for Linux, the distro family found at the scan root.
func (*Mode) Plan(_ context.Context, path string, ov mode.Overrides) (*mode.Plan, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	targetOS := ov.TargetOS
	if targetOS == "" {
		targetOS = detect.Host()
	}

	var pluginNames []string
	var component bom.ComponentInfo

	switch targetOS {
	case "linux":
		families := osfamily.LinuxDistroFamilies(scalibrfs.DirFS(abs))
		if len(families) == 0 {
			// No distro fingerprint at the scan root: enable every Linux
			// extractor so an unrecognised root is still scanned.
			pluginNames = osfamily.AllLinuxPlugins()
		} else {
			pluginNames = osfamily.LinuxPluginsFor(families)
		}
		component = bom.ComponentInfo{
			Name:    filepath.Base(abs),
			Version: "",
			Type:    bom.ComponentTypeOS,
		}
	case "windows":
		pluginNames = osfamily.WindowsPlugins()
		component = bom.ComponentInfo{
			Name:    "Windows",
			Version: "",
			Type:    bom.ComponentTypeOS,
		}
	case "mac":
		pluginNames = osfamily.MacPlugins()
		component = bom.ComponentInfo{
			Name:    "macOS",
			Version: "",
			Type:    bom.ComponentTypeOS,
		}
	default:
		return nil, fmt.Errorf("unsupported target OS %q", targetOS)
	}

	pluginNames = mode.ApplyOverrides(pluginNames, ov)
	if len(pluginNames) == 0 {
		return nil, errors.New("no extractors selected for OS scan")
	}

	plugins, err := pl.FromNames(pluginNames, nil)
	if err != nil {
		return nil, fmt.Errorf("load plugins %v: %w", pluginNames, err)
	}

	caps := capabilitiesFor(targetOS)
	plugins = mode.AddOfflineLicenseEnrichers(plugins)
	plugins, err = mode.AddOnlineLicenses(plugins, caps, ov)
	if err != nil {
		return nil, err
	}

	// The binary classifier surfaces software compiled into the root outside any
	// package manager. It is a kunnus extractor (not in scalibr's name registry),
	// so it is appended directly; its pkg:generic twins of OS-managed packages are
	// suppressed later in the encode pipeline. The ELF gate makes it a no-op on
	// the Windows/Mac targets.
	plugins = append(plugins, binclass.New())

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   scalibrfs.DirFS(abs),
			Path: abs,
		}},
		Plugins:      plugins,
		Capabilities: caps,
	}

	return &mode.Plan{
		Config: cfg,
		// An OS scan analyses built artifacts (installed packages, binaries),
		// so its generation context is post-build.
		Lifecycle: bom.LifecyclePostBuild,
		Component: component,
		// dpkg/apk file ownership at the scan root, so the encoder can suppress
		// binary-classifier pkg:generic twins of packaged binaries by path.
		OwnedFiles: ownership.Scan(scalibrfs.DirFS(abs)),
	}, nil
}

func capabilitiesFor(targetOS string) *plugin.Capabilities {
	switch targetOS {
	case "linux":
		return &plugin.Capabilities{OS: plugin.OSLinux, DirectFS: true}
	case "windows":
		return &plugin.Capabilities{OS: plugin.OSWindows, DirectFS: true}
	case "mac":
		return &plugin.Capabilities{OS: plugin.OSMac, DirectFS: true}
	}
	return &plugin.Capabilities{OS: plugin.OSAny}
}
