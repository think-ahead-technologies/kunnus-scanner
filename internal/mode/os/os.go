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

	"github.com/think-ahead/kunnus-scanner/internal/detect"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

// Mode implements mode.Mode for OS-package scans.
type Mode struct{}

// New returns a fresh os mode.
func New() *Mode { return &Mode{} }

// Name returns the user-facing name.
func (*Mode) Name() string { return "os" }

// Plan picks plugins based on the target OS (auto-detected from runtime.GOOS,
// overridable via ov.TargetOS) and, for Linux, the distro family found at the scan root.
func (*Mode) Plan(_ context.Context, path string, ov mode.Overrides) (*scalibr.ScanConfig, mode.ComponentInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, mode.ComponentInfo{}, fmt.Errorf("resolve path: %w", err)
	}

	targetOS := ov.TargetOS
	if targetOS == "" {
		targetOS = detect.Host()
	}

	var pluginNames []string
	var component mode.ComponentInfo

	switch targetOS {
	case "linux":
		families, derr := detect.LinuxDistroFamilies(abs)
		if derr != nil {
			return nil, mode.ComponentInfo{}, fmt.Errorf("detect linux distro: %w", derr)
		}
		pluginNames = linuxPlugins(families)
		component = mode.ComponentInfo{
			Name:    filepath.Base(abs),
			Version: "",
			Type:    "operating-system",
		}
	case "windows":
		pluginNames = windowsPlugins()
		component = mode.ComponentInfo{
			Name:    "Windows",
			Version: "",
			Type:    "operating-system",
		}
	case "mac", "darwin":
		pluginNames = macPlugins()
		component = mode.ComponentInfo{
			Name:    "macOS",
			Version: "",
			Type:    "operating-system",
		}
	default:
		return nil, mode.ComponentInfo{}, fmt.Errorf("unsupported target OS %q", targetOS)
	}

	pluginNames = applyOverrides(pluginNames, ov)
	if len(pluginNames) == 0 {
		return nil, mode.ComponentInfo{}, errors.New("no extractors selected for OS scan")
	}

	plugins, err := pl.FromNames(pluginNames, nil)
	if err != nil {
		return nil, mode.ComponentInfo{}, fmt.Errorf("load plugins %v: %w", pluginNames, err)
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   scalibrfs.DirFS(abs),
			Path: abs,
		}},
		Plugins:      plugins,
		Capabilities: capabilitiesFor(targetOS),
	}

	return cfg, component, nil
}

func capabilitiesFor(targetOS string) *plugin.Capabilities {
	switch targetOS {
	case "linux":
		return &plugin.Capabilities{OS: plugin.OSLinux, DirectFS: true}
	case "windows":
		return &plugin.Capabilities{OS: plugin.OSWindows, DirectFS: true}
	case "mac", "darwin":
		return &plugin.Capabilities{OS: plugin.OSMac, DirectFS: true}
	}
	return &plugin.Capabilities{OS: plugin.OSAny}
}
