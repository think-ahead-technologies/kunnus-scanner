// ABOUTME: Source-code scan mode. Walks a directory and auto-detects lockfile-based ecosystems.
// ABOUTME: Produces a ScanConfig containing only filesystem extractors for the detected ecosystems.
package repo

import (
	"context"
	"fmt"
	"path/filepath"

	scalibr "github.com/google/osv-scalibr"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/think-ahead/kunnus-scanner/internal/detect"
	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

// Mode implements mode.Mode for source-code scans.
type Mode struct{}

// New returns a fresh repo mode.
func New() *Mode { return &Mode{} }

// Name returns the user-facing name.
func (*Mode) Name() string { return "repo" }

// Plan walks path looking for lockfile signatures, maps them to scalibr plugin
// names, applies overrides, and returns a ScanConfig that scans only path.
func (*Mode) Plan(_ context.Context, path string, ov mode.Overrides) (*scalibr.ScanConfig, mode.ComponentInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, mode.ComponentInfo{}, fmt.Errorf("resolve path: %w", err)
	}

	ecosystems, err := detect.Ecosystems(abs)
	if err != nil {
		return nil, mode.ComponentInfo{}, fmt.Errorf("detect ecosystems: %w", err)
	}

	if len(ov.Ecosystems) > 0 {
		ecosystems = intersect(ecosystems, ov.Ecosystems)
	}

	pluginNames := pluginsFor(ecosystems)
	pluginNames = mode.ApplyOverrides(pluginNames, ov)

	if len(pluginNames) == 0 {
		return nil, mode.ComponentInfo{}, fmt.Errorf("no extractors selected for %s (detected ecosystems: %v)", abs, ecosystems)
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
		Capabilities: &plugin.Capabilities{OS: plugin.OSAny},
		UseGitignore: true,
		DirsToSkip:   fswalk.AbsoluteSkipPaths(abs),
	}

	return cfg, mode.ComponentInfo{
		Name:    filepath.Base(abs),
		Version: "",
		Type:    mode.ComponentTypeApplication,
	}, nil
}
