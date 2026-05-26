// ABOUTME: Source-code scan mode. Walks a directory and auto-detects lockfile-based ecosystems.
// ABOUTME: Produces a ScanConfig containing only filesystem extractors for the detected ecosystems.
package repo

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"

	scalibr "github.com/google/osv-scalibr"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

// Mode implements mode.Mode for source-code scans.
type Mode struct{}

// New returns a fresh repo mode.
func New() *Mode { return &Mode{} }

// Name returns the user-facing name.
func (*Mode) Name() string { return "repo" }

// Plan walks path once, surveying both lockfile-based ecosystems and the
// native digests inside those lockfiles, then maps the detected ecosystems
// to scalibr plugin names and returns a ScanConfig that scans only path.
func (*Mode) Plan(_ context.Context, path string, ov mode.Overrides) (*mode.Plan, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	ecosystems, hashMap := ecosystem.Survey(abs, nil)

	if len(ov.Ecosystems) > 0 {
		ecosystems = intersect(ecosystems, ov.Ecosystems)
	}

	pluginNames := ecosystem.PluginsFor(ecosystems)
	pluginNames = mode.ApplyOverrides(pluginNames, ov)

	if len(pluginNames) == 0 {
		return nil, fmt.Errorf("no extractors selected for %s (detected ecosystems: %v)", abs, ecosystems)
	}

	plugins, err := pl.FromNames(pluginNames, nil)
	if err != nil {
		return nil, fmt.Errorf("load plugins %v: %w", pluginNames, err)
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

	return &mode.Plan{
		Config: cfg,
		Component: mode.ComponentInfo{
			Name:    filepath.Base(abs),
			Version: "",
			Type:    mode.ComponentTypeApplication,
		},
		Hashes: hashMap,
	}, nil
}

// intersect returns the elements of a that also appear in b.
func intersect(a, b []string) []string {
	out := make([]string, 0, len(a))
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
