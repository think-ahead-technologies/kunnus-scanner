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

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/gitsubmodule"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/modustoolbox"
	"github.com/think-ahead/kunnus-scanner/internal/platformio"
	"github.com/think-ahead/kunnus-scanner/internal/vcpkg"
	"github.com/think-ahead/kunnus-scanner/internal/vendored"
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

	ecosystems, hashMap, licenseMap := ecosystem.Survey(scalibrfs.DirFS(abs))

	// Vendored C/C++ libraries are surfaced unconditionally — the C/C++ source
	// check inside vendored.Survey keeps it quiet for Go/Python/JS-only vendor
	// directories. Hashes merge directly into the same map so the SBOM injector
	// picks them up without a second code path.
	vendoredHits, vendoredHashes := vendored.Survey(abs)
	hashMap.Merge(vendoredHashes)
	extras := make([]bom.ExtraComponent, 0, len(vendoredHits))
	for _, hit := range vendoredHits {
		extras = append(extras, bom.ExtraComponent{
			PURL:   hit.PURL,
			Name:   hit.Name,
			Type:   bom.ComponentTypeLibrary,
			BomRef: "vendored:" + filepath.ToSlash(hit.RelPath),
		})
	}

	if len(ov.Ecosystems) > 0 {
		ecosystems = intersect(ecosystems, ov.Ecosystems)
	}

	pluginNames := ecosystem.PluginsFor(ecosystems)
	pluginNames = mode.ApplyOverrides(pluginNames, ov)

	// Kunnus-native extractors for detected ecosystems that have no scalibr
	// plugin (ModusToolbox). Like binclass in mode/os, the instance is appended
	// directly here rather than resolved by name through scalibr's registry.
	nativeExtractors := nativeExtractorsFor(ecosystems)

	// We need something to ship — a scalibr plugin selection, a kunnus-native
	// extractor, or at least one ExtraComponent (a vendored-only C/C++ repo is a
	// valid scan target). Without any, there is nothing for the SBOM to describe.
	if len(pluginNames) == 0 && len(nativeExtractors) == 0 && len(extras) == 0 {
		return nil, fmt.Errorf("no extractors selected for %s (detected ecosystems: %v)", abs, ecosystems)
	}

	plugins, err := pl.FromNames(pluginNames, nil)
	if err != nil {
		return nil, fmt.Errorf("load plugins %v: %w", pluginNames, err)
	}

	// Drop plugins that cannot run under these capabilities. Some ecosystems
	// pull in OS-specific extractors (e.g. dotnet/pe is Windows-only); scalibr
	// hard-fails the whole scan if such a plugin is enabled on a host it can't
	// run on. Filtering here keeps the remaining extractors for that ecosystem.
	caps := &plugin.Capabilities{OS: plugin.OSAny}
	plugins = plugin.FilterByCapabilities(plugins, caps)

	plugins = mode.AddOfflineLicenseEnrichers(plugins)
	plugins, err = mode.AddOnlineLicenses(plugins, caps, ov)
	if err != nil {
		return nil, err
	}

	// Append kunnus-native extractors last, after capability filtering and
	// licence enrichers, mirroring how mode/os wires in binclass.
	plugins = append(plugins, nativeExtractors...)

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   scalibrfs.DirFS(abs),
			Path: abs,
		}},
		Plugins:      plugins,
		Capabilities: caps,
		UseGitignore: true,
		DirsToSkip:   fswalk.AbsoluteSkipPaths(abs),
	}

	return &mode.Plan{
		Config: cfg,
		Component: bom.ComponentInfo{
			Name:    filepath.Base(abs),
			Version: "",
			Type:    bom.ComponentTypeApplication,
		},
		Hashes:          hashMap,
		ExtraComponents: extras,
		Licenses:        licenseMap,
	}, nil
}

// nativeExtractorsFor returns the kunnus-native filesystem extractors for the
// detected ecosystems that scalibr cannot supply a plugin for. The mapping from
// an ecosystem name to its extractor instance lives here (mode/repo may know
// both ecosystem names and concrete extractors) so the ecosystem registry stays
// free of scalibr APIs.
func nativeExtractorsFor(ecosystems []string) []plugin.Plugin {
	var out []plugin.Plugin
	if slices.Contains(ecosystems, "modustoolbox") {
		out = append(out, modustoolbox.New())
	}
	if slices.Contains(ecosystems, "vcpkg") {
		out = append(out, vcpkg.New())
	}
	if slices.Contains(ecosystems, "gitsubmodule") {
		out = append(out, gitsubmodule.New())
	}
	if slices.Contains(ecosystems, "platformio") {
		out = append(out, platformio.New())
	}
	return out
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
