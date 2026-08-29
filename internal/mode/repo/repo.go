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

	"github.com/think-ahead/kunnus-scanner/internal/arduino"
	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/cmake"
	"github.com/think-ahead/kunnus-scanner/internal/cmsis"
	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/espidf"
	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/gitsubmodule"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/modustoolbox"
	"github.com/think-ahead/kunnus-scanner/internal/platformio"
	"github.com/think-ahead/kunnus-scanner/internal/pluginset"
	"github.com/think-ahead/kunnus-scanner/internal/vcpkg"
	"github.com/think-ahead/kunnus-scanner/internal/vendored"
	"github.com/think-ahead/kunnus-scanner/internal/zephyr"
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

	rootFS := scalibrfs.DirFS(abs)
	ecosystems, hashMap, licenseMap, graphMap, superseded := ecosystem.Survey(rootFS)

	// Vendored C/C++ libraries are surfaced unconditionally — the C/C++ source
	// check inside vendored.Survey keeps it quiet for Go/Python/JS-only vendor
	// directories. Hashes merge directly into the same map so the SBOM injector
	// picks them up without a second code path.
	vendoredHits, vendoredHashes := vendored.Survey(rootFS)
	hashMap.Merge(vendoredHashes)
	extras := make([]bom.ExtraComponent, 0, len(vendoredHits))
	for _, hit := range vendoredHits {
		extras = append(extras, bom.ExtraComponent{
			PURL:   hit.PURL,
			Name:   hit.Name,
			Type:   bom.ComponentTypeLibrary,
			BomRef: "vendored:" + hit.RelPath,
		})
	}

	if len(ov.Ecosystems) > 0 {
		ecosystems = intersect(ecosystems, ov.Ecosystems)
	}

	// Drop the extractors a file present in the tree made redundant — today, the
	// Cargo.toml extractor where a Cargo.lock resolves the same crates. Before
	// ApplyOverrides, so an explicit --enable of a superseded plugin still wins.
	pluginNames := pluginset.Without(ecosystem.PluginsFor(ecosystems), superseded)
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

	// A vendored Go module tree keeps its module list in vendor/modules.txt, the
	// one directory every walk otherwise skips. Where that manifest is present the
	// skip is lifted so scalibr's go/vendormodules can read it; elsewhere vendor/
	// stays skipped, keeping npm, composer and bundler install trees out of the
	// walk as before.
	var keepDirs []string
	if ecosystem.HasGoVendorTree(rootFS) {
		keepDirs = append(keepDirs, "vendor")
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{{
			FS:   rootFS,
			Path: abs,
		}},
		Plugins:      plugins,
		Capabilities: caps,
		UseGitignore: true,
		DirsToSkip:   fswalk.AbsoluteSkipPathsExcept(abs, keepDirs),
	}

	return &mode.Plan{
		Config: cfg,
		// A repo scan reads source (manifests, lockfiles), so its generation
		// context is pre-build.
		Lifecycle: bom.LifecyclePreBuild,
		Component: bom.ComponentInfo{
			Name:    filepath.Base(abs),
			Version: "",
			Type:    bom.ComponentTypeApplication,
		},
		Hashes:          hashMap,
		ExtraComponents: extras,
		Licenses:        licenseMap,
		Graph:           graphMap,
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
	if slices.Contains(ecosystems, "espidf") {
		out = append(out, espidf.New())
	}
	if slices.Contains(ecosystems, "zephyr") {
		out = append(out, zephyr.New())
	}
	if slices.Contains(ecosystems, "cmake") {
		out = append(out, cmake.New())
	}
	if slices.Contains(ecosystems, "arduino") {
		out = append(out, arduino.New())
	}
	if slices.Contains(ecosystems, "cmsis") {
		out = append(out, cmsis.New())
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
