// ABOUTME: Maps detected ecosystems to scalibr plugin names for source-code scans.
// ABOUTME: Single source of truth for "which extractors do we want when ecosystem X is present?"
package repo

import (
	"slices"
	"sort"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

// ecosystemPlugins lists the scalibr plugin names enabled per detected ecosystem.
// Keep this table tight: only add a plugin here once we have integration coverage
// confirming it produces useful output for that ecosystem.
var ecosystemPlugins = map[string][]string{
	"npm":      {"javascript/packagejson", "javascript/packagelockjson", "javascript/pnpmlock", "javascript/yarnlock"},
	"go":       {"go/gomod", "go/binary"},
	"cargo":    {"rust/cargoauditable", "rust/cargolock"},
	"dotnet":   {"dotnet/csproj", "dotnet/depsjson", "dotnet/nugetcpm", "dotnet/packagesconfig", "dotnet/packageslockjson", "dotnet/pe"},
	"maven":    {"java/pomxml", "java/archive"},
	"gradle":   {"java/gradlelockfile", "java/gradleverificationmetadataxml"},
	"python":   {"python/poetrylock", "python/pdmlock", "python/pipfilelock", "python/requirements", "python/setup", "python/wheelegg"},
	"composer": {"php/composerlock"},
	"ruby":     {"ruby/gemfilelock"},
	"swift":    {"swift/packageresolved", "swift/podfilelock"},
	"haskell":  {"haskell/cabal", "haskell/stacklock"},
	"r":        {"r/renvlock"},
}

// pluginsFor returns the deduplicated, sorted set of plugin names for the given ecosystems.
func pluginsFor(ecosystems []string) []string {
	seen := make(map[string]struct{})
	for _, eco := range ecosystems {
		for _, p := range ecosystemPlugins[eco] {
			seen[p] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// applyOverrides adds names from ov.EnablePlugins and removes names from ov.DisablePlugins.
func applyOverrides(plugins []string, ov mode.Overrides) []string {
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
