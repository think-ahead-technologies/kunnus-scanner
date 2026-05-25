// ABOUTME: Plugin-selection tables for OS-mode scans, keyed by target OS family.
// ABOUTME: One source of truth for "what do we run on Linux/Windows/macOS by default?"
package os

import (
	"slices"
	"sort"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

// linuxFamilyPlugins maps a distro family name (debian, rhel, alpine, ...) to
// the scalibr filesystem extractors that read its package database.
var linuxFamilyPlugins = map[string][]string{
	"debian":  {"os/dpkg"},
	"rhel":    {"os/rpm"},
	"suse":    {"os/rpm"},
	"alpine":  {"os/apk"},
	"arch":    {"os/pacman"},
	"gentoo":  {"os/portage"},
	"nix":     {"os/nix"},
	"flatpak": {"os/flatpak"},
	"snap":    {"os/snap"},
	"cos":     {"os/cos"},
}

// linuxPlugins returns the deduplicated plugin set for the detected distro families.
// If detection found nothing, fall back to "all known Linux package managers" so a
// firmware scan still produces output instead of bailing.
func linuxPlugins(families []string) []string {
	if len(families) == 0 {
		families = make([]string, 0, len(linuxFamilyPlugins))
		for f := range linuxFamilyPlugins {
			families = append(families, f)
		}
	}

	seen := make(map[string]struct{})
	for _, fam := range families {
		for _, p := range linuxFamilyPlugins[fam] {
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

// windowsPlugins returns the scalibr extractors used on Windows. Registry
// extractors are standalone (no filesystem walk); chocolatey/winget are
// filesystem extractors. Scalibr runs both flavours in a single Scan() call.
func windowsPlugins() []string {
	return []string{
		"windows/ospackages",
		"windows/regosversion",
		"windows/regpatchlevel",
		"windows/dismpatch",
		"os/chocolatey",
		"os/winget",
	}
}

// macPlugins returns the scalibr extractors used on macOS hosts.
func macPlugins() []string {
	return []string{
		"os/homebrew",
		"os/macports",
		"os/macapps",
	}
}

// applyOverrides adds names from ov.EnablePlugins and removes names in ov.DisablePlugins.
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
