// ABOUTME: Single source of truth for OS scan targets — distro families folded with scalibr plugin selection.
// ABOUTME: Mirrors internal/ecosystem: one struct per Linux family carries detection metadata and plugin names together.
package osfamily

import (
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey"
	"github.com/google/osv-scalibr/extractor/filesystem/os/cos"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/flatpak"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macapps"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macports"
	"github.com/google/osv-scalibr/extractor/filesystem/os/nix"
	"github.com/google/osv-scalibr/extractor/filesystem/os/pacman"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
	"github.com/google/osv-scalibr/extractor/filesystem/os/winget"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch"
	"github.com/google/osv-scalibr/extractor/standalone/windows/ospackages"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regosversion"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regpatchlevel"

	"github.com/think-ahead/kunnus-scanner/internal/pluginset"
)

// LinuxFamily folds the detection metadata for one distro family together
// with the scalibr extractors that read its package database. One entry per
// family is the single source of truth — adding a family means one struct
// literal in linuxFamilies, no other registration site to keep in sync.
//
// Families with empty OSReleaseIDs and empty PackageDBPath are fallback-only:
// they never surface from LinuxDistroFamilies, but their plugins are included
// when no family is detected (the "unknown distro, run everything" behaviour).
type LinuxFamily struct {
	// Name is the family identifier ("debian", "rhel", ...). Returned by
	// LinuxDistroFamilies and consumed by LinuxPluginsFor.
	Name string

	// OSReleaseIDs lists /etc/os-release ID and ID_LIKE values that map to
	// this family. Empty means no os-release fingerprint.
	OSReleaseIDs []string

	// PackageDBPath is a path relative to the scan root whose existence
	// proves the family is installed. Empty means no DB fingerprint.
	PackageDBPath string

	// ScalibrPlugins lists the scalibr extractor names enabled when this
	// family is selected.
	ScalibrPlugins []string
}

// linuxFamilies is the master list. Adding or removing a family is one struct
// literal here. Order does not matter — LinuxPluginsFor sorts its output.
var linuxFamilies = []LinuxFamily{
	{
		Name:           "debian",
		OSReleaseIDs:   []string{"ubuntu", "debian", "raspbian", "linuxmint", "kali"},
		PackageDBPath:  "var/lib/dpkg/status",
		ScalibrPlugins: []string{dpkg.Name},
	},
	{
		Name:           "rhel",
		OSReleaseIDs:   []string{"rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol"},
		PackageDBPath:  "var/lib/rpm",
		ScalibrPlugins: []string{rpm.Name},
	},
	{
		Name:           "suse",
		OSReleaseIDs:   []string{"sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"},
		ScalibrPlugins: []string{rpm.Name},
	},
	{
		Name:           "alpine",
		OSReleaseIDs:   []string{"alpine"},
		PackageDBPath:  "lib/apk/db/installed",
		ScalibrPlugins: []string{apk.Name},
	},
	{
		Name:           "arch",
		OSReleaseIDs:   []string{"arch", "manjaro"},
		PackageDBPath:  "var/lib/pacman/local",
		ScalibrPlugins: []string{pacman.Name},
	},
	{
		Name:           "gentoo",
		OSReleaseIDs:   []string{"gentoo"},
		PackageDBPath:  "var/db/pkg",
		ScalibrPlugins: []string{portage.Name},
	},
	{
		Name:           "nix",
		OSReleaseIDs:   []string{"nixos"},
		PackageDBPath:  "nix/store",
		ScalibrPlugins: []string{nix.Name},
	},
	{
		Name:           "cos",
		OSReleaseIDs:   []string{"cos"},
		ScalibrPlugins: []string{cos.Name},
	},
	// Fallback-only families: no detection fingerprint, plugins included
	// only when the empty-families fallback fires.
	{
		Name:           "flatpak",
		ScalibrPlugins: []string{flatpak.Name},
	},
	{
		Name:           "snap",
		ScalibrPlugins: []string{snap.Name},
	},
}

// LinuxFamilies returns the registered families. Exposed for introspection
// and invariant tests; production code should use LinuxDistroFamilies and
// LinuxPluginsFor instead.
func LinuxFamilies() []LinuxFamily { return linuxFamilies }

// LinuxPluginsFor returns the deduplicated, sorted scalibr plugin names
// enabled by the given family names. If families is empty, returns the union
// of every known Linux family's plugins — the "unknown distro, scan
// everything" fallback used when detection produced nothing.
//
// Unknown family names are silently ignored: callers (mode/os) drive the
// list from detect output, which is itself derived from this package.
func LinuxPluginsFor(families []string) []string {
	if len(families) == 0 {
		families = make([]string, 0, len(linuxFamilies))
		for _, f := range linuxFamilies {
			families = append(families, f.Name)
		}
	}
	var lists [][]string
	for _, name := range families {
		for _, f := range linuxFamilies {
			if f.Name == name {
				lists = append(lists, f.ScalibrPlugins)
			}
		}
	}
	return pluginset.Union(lists...)
}

// WindowsPlugins returns the scalibr extractors used on Windows. Registry
// extractors are standalone (no filesystem walk); chocolatey/winget are
// filesystem extractors. Scalibr runs both flavours in a single Scan() call.
//
// Windows has no per-family detection — every Windows scan runs all of them.
func WindowsPlugins() []string {
	return []string{
		ospackages.Name,
		regosversion.Name,
		regpatchlevel.Name,
		dismpatch.Name,
		chocolatey.Name,
		winget.Name,
	}
}

// MacPlugins returns the scalibr extractors used on macOS hosts.
// macOS has no per-family detection — every Mac scan runs all of them.
func MacPlugins() []string {
	return []string{
		homebrew.Name,
		macports.Name,
		macapps.Name,
	}
}
