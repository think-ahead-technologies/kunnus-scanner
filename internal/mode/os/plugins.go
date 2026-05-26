// ABOUTME: Plugin-selection tables for OS-mode scans, keyed by target OS family.
// ABOUTME: One source of truth for "what do we run on Linux/Windows/macOS by default?"
package os

import (
	"sort"

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
)

// linuxFamilyPlugins maps a distro family name (debian, rhel, alpine, ...) to
// the scalibr filesystem extractors that read its package database.
var linuxFamilyPlugins = map[string][]string{
	"debian":  {dpkg.Name},
	"rhel":    {rpm.Name},
	"suse":    {rpm.Name},
	"alpine":  {apk.Name},
	"arch":    {pacman.Name},
	"gentoo":  {portage.Name},
	"nix":     {nix.Name},
	"flatpak": {flatpak.Name},
	"snap":    {snap.Name},
	"cos":     {cos.Name},
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
		ospackages.Name,
		regosversion.Name,
		regpatchlevel.Name,
		dismpatch.Name,
		chocolatey.Name,
		winget.Name,
	}
}

// macPlugins returns the scalibr extractors used on macOS hosts.
func macPlugins() []string {
	return []string{
		homebrew.Name,
		macports.Name,
		macapps.Name,
	}
}
