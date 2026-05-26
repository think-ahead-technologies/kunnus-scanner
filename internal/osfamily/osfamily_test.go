// ABOUTME: Registry invariants + plugin-selection tests for the OS-family registry.
// ABOUTME: Mirrors internal/ecosystem's ecosystem_test.go — same drift class, same invariant style.
package osfamily

import (
	"slices"
	"testing"
)

// TestRegistry_FamilyNamesAreUnique guards against adding a family twice.
// Two entries sharing a name would double-count plugins on detection.
func TestRegistry_FamilyNamesAreUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for _, f := range linuxFamilies {
		if f.Name == "" {
			t.Errorf("family has empty Name: %+v", f)
			continue
		}
		if _, dup := seen[f.Name]; dup {
			t.Errorf("duplicate family name %q", f.Name)
		}
		seen[f.Name] = struct{}{}
	}
}

// TestRegistry_PluginsNonEmpty: every family must enable at least one plugin,
// otherwise detecting it is a no-op and the registration is dead weight.
func TestRegistry_PluginsNonEmpty(t *testing.T) {
	for _, f := range linuxFamilies {
		if len(f.ScalibrPlugins) == 0 {
			t.Errorf("family %q has no ScalibrPlugins", f.Name)
		}
	}
}

// TestRegistry_OSReleaseIDsAreUniqueAcrossFamilies guarantees that an
// /etc/os-release ID maps to exactly one family. Two families claiming
// "debian" would silently double the detected set.
func TestRegistry_OSReleaseIDsAreUniqueAcrossFamilies(t *testing.T) {
	owner := make(map[string]string)
	for _, f := range linuxFamilies {
		for _, id := range f.OSReleaseIDs {
			if other, dup := owner[id]; dup {
				t.Errorf("os-release ID %q claimed by both %q and %q", id, other, f.Name)
			}
			owner[id] = f.Name
		}
	}
}

// TestRegistry_PackageDBPathsAreUnique: same drift concern as OS-release IDs,
// applied to the package-database fingerprints.
func TestRegistry_PackageDBPathsAreUnique(t *testing.T) {
	owner := make(map[string]string)
	for _, f := range linuxFamilies {
		if f.PackageDBPath == "" {
			continue
		}
		if other, dup := owner[f.PackageDBPath]; dup {
			t.Errorf("package-DB path %q claimed by both %q and %q", f.PackageDBPath, other, f.Name)
		}
		owner[f.PackageDBPath] = f.Name
	}
}

func TestLinuxPluginsFor(t *testing.T) {
	tests := []struct {
		name     string
		families []string
		wantSome []string
	}{
		{
			name:     "debian only",
			families: []string{"debian"},
			wantSome: []string{"os/dpkg"},
		},
		{
			name:     "rhel and suse share rpm",
			families: []string{"rhel", "suse"},
			wantSome: []string{"os/rpm"},
		},
		{
			name:     "alpine",
			families: []string{"alpine"},
			wantSome: []string{"os/apk"},
		},
		{
			name:     "empty falls back to all linux extractors",
			families: nil,
			wantSome: []string{"os/dpkg", "os/rpm", "os/apk", "os/pacman", "os/portage"},
		},
		{
			name:     "unknown family yields nothing",
			families: []string{"plan9"},
			wantSome: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := LinuxPluginsFor(tc.families)
			if !slices.IsSorted(got) {
				t.Errorf("LinuxPluginsFor not sorted: %v", got)
			}
			for _, p := range tc.wantSome {
				if !slices.Contains(got, p) {
					t.Errorf("LinuxPluginsFor(%v) missing %q (got %v)", tc.families, p, got)
				}
			}
		})
	}
}

func TestLinuxPluginsFor_FallbackIncludesFlatpakAndSnap(t *testing.T) {
	// Fallback-only families exist for exactly one purpose: ride along on the
	// empty-families path. If they drop out of LinuxPluginsFor(nil) the
	// "unknown distro" scan loses coverage silently.
	got := LinuxPluginsFor(nil)
	for _, must := range []string{"os/flatpak", "os/snap"} {
		if !slices.Contains(got, must) {
			t.Errorf("fallback set missing %q (got %v)", must, got)
		}
	}
}

func TestWindowsPlugins(t *testing.T) {
	got := WindowsPlugins()
	for _, must := range []string{"windows/ospackages", "windows/regosversion", "windows/regpatchlevel"} {
		if !slices.Contains(got, must) {
			t.Errorf("WindowsPlugins missing %q (got %v)", must, got)
		}
	}
}

func TestMacPlugins(t *testing.T) {
	got := MacPlugins()
	for _, must := range []string{"os/homebrew", "os/macports"} {
		if !slices.Contains(got, must) {
			t.Errorf("MacPlugins missing %q (got %v)", must, got)
		}
	}
}
