// ABOUTME: Pure mapping tests for OS-mode distro → plugin and applyOverrides logic.
// ABOUTME: Verifies that an empty families slice falls back to the all-Linux extractor set.
package os

import (
	"reflect"
	"slices"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

func TestLinuxPlugins(t *testing.T) {
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
			got := linuxPlugins(tc.families)
			if !slices.IsSorted(got) {
				t.Errorf("linuxPlugins not sorted: %v", got)
			}
			for _, p := range tc.wantSome {
				if !slices.Contains(got, p) {
					t.Errorf("linuxPlugins(%v) missing %q (got %v)", tc.families, p, got)
				}
			}
		})
	}
}

func TestWindowsPlugins(t *testing.T) {
	got := windowsPlugins()
	for _, must := range []string{"windows/ospackages", "windows/regosversion", "windows/regpatchlevel"} {
		if !slices.Contains(got, must) {
			t.Errorf("windowsPlugins missing %q (got %v)", must, got)
		}
	}
}

func TestMacPlugins(t *testing.T) {
	got := macPlugins()
	for _, must := range []string{"os/homebrew", "os/macports"} {
		if !slices.Contains(got, must) {
			t.Errorf("macPlugins missing %q (got %v)", must, got)
		}
	}
}

func TestApplyOverrides_OS(t *testing.T) {
	base := []string{"os/dpkg", "os/rpm"}

	got := applyOverrides(slices.Clone(base), mode.Overrides{
		EnablePlugins:  []string{"os/apk"},
		DisablePlugins: []string{"os/rpm"},
	})
	want := []string{"os/apk", "os/dpkg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("applyOverrides = %v, want %v", got, want)
	}
}
