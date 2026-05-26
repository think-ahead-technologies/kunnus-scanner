// ABOUTME: Tests LinuxDistroFamilies() against fixture filesystem roots.
// ABOUTME: Covers os-release parsing, ID_LIKE handling, package-DB fallbacks, dedup, and missing files.
package detect_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/detect"
	"github.com/think-ahead/kunnus-scanner/internal/osfamily"
)

func TestLinuxDistroFamilies(t *testing.T) {
	tests := []struct {
		name      string
		osRelease string   // contents of etc/os-release, empty means file absent
		dbPaths   []string // additional empty paths to create relative to scan root
		want      []string // expected sorted families
	}{
		{
			name:      "ubuntu",
			osRelease: `ID=ubuntu` + "\n" + `ID_LIKE=debian`,
			want:      []string{"debian"},
		},
		{
			name:      "debian quoted",
			osRelease: `ID="debian"`,
			want:      []string{"debian"},
		},
		{
			name:      "alpine",
			osRelease: `ID=alpine`,
			want:      []string{"alpine"},
		},
		{
			name:      "rhel via centos",
			osRelease: `ID="centos"` + "\n" + `ID_LIKE="rhel fedora"`,
			want:      []string{"rhel"},
		},
		{
			name:      "suse",
			osRelease: `ID=opensuse-leap`,
			want:      []string{"suse"},
		},
		{
			name:      "arch",
			osRelease: `ID=arch`,
			want:      []string{"arch"},
		},
		{
			name:      "unknown ID falls through to nothing",
			osRelease: `ID=plan9`,
			want:      []string{},
		},
		{
			name:    "no os-release, dpkg only",
			dbPaths: []string{"var/lib/dpkg/status"},
			want:    []string{"debian"},
		},
		{
			name:    "no os-release, rpm only",
			dbPaths: []string{"var/lib/rpm/Packages"},
			want:    []string{"rhel"},
		},
		{
			name:    "no os-release, apk only",
			dbPaths: []string{"lib/apk/db/installed"},
			want:    []string{"alpine"},
		},
		{
			name:      "os-release + matching db dedups",
			osRelease: `ID=debian`,
			dbPaths:   []string{"var/lib/dpkg/status"},
			want:      []string{"debian"},
		},
		{
			name:      "completely empty root",
			osRelease: "",
			want:      []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.osRelease != "" {
				path := filepath.Join(root, "etc", "os-release")
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(path, []byte(tc.osRelease), 0o644); err != nil {
					t.Fatalf("write os-release: %v", err)
				}
			}
			for _, rel := range tc.dbPaths {
				abs := filepath.Join(root, rel)
				if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(abs, nil, 0o644); err != nil {
					t.Fatalf("write %s: %v", abs, err)
				}
			}

			got := detect.LinuxDistroFamilies(root, osfamily.LinuxDetectionRules())
			// Normalise nil vs empty slice for comparison.
			if got == nil {
				got = []string{}
			}
			slices.Sort(got)
			slices.Sort(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("LinuxDistroFamilies = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHost_ReturnsCanonicalName(t *testing.T) {
	// Host() reads runtime.GOOS — we just verify it's one of the canonical names.
	got := detect.Host()
	allowed := []string{"linux", "windows", "mac", "freebsd", "openbsd", "netbsd"}
	if !slices.Contains(allowed, got) {
		t.Errorf("Host() = %q, want one of %v", got, allowed)
	}
}
