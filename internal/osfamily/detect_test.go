// ABOUTME: Tests LinuxDistroFamilies() against fixture filesystem roots.
// ABOUTME: Covers os-release parsing, ID_LIKE handling, package-DB fallbacks, dedup, and missing files.
package osfamily_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

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
			name:    "no os-release, chisel manifest only",
			dbPaths: []string{"var/lib/chisel/manifest.wall"},
			want:    []string{"chisel"},
		},
		{
			name:      "chiselled ubuntu detects both debian and chisel",
			osRelease: `ID=ubuntu` + "\n" + `ID_LIKE=debian`,
			dbPaths:   []string{"var/lib/chisel/manifest.wall"},
			want:      []string{"chisel", "debian"},
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

			got := osfamily.LinuxDistroFamilies(os.DirFS(root))
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

func TestLinuxOSRelease(t *testing.T) {
	tests := []struct {
		name          string
		osRelease     string // empty means the file is absent
		debianVersion string // contents of etc/debian_version; empty means absent
		wantID        string
		wantVersion   string
		wantOK        bool
	}{
		{
			name:          "debian prefers point release from debian_version",
			osRelease:     "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			debianVersion: "12.5\n",
			wantID:        "debian",
			wantVersion:   "12.5",
			wantOK:        true,
		},
		{
			name:          "debian testing falls back to VERSION_ID over codename",
			osRelease:     "ID=debian\nVERSION_ID=\"13\"\n",
			debianVersion: "trixie/sid\n",
			wantID:        "debian",
			wantVersion:   "13",
			wantOK:        true,
		},
		{
			name:          "ubuntu ignores debian_version, uses VERSION_ID",
			osRelease:     "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n",
			debianVersion: "trixie/sid\n",
			wantID:        "ubuntu",
			wantVersion:   "22.04",
			wantOK:        true,
		},
		{
			name:      "rolling distro has id but no version",
			osRelease: "NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n",
			wantID:    "arch",
			wantOK:    true,
		},
		{
			name:      "absent os-release yields not-ok",
			osRelease: "",
			wantOK:    false,
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
			if tc.debianVersion != "" {
				path := filepath.Join(root, "etc", "debian_version")
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(path, []byte(tc.debianVersion), 0o644); err != nil {
					t.Fatalf("write debian_version: %v", err)
				}
			}
			id, version, ok := osfamily.LinuxOSRelease(os.DirFS(root))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if id != tc.wantID {
				t.Errorf("id = %q, want %q", id, tc.wantID)
			}
			if version != tc.wantVersion {
				t.Errorf("version = %q, want %q", version, tc.wantVersion)
			}
		})
	}
}

// A line in etc/os-release past bufio.Scanner's 64 KiB default token size must
// not end the parse. Everything below it — potentially ID itself — would go
// unread, and the caller cannot tell a truncated file from a distroless root:
// both look like "no ID", which silently drops the operating-system component
// and every distro plugin with it.
func TestLinuxOSRelease_LongLineDoesNotTruncate(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release": &fstest.MapFile{Data: []byte(
			"PRETTY_NAME=\"" + strings.Repeat("x", 100*1024) + "\"\n" +
				"ID=debian\nVERSION_ID=\"12\"\n")},
	}

	id, version, ok := osfamily.LinuxOSRelease(fsys)

	if !ok || id != "debian" || version != "12" {
		t.Errorf("LinuxOSRelease = (%q, %q, %v), want (debian, 12, true) — fields after an over-long line were dropped", id, version, ok)
	}
}
