// ABOUTME: Linux distro detection from a given filesystem root (live host or extracted firmware).
// ABOUTME: Inspects /etc/os-release plus package-database fingerprints. Pure I/O, no scalibr.
package detect

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// LinuxDistroFamilies inspects the filesystem root at scanRoot and returns the
// distro families it recognises. Returns an empty slice (not an error) when nothing
// is found — callers can then fall back to a broad "all Linux extractors" set.
//
// Detection strategy, in order:
//  1. Parse /etc/os-release ID and ID_LIKE if present.
//  2. Fall back to package-database fingerprints (dpkg/rpm/apk paths).
func LinuxDistroFamilies(scanRoot string) ([]string, error) {
	families := familiesFromOSRelease(scanRoot)
	families = append(families, familiesFromPackageDBs(scanRoot)...)
	return dedup(families), nil
}

func familiesFromOSRelease(scanRoot string) []string {
	path := filepath.Join(scanRoot, "etc", "os-release")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return nil
	}
	defer func() { _ = f.Close() }()

	var ids []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "ID="):
			ids = append(ids, parseOSReleaseValue(strings.TrimPrefix(line, "ID=")))
		case strings.HasPrefix(line, "ID_LIKE="):
			ids = append(ids, strings.Fields(parseOSReleaseValue(strings.TrimPrefix(line, "ID_LIKE=")))...)
		}
	}

	var families []string
	for _, id := range ids {
		if fam := osReleaseIDToFamily(id); fam != "" {
			families = append(families, fam)
		}
	}
	return families
}

func familiesFromPackageDBs(scanRoot string) []string {
	var families []string
	if exists(filepath.Join(scanRoot, "var", "lib", "dpkg", "status")) {
		families = append(families, "debian")
	}
	if exists(filepath.Join(scanRoot, "var", "lib", "rpm")) {
		families = append(families, "rhel")
	}
	if exists(filepath.Join(scanRoot, "lib", "apk", "db", "installed")) {
		families = append(families, "alpine")
	}
	if exists(filepath.Join(scanRoot, "var", "lib", "pacman", "local")) {
		families = append(families, "arch")
	}
	if exists(filepath.Join(scanRoot, "var", "db", "pkg")) {
		families = append(families, "gentoo")
	}
	if exists(filepath.Join(scanRoot, "nix", "store")) {
		families = append(families, "nix")
	}
	return families
}

func osReleaseIDToFamily(id string) string {
	switch id {
	case "ubuntu", "debian", "raspbian", "linuxmint", "kali":
		return "debian"
	case "rhel", "centos", "fedora", "rocky", "almalinux", "amzn", "ol":
		return "rhel"
	case "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "suse"
	case "alpine":
		return "alpine"
	case "arch", "manjaro":
		return "arch"
	case "gentoo":
		return "gentoo"
	case "nixos":
		return "nix"
	case "cos":
		return "cos"
	}
	return ""
}

func parseOSReleaseValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "\"")
	v = strings.TrimSuffix(v, "\"")
	v = strings.TrimPrefix(v, "'")
	v = strings.TrimSuffix(v, "'")
	return v
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func dedup(in []string) []string {
	out := make([]string, 0, len(in))
	for _, x := range in {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
