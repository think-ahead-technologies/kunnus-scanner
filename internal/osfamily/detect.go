// ABOUTME: Linux distro detection from a filesystem root (live host or extracted firmware).
// ABOUTME: Inspects /etc/os-release plus per-family package-database fingerprints. Pure I/O.
package osfamily

import (
	"bufio"
	"io/fs"
	"strings"
)

// LinuxDistroFamilies inspects the filesystem root fsys and returns the distro
// families it recognises, evaluated against the registered linuxFamilies.
// Returns an empty slice when nothing matched — callers can then fall back to
// LinuxPluginsFor(nil) for the broad "all Linux extractors" set. Operating on
// an fs.FS lets the same detection serve a real root (os.DirFS) and any virtual
// filesystem.
//
// Detection strategy, in order:
//  1. Parse etc/os-release ID and ID_LIKE if present; match each value
//     against every family's OSReleaseIDs.
//  2. For each family with a PackageDBPath, check whether the path exists
//     within fsys.
//
// Order in the output matches discovery order; duplicates are collapsed.
func LinuxDistroFamilies(fsys fs.FS) []string {
	var families []string
	seen := make(map[string]bool)
	addFamily := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		families = append(families, name)
	}

	for _, id := range parseOSReleaseIDs(fsys) {
		for _, f := range linuxFamilies {
			for _, ruleID := range f.OSReleaseIDs {
				if id == ruleID {
					addFamily(f.Name)
				}
			}
		}
	}

	for _, f := range linuxFamilies {
		if f.PackageDBPath == "" {
			continue
		}
		if exists(fsys, f.PackageDBPath) {
			addFamily(f.Name)
		}
	}

	return families
}

// LinuxOSRelease reads etc/os-release from fsys and returns the distro ID and
// VERSION_ID (e.g. "debian", "12"). ok is false when os-release is absent or
// declares no ID — scratch and distroless images — and the caller should then
// omit the operating-system component rather than emit a nameless one.
func LinuxOSRelease(fsys fs.FS) (id, versionID string, ok bool) {
	kv := parseOSRelease(fsys)
	id = kv["ID"]
	return id, kv["VERSION_ID"], id != ""
}

// parseOSReleaseIDs returns every ID and ID_LIKE value in etc/os-release.
// Missing file or read errors yield nil — callers treat "no IDs" identically to
// "file absent", which matches the fallback contract.
func parseOSReleaseIDs(fsys fs.FS) []string {
	kv := parseOSRelease(fsys)
	var ids []string
	if id := kv["ID"]; id != "" {
		ids = append(ids, id)
	}
	if like := kv["ID_LIKE"]; like != "" {
		ids = append(ids, strings.Fields(like)...)
	}
	return ids
}

// parseOSRelease parses etc/os-release from fsys into its key/value pairs, with
// surrounding quotes stripped from values. Returns nil when the file is absent.
func parseOSRelease(fsys fs.FS) map[string]string {
	f, err := fsys.Open("etc/os-release")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = parseOSReleaseValue(v)
	}
	return out
}

func parseOSReleaseValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "\"")
	v = strings.TrimSuffix(v, "\"")
	v = strings.TrimPrefix(v, "'")
	v = strings.TrimSuffix(v, "'")
	return v
}

func exists(fsys fs.FS, name string) bool {
	_, err := fs.Stat(fsys, name)
	return err == nil
}
