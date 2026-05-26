// ABOUTME: Linux distro detection from a filesystem root (live host or extracted firmware).
// ABOUTME: Inspects /etc/os-release plus per-family package-database fingerprints. Pure I/O.
package osfamily

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LinuxDistroFamilies inspects the filesystem root at scanRoot and returns the
// distro families it recognises, evaluated against the registered linuxFamilies.
// Returns an empty slice when nothing matched — callers can then fall back to
// LinuxPluginsFor(nil) for the broad "all Linux extractors" set.
//
// Detection strategy, in order:
//  1. Parse /etc/os-release ID and ID_LIKE if present; match each value
//     against every family's OSReleaseIDs.
//  2. For each family with a PackageDBPath, check whether the path exists
//     relative to scanRoot.
//
// Order in the output matches discovery order; duplicates are collapsed.
func LinuxDistroFamilies(scanRoot string) []string {
	var families []string
	seen := make(map[string]bool)
	addFamily := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		families = append(families, name)
	}

	for _, id := range parseOSReleaseIDs(scanRoot) {
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
		if exists(filepath.Join(scanRoot, f.PackageDBPath)) {
			addFamily(f.Name)
		}
	}

	return families
}

// parseOSReleaseIDs reads scanRoot/etc/os-release and returns every ID and
// ID_LIKE value found. Missing file or read errors yield nil — callers treat
// "no IDs" identically to "file absent", which matches the fallback contract.
func parseOSReleaseIDs(scanRoot string) []string {
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
	return ids
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
