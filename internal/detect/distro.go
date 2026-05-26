// ABOUTME: Linux distro detection from a given filesystem root (live host or extracted firmware).
// ABOUTME: Inspects /etc/os-release plus package-database fingerprints. Pure I/O, no scalibr.
package detect

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FamilyRule describes one Linux distro family for LinuxDistroFamilies.
// internal/osfamily owns the canonical rule set and folds it together with
// scalibr plugin selection; callers obtain a slice via
// osfamily.LinuxDetectionRules() and pass it in. The split keeps detect
// scalibr-free (architecture rule #1) while the rule data lives next to the
// plugin-name mapping it informs.
type FamilyRule struct {
	// Name is the family identifier returned by LinuxDistroFamilies on a match.
	Name string

	// OSReleaseIDs lists /etc/os-release ID and ID_LIKE values that map to
	// this family. Empty means no os-release fingerprint for this rule.
	OSReleaseIDs []string

	// PackageDBPath is a path relative to the scan root whose existence
	// proves the family is installed. Empty means no DB fingerprint.
	PackageDBPath string
}

// LinuxDistroFamilies inspects the filesystem root at scanRoot and returns the
// distro families it recognises, evaluated against rules. Returns an empty
// slice when nothing matched — callers can then fall back to a broad "all
// Linux extractors" set.
//
// Detection strategy, in order:
//  1. Parse /etc/os-release ID and ID_LIKE if present; match each value
//     against every rule's OSReleaseIDs.
//  2. For each rule with a PackageDBPath, check whether the path exists
//     relative to scanRoot.
//
// Order in the output matches discovery order; duplicates are collapsed.
func LinuxDistroFamilies(scanRoot string, rules []FamilyRule) []string {
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
		for _, r := range rules {
			for _, ruleID := range r.OSReleaseIDs {
				if id == ruleID {
					addFamily(r.Name)
				}
			}
		}
	}

	for _, r := range rules {
		if r.PackageDBPath == "" {
			continue
		}
		if exists(filepath.Join(scanRoot, r.PackageDBPath)) {
			addFamily(r.Name)
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
