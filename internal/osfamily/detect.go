// ABOUTME: Linux distro detection from a filesystem root (live host or extracted firmware).
// ABOUTME: Inspects /etc/os-release plus per-family package-database fingerprints. Pure I/O.
package osfamily

import (
	"bufio"
	"io/fs"
	"log/slog"
	"regexp"
	"strings"
)

// LinuxDistroFamilies inspects the filesystem root fsys and returns the distro
// families it recognises, evaluated against the registered linuxFamilies.
// Returns an empty slice when nothing matched — callers can then fall back to
// AllLinuxPlugins for the broad "all Linux extractors" set. Operating on
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

// versionFiles maps an os-release ID to a file whose numeric content is a more
// precise version than os-release's VERSION_ID. Only distros whose VERSION_ID
// is coarser than a dedicated file need an entry: today just Debian, whose
// VERSION_ID is the major ("12") while etc/debian_version carries the point
// release ("12.5"). For every other supported distro VERSION_ID is already the
// canonical version (rhel/rocky/suse carry the point release there, alpine's
// etc/alpine-release just duplicates it, and rolling releases have none).
//
// Keyed by ID rather than family on purpose: a derivative shares its family's
// detection fingerprints but not its base distro's version file — Ubuntu (the
// debian family) ships /etc/debian_version describing Debian ("bookworm/sid"),
// which must not be read as Ubuntu's version.
var versionFiles = map[string]string{
	"debian": "etc/debian_version",
}

// LinuxOSRelease reads etc/os-release from fsys and returns the distro ID and
// version (e.g. "debian", "12.5"). ok is false when os-release is absent or
// declares no ID — scratch and distroless images — and the caller should then
// omit the operating-system component rather than emit a nameless one.
//
// The version is os-release VERSION_ID, overridden by a more precise per-distro
// version file when one applies (see versionFiles). The override is ignored
// unless it holds a concrete numeric version, so Debian testing/unstable (whose
// debian_version is a "codename/sid" string) correctly falls back to VERSION_ID.
func LinuxOSRelease(fsys fs.FS) (id, version string, ok bool) {
	kv := parseOSRelease(fsys)
	id = kv["ID"]
	version = kv["VERSION_ID"]
	if vf, has := versionFiles[id]; has {
		if v, ok := numericVersionFile(fsys, vf); ok {
			version = v
		}
	}
	return id, version, id != ""
}

// numericVersionRe matches a concrete dotted-numeric version ("12" or "12.5"),
// excluding non-numeric forms such as a "codename/sid" rolling identifier.
var numericVersionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// numericVersionFile returns the trimmed content of name in fsys when it is a
// concrete numeric version, or ok=false when the file is absent or non-numeric.
func numericVersionFile(fsys fs.FS, name string) (string, bool) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(string(b))
	if !numericVersionRe.MatchString(v) {
		return "", false
	}
	return v, true
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

// maxOSReleaseLineBytes caps one os-release line. bufio.Scanner's 64 KiB
// default is the wrong ceiling to hit silently here: a longer line ends the
// parse, and an ID below it goes unread — which both callers read as "this root
// declares no distro", the same answer a distroless image gives.
const maxOSReleaseLineBytes = 1 << 20

// parseOSRelease parses etc/os-release from fsys into its key/value pairs, with
// surrounding quotes stripped from values. Returns nil when the file is absent.
// A line past maxOSReleaseLineBytes ends the parse: the pairs read so far are
// still returned (partial detection beats none), and the truncation is logged
// rather than passed off as a complete read — neither caller has an error slot,
// and the path is fixed, so nothing is lost by reporting it here.
func parseOSRelease(fsys fs.FS) map[string]string {
	f, err := fsys.Open("etc/os-release")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxOSReleaseLineBytes)
	defer func() {
		if err := scanner.Err(); err != nil {
			slog.Warn("etc/os-release truncated; distro detection may be incomplete", "err", err)
		}
	}()
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
