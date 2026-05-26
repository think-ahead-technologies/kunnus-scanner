// ABOUTME: Single source of truth for directory names that filesystem walks skip.
// ABOUTME: Imported by detect, hashes, and any other package that traverses scan roots.
package fswalk

import (
	"path/filepath"
	"strings"
)

// skipDirNames lists the directory names that detection, hash extraction, and
// scan-plan construction all want to skip. Add a name here, get it skipped
// everywhere — that's the whole point of this package.
var skipDirNames = []string{
	".git", ".hg", ".svn",
	"node_modules", "bower_components",
	"vendor", "target", "dist", "build", "out",
	".venv", "venv", "__pycache__",
	".gradle", ".idea", ".vscode",
}

// vendoredDirNames lists the (case-insensitive) basenames that mark a
// directory as a vendored-libraries container. The vendored survey descends
// into these even when SkipDir blanket-skips "vendor", so callers that need
// to find vendored libs use SkipDirForVendoredSearch instead of SkipDir.
var vendoredDirNames = []string{
	"3rdparty", "dep", "deps", "thirdparty", "third-party", "third_party",
	"libs", "external", "externals", "vendor", "vendored",
}

// SkipDir reports whether the given directory name should be skipped during a
// filesystem walk. Match is exact (case-sensitive), matching scalibr behaviour.
func SkipDir(name string) bool {
	for _, n := range skipDirNames {
		if name == n {
			return true
		}
	}
	return false
}

// IsVendoredDir reports whether name (case-insensitive) is a known
// vendored-libraries container basename (third_party, libs, vendor, …).
func IsVendoredDir(name string) bool {
	lower := strings.ToLower(name)
	for _, n := range vendoredDirNames {
		if lower == n {
			return true
		}
	}
	return false
}

// SkipDirForVendoredSearch reports whether a walk that is *looking for*
// vendored libraries should skip directory name. It is SkipDir minus the
// vendored-family names: the search must descend into vendor/ et al., but
// still skips .git, node_modules, build/, etc.
//
// Use SkipDir for normal walks; use this only when you specifically need to
// find vendored libraries inside vendor-named containers.
func SkipDirForVendoredSearch(name string) bool {
	if IsVendoredDir(name) {
		return false
	}
	return SkipDir(name)
}

// AbsoluteSkipPaths returns scanRoot-joined absolute paths for every skip name.
// scalibr's ScanConfig.DirsToSkip wants absolute paths rooted under a scan
// root, not bare names.
func AbsoluteSkipPaths(scanRoot string) []string {
	out := make([]string, 0, len(skipDirNames))
	for _, n := range skipDirNames {
		out = append(out, filepath.Join(scanRoot, n))
	}
	return out
}
