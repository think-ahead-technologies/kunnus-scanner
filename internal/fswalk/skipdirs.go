// ABOUTME: Single source of truth for directory names that filesystem walks skip.
// ABOUTME: Imported by detect, hashes, and any other package that traverses scan roots.
package fswalk

import "path/filepath"

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
