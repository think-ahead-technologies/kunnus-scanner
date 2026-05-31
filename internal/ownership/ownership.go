// ABOUTME: Reads the dpkg and apk package databases to map which files an OS package manager owns.
// ABOUTME: The binary-classifier overlap suppression uses this to drop pkg:generic twins of packaged binaries by path.
package ownership

import (
	"bufio"
	"bytes"
	"io/fs"
	"path"
	"strings"
)

// Set is the set of root-relative file paths (no leading slash, matching
// scalibr's location convention) owned by an OS package manager.
type Set map[string]struct{}

// Owns reports whether loc is recorded as owned by an OS package. A nil Set owns
// nothing.
func (s Set) Owns(loc string) bool {
	if s == nil {
		return false
	}
	_, ok := s[strings.TrimPrefix(loc, "/")]
	return ok
}

// Scan reads the dpkg and apk databases on fsys and returns every file path they
// record as owned. Absent databases are skipped, so a root with neither yields
// an empty Set rather than an error — ownership data refines SBOM dedup and is
// never required for a scan to succeed.
func Scan(fsys fs.FS) Set {
	s := Set{}
	scanDpkg(fsys, s)
	scanApk(fsys, s)
	return s
}

// scanDpkg reads var/lib/dpkg/info/*.list, each line of which is an absolute
// path the package owns. The package name (the file stem) is irrelevant here —
// suppression only needs to know that *some* package owns the path.
func scanDpkg(fsys fs.FS, s Set) {
	const dir = "var/lib/dpkg/info"
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".list") {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if p := strings.TrimPrefix(strings.TrimSpace(sc.Text()), "/"); p != "" {
				s[p] = struct{}{}
			}
		}
	}
}

// scanApk reads lib/apk/db/installed, whose records list owned files as an "F:"
// directory line followed by "R:" file lines relative to it.
func scanApk(fsys fs.FS, s Set) {
	data, err := fs.ReadFile(fsys, "lib/apk/db/installed")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	dir := ""
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'F': // directory, relative to root with no leading slash
			dir = line[2:]
		case 'R': // file name within the current directory
			name := line[2:]
			if dir != "" {
				s[dir+"/"+name] = struct{}{}
			} else {
				s[name] = struct{}{}
			}
		}
	}
}
