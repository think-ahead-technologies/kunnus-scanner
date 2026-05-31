// ABOUTME: Reads the dpkg, apk and rpm package databases to map which files an OS package manager owns.
// ABOUTME: The binary-classifier overlap suppression uses this to drop pkg:generic twins of packaged binaries by path.
package ownership

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path"
	"strings"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	_ "modernc.org/sqlite" // sqlite driver for reading rpmdb.sqlite databases
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

// Scan reads the dpkg, apk and rpm databases on fsys and returns every file path
// they record as owned. Absent databases are skipped, so a root with none yields
// an empty Set rather than an error — ownership data refines SBOM dedup and is
// never required for a scan to succeed.
func Scan(fsys fs.FS) Set {
	s := Set{}
	scanDpkg(fsys, s)
	scanApk(fsys, s)
	scanRpm(fsys, s)
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

// rpmDBPaths are the rpm database locations across rpm storage backends, in the
// order Scan probes them. The format (sqlite3 / ndb / BerkeleyDB) is detected
// from the file contents, not its name.
var rpmDBPaths = []string{
	"var/lib/rpm/rpmdb.sqlite",          // sqlite3 — Fedora, Amazon Linux, modern
	"var/lib/rpm/Packages",              // BerkeleyDB — older
	"var/lib/rpm/Packages.db",           // ndb — rare
	"usr/lib/sysimage/rpm/rpmdb.sqlite", // relocated DB on some distros
	"usr/lib/sysimage/rpm/Packages.db",  //
}

// scanRpm reads the rpm database and records every file each installed package
// owns. The go-rpmdb opener needs a real filesystem path (its sqlite/BerkeleyDB
// drivers open by path), so the in-FS database is materialised to a temp file
// first. Any failure — no database, an unreadable or corrupt one — yields no
// entries rather than an error: ownership is advisory.
func scanRpm(fsys fs.FS, s Set) {
	data, ok := readFirst(fsys, rpmDBPaths)
	if !ok {
		return
	}
	tmp, err := os.CreateTemp("", "kunnus-rpmdb-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr != nil || cerr != nil {
		return
	}

	db, err := rpmdb.Open(tmp.Name())
	if err != nil {
		return
	}
	defer db.Close()
	pkgs, err := db.ListPackages()
	if err != nil {
		return
	}
	for _, p := range pkgs {
		files, err := p.InstalledFileNames()
		if err != nil {
			continue
		}
		for _, f := range files {
			if f = strings.TrimPrefix(f, "/"); f != "" {
				s[f] = struct{}{}
			}
		}
	}
}

// readFirst returns the contents of the first of paths that exists on fsys.
func readFirst(fsys fs.FS, paths []string) ([]byte, bool) {
	for _, p := range paths {
		if data, err := fs.ReadFile(fsys, p); err == nil {
			return data, true
		}
	}
	return nil, false
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
