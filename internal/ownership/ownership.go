// ABOUTME: Reads the dpkg, apk, rpm and chisel package databases to map which files an OS package manager owns.
// ABOUTME: The binary-classifier overlap suppression uses this to drop pkg:generic twins of packaged binaries by path.
package ownership

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"strings"

	rpmdb "github.com/erikvarga/go-rpmdb/pkg"
	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite" // sqlite driver for reading rpmdb.sqlite databases
)

// maxRecordBytes caps one line of a package database. bufio.Scanner's 64 KiB
// default is too small a ceiling to fail silently against: a longer line ends
// the scan, every path after it goes unrecorded, and the suppression stage
// reads that as "no package owns this file". Real records are short — a path,
// or one jsonwall object — so 1 MiB is headroom, not a target.
const maxRecordBytes = 1 << 20

// newRecordScanner returns a line scanner over data with the record cap in
// place. Shared by the three database parsers, whose token-size needs are the
// same and whose failure mode when it is missed is the same.
func newRecordScanner(data []byte) *bufio.Scanner {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxRecordBytes)
	return sc
}

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

// Scan reads the dpkg, apk, rpm and chisel databases on fsys and returns every
// file path they record as owned. Absent databases are skipped, so a root with
// none yields an empty Set rather than an error — ownership data refines SBOM
// dedup and is never required for a scan to succeed.
func Scan(fsys fs.FS) Set {
	s := Set{}
	scanDpkg(fsys, s)
	scanApk(fsys, s)
	scanRpm(fsys, s)
	scanChisel(fsys, s)
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
		name := path.Join(dir, e.Name())
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			continue
		}
		paths, err := parseDpkgList(data)
		if err != nil {
			slog.Warn("dpkg file list truncated; some owned paths will be missing", "path", name, "err", err)
		}
		for _, p := range paths {
			s[p] = struct{}{}
		}
	}
}

// parseDpkgList reads one dpkg *.list file — each line an absolute path the
// package owns — and returns those paths root-relative (leading slash stripped),
// skipping blank lines. Split from the filesystem walk so the line parsing is
// exercisable on raw bytes alone.
//
// A line past maxRecordBytes ends the scan: the paths read up to that point are
// returned along with the error, because partial ownership data suppresses more
// duplicate components than none.
func parseDpkgList(data []byte) ([]string, error) {
	var out []string
	sc := newRecordScanner(data)
	for sc.Scan() {
		if p := strings.TrimPrefix(strings.TrimSpace(sc.Text()), "/"); p != "" {
			out = append(out, p)
		}
	}
	return out, sc.Err()
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
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr != nil || cerr != nil {
		return
	}

	db, err := rpmdb.Open(tmp.Name())
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
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

// scanChisel reads var/lib/chisel/manifest.wall, the package record of a
// chiselled Ubuntu root (which has no dpkg status or .list files). The manifest
// is a zstd-compressed jsonwall whose kind=path records each name a path a
// package slice installed. Any failure — no manifest, not zstd, malformed —
// yields no entries rather than an error: ownership is advisory.
func scanChisel(fsys fs.FS, s Set) {
	data, err := fs.ReadFile(fsys, "var/lib/chisel/manifest.wall")
	if err != nil {
		return
	}
	r, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return
	}
	paths, err := parseChiselManifest(raw)
	if err != nil {
		slog.Warn("chisel manifest truncated; some owned paths will be missing", "err", err)
	}
	for _, p := range paths {
		s[p] = struct{}{}
	}
}

// parseChiselManifest reads a decompressed chisel jsonwall — one JSON object
// per line — and returns the path of every kind=path record, root-relative
// (leading slash stripped). Other record kinds (package, slice, content) and
// unparseable lines are skipped; content records duplicate the path records
// slice-by-slice, so reading them too would only add duplicates. Directory
// records keep their trailing slash and are inert in Owns, which matches file
// locations. Split from the filesystem read so the line parsing is exercisable
// on raw bytes alone.
//
// Truncation is reported the same way as parseDpkgList: partial records plus
// the error.
func parseChiselManifest(data []byte) ([]string, error) {
	var out []string
	sc := newRecordScanner(data)
	for sc.Scan() {
		var rec struct {
			Kind string `json:"kind"`
			Path string `json:"path"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Kind != "path" {
			continue
		}
		if p := strings.TrimPrefix(rec.Path, "/"); p != "" {
			out = append(out, p)
		}
	}
	return out, sc.Err()
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
	paths, err := parseApkInstalled(data)
	if err != nil {
		slog.Warn("apk installed database truncated; some owned paths will be missing", "err", err)
	}
	for _, p := range paths {
		s[p] = struct{}{}
	}
}

// parseApkInstalled reads an apk installed database and returns the owned file
// paths. Records list files as an "F:" directory line followed by "R:" file
// lines relative to it. Split from the filesystem read so the record parsing is
// exercisable on raw bytes alone.
//
// Truncation is reported the same way as parseDpkgList: partial records plus
// the error.
func parseApkInstalled(data []byte) ([]string, error) {
	var out []string
	sc := newRecordScanner(data)
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
				out = append(out, dir+"/"+name)
			} else {
				out = append(out, name)
			}
		}
	}
	return out, sc.Err()
}
