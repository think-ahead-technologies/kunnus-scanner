// ABOUTME: Detects C/C++ vendored libraries (third_party/, libs/, vendor/, …) and per-file MD5 fingerprints them.
// ABOUTME: Directory-shaped detection, not lockfile-shaped — sibling to ecosystem rather than an entry in its registry.
package vendored

import (
	"crypto/md5" //nolint:gosec // file fingerprint, not security
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/fswalk"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// cppFileExts is the extension set considered C/C++ source. Lifted from v1.
var cppFileExts = map[string]struct{}{
	".c":   {},
	".cc":  {},
	".cpp": {},
	".h":   {},
	".hh":  {},
	".hpp": {},
}

// maxFilesPerLib caps hashes per detected library. Matches v1's
// maxDetermineVersionFiles — a real-world OpenSSL vendor is ~700 files, so
// 10000 leaves headroom while protecting against pathological trees.
const maxFilesPerLib = 10000

// Hit describes one vendored library directory the survey found.
// mode/repo translates this into a bom.ExtraComponent; this package stays
// free of bom/mode imports so the package dependency graph remains a DAG.
type Hit struct {
	// Name is the basename of the vendored library directory (e.g. "zlib").
	Name string

	// RelPath is the library directory relative to scanRoot (e.g. "third_party/zlib").
	// Uses the OS path separator — callers that need posix form must convert.
	RelPath string

	// PURL is the package-url for this hit. Convention:
	//   pkg:generic/<Name>?vendored_path=<RelPath-as-posix>
	// The qualifier disambiguates two vendored copies of the same upstream
	// library at different paths in one repository.
	PURL string
}

// Survey walks scanRoot looking for C/C++ vendored library directories.
// For each candidate it emits one Hit plus an entry in the returned
// hashes.Map (keyed by the hit's PURL) containing one Hash per source file.
//
// Discovery rules:
//   - A directory matches if its basename is a fswalk vendored-family name
//     AND it contains at least one C/C++ source file (transitively, before
//     nested vendored). The C/C++ check is what lets the survey run
//     unconditionally without producing noise for Go's vendor/, Python's
//     external/, etc.
//   - The walker descends into vendored-family names even though
//     fswalk.SkipDir blanket-skips "vendor". It still skips .git,
//     node_modules, etc. inside.
//   - Nested vendored directories collapse into the outer match — only the
//     outermost candidate produces a hit (otherwise layered vendor trees emit
//     duplicate components).
//
// Errors:
//   - File read failures are logged to logOut (nil = silent) and the file is
//     skipped. The survey never aborts on a single bad file.
//   - WalkDir errors on subtrees are silently skipped (permission errors etc.).
func Survey(scanRoot string, logOut io.Writer) ([]Hit, hashes.Map) {
	digests := make(hashes.Map)

	abs, err := filepath.Abs(scanRoot)
	if err != nil {
		return nil, digests
	}

	// First pass: locate candidate library directories. We find them in a
	// dedicated walk because the hashing pass needs to descend into a single
	// candidate as a unit (file cap, nested-vendored detection) and mixing the
	// two passes makes the per-candidate state hard to reason about.
	candidates := findCandidates(abs)

	hits := make([]Hit, 0, len(candidates))
	for _, libDir := range candidates {
		fileHashes, hasCpp := hashLib(libDir, logOut)
		if !hasCpp {
			continue
		}
		rel, err := filepath.Rel(abs, libDir)
		if err != nil {
			continue
		}
		name := filepath.Base(libDir)
		purl := libPURL(name, rel)
		hits = append(hits, Hit{Name: name, RelPath: rel, PURL: purl})
		for _, h := range fileHashes {
			digests.Add(purl, h)
		}
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].RelPath < hits[j].RelPath })
	return hits, digests
}

// findCandidates returns every library-dir candidate under abs.
// "Candidate" means: parent directory's basename is a vendored-family name.
// We collect the parent-named dir's *children* (each child is one library),
// not the parent itself — `third_party/zlib` is a candidate, `third_party` is
// not. Nested vendored containers under an already-claimed library are pruned
// to avoid duplicate matches.
func findCandidates(abs string) []string {
	var candidates []string
	// claimedPrefixes lists subtree roots already covered by an outer candidate.
	// We use prefix matching with a trailing separator to avoid `lib` matching
	// `library/`.
	var claimedPrefixes []string

	_ = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		// Inside a previously-claimed library subtree → never descend further.
		for _, p := range claimedPrefixes {
			if strings.HasPrefix(path+string(filepath.Separator), p) {
				return fs.SkipDir
			}
		}
		// We are at directory `path`. Its children are candidates if `path`
		// itself has a vendored name. Don't recurse into hidden / build dirs
		// inside the wider tree though.
		if path != abs && fswalk.SkipDirForVendoredSearch(d.Name()) {
			return fs.SkipDir
		}
		if !fswalk.IsVendoredDir(d.Name()) {
			return nil
		}
		// Enumerate one level: each subdirectory is a library candidate.
		entries, rerr := os.ReadDir(path)
		if rerr != nil {
			return nil
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			libDir := filepath.Join(path, e.Name())
			candidates = append(candidates, libDir)
			claimedPrefixes = append(claimedPrefixes, libDir+string(filepath.Separator))
		}
		// We've claimed this entire vendored container — don't descend further
		// from here; child libraries are scanned via hashLib.
		return fs.SkipDir
	})

	return candidates
}

// hashLib walks libDir and MD5-hashes every C/C++ source file.
// Returns the hash slice plus a bool indicating whether at least one C/C++
// file was found — callers use it to drop directories that match the name
// heuristic but contain only Go/Python/JS (the unconditional-discovery rule).
//
// .git subtrees and nested vendored-name containers inside the library are
// skipped to avoid double-counting.
func hashLib(libDir string, logOut io.Writer) ([]hashes.Hash, bool) {
	var out []hashes.Hash
	hasCpp := false
	capped := false

	_ = filepath.WalkDir(libDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if capped {
			return filepath.SkipAll
		}
		if d.IsDir() {
			name := d.Name()
			if path == libDir {
				return nil
			}
			// Skip nested vendored containers — their contents would be a second
			// Hit if we ever ran the survey rooted at this libDir.
			if fswalk.IsVendoredDir(name) {
				return fs.SkipDir
			}
			if fswalk.SkipDirForVendoredSearch(name) {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := cppFileExts[ext]; !ok {
			return nil
		}
		hasCpp = true
		rel, rerr := filepath.Rel(libDir, path)
		if rerr != nil {
			return nil
		}
		hex, herr := md5File(path)
		if herr != nil {
			if logOut != nil {
				_, _ = fmt.Fprintf(logOut, "vendored: hash failed on %s: %v\n", path, herr)
			}
			return nil
		}
		out = append(out, hashes.Hash{
			Algorithm: hashes.AlgMD5,
			Hex:       hex,
			Path:      filepath.ToSlash(rel),
		})
		if len(out) >= maxFilesPerLib {
			capped = true
			if logOut != nil {
				_, _ = fmt.Fprintf(logOut, "vendored: file cap (%d) reached in %s\n", maxFilesPerLib, libDir)
			}
			return filepath.SkipAll
		}
		return nil
	})

	return out, hasCpp
}

func md5File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := md5.New() //nolint:gosec
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// libPURL builds the canonical PURL for one vendored library hit.
// The vendored_path qualifier uses posix separators so the PURL is stable
// across Windows and Unix scans of the same source tree.
func libPURL(name, relPath string) string {
	return "pkg:generic/" + name + "?vendored_path=" + filepath.ToSlash(relPath)
}
