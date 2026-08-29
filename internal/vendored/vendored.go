// ABOUTME: Detects C/C++ vendored libraries (third_party/, libs/, vendor/, …) and per-file MD5 fingerprints them.
// ABOUTME: Directory-shaped detection, not lockfile-shaped — sibling to ecosystem rather than an entry in its registry.
package vendored

import (
	"crypto/md5" //nolint:gosec // file fingerprint, not security
	"encoding/hex"
	"io"
	"io/fs"
	"log/slog"
	"path"
	"slices"
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

	// RelPath is the library directory relative to the scan root
	// (e.g. "third_party/zlib"), always slash-separated: it is an fs.FS path,
	// so it reads identically on every platform.
	RelPath string

	// PURL is the package-url for this hit. Convention:
	//   pkg:generic/<Name>?vendored_path=<RelPath-as-posix>
	// The qualifier disambiguates two vendored copies of the same upstream
	// library at different paths in one repository.
	PURL string
}

// Survey walks fsys looking for C/C++ vendored library directories.
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
//   - File read failures are logged at warn level via slog.Default() and the
//     file is skipped. The survey never aborts on a single bad file.
//   - WalkDir errors on subtrees are silently skipped (permission errors etc.).
//
// Taking an fs.FS rather than a path lets the caller pass the scan root it has
// already opened, and keeps this package off the host filesystem directly.
func Survey(fsys fs.FS) ([]Hit, hashes.Map) {
	digests := make(hashes.Map)

	// First pass: locate candidate library directories. We find them in a
	// dedicated walk because the hashing pass needs to descend into a single
	// candidate as a unit (file cap, nested-vendored detection) and mixing the
	// two passes makes the per-candidate state hard to reason about.
	candidates := findCandidates(fsys)

	hits := make([]Hit, 0, len(candidates))
	for _, libDir := range candidates {
		fileHashes, hasCpp := hashLib(fsys, libDir)
		if !hasCpp {
			continue
		}
		name := path.Base(libDir)
		purl := libPURL(name, libDir)
		hits = append(hits, Hit{Name: name, RelPath: libDir, PURL: purl})
		for _, h := range fileHashes {
			digests.Add(purl, h)
		}
	}

	slices.SortFunc(hits, func(a, b Hit) int { return strings.Compare(a.RelPath, b.RelPath) })
	return hits, digests
}

// findCandidates returns every library-dir candidate in fsys, as paths
// relative to its root.
// "Candidate" means: parent directory's basename is a vendored-family name.
// We collect the parent-named dir's *children* (each child is one library),
// not the parent itself — `third_party/zlib` is a candidate, `third_party` is
// not. Nested vendored containers under an already-claimed library are pruned
// to avoid duplicate matches.
func findCandidates(fsys fs.FS) []string {
	var candidates []string
	// claimedPrefixes lists subtree roots already covered by an outer candidate.
	// We use prefix matching with a trailing separator to avoid `lib` matching
	// `library/`.
	var claimedPrefixes []string

	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
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
		for _, claimed := range claimedPrefixes {
			if strings.HasPrefix(p+"/", claimed) {
				return fs.SkipDir
			}
		}
		// We are at directory `p`. Its children are candidates if `p` itself
		// has a vendored name. Don't recurse into hidden / build dirs inside
		// the wider tree though.
		if p != "." && fswalk.SkipDirForVendoredSearch(d.Name()) {
			return fs.SkipDir
		}
		if !fswalk.IsVendoredDir(d.Name()) {
			return nil
		}
		// Enumerate one level: each subdirectory is a library candidate.
		entries, rerr := fs.ReadDir(fsys, p)
		if rerr != nil {
			return nil
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			libDir := path.Join(p, e.Name())
			candidates = append(candidates, libDir)
			claimedPrefixes = append(claimedPrefixes, libDir+"/")
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
func hashLib(fsys fs.FS, libDir string) ([]hashes.Hash, bool) {
	var out []hashes.Hash
	hasCpp := false
	capped := false

	_ = fs.WalkDir(fsys, libDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if capped {
			return fs.SkipAll
		}
		if d.IsDir() {
			name := d.Name()
			if p == libDir {
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
		ext := strings.ToLower(path.Ext(p))
		if _, ok := cppFileExts[ext]; !ok {
			return nil
		}
		hasCpp = true
		rel := strings.TrimPrefix(p, libDir+"/")
		hex, herr := md5File(fsys, p)
		if herr != nil {
			slog.Warn("vendored md5 failed", "path", p, "err", herr)
			return nil
		}
		out = append(out, hashes.Hash{
			Algorithm: hashes.AlgMD5,
			Hex:       hex,
			Path:      rel,
		})
		if len(out) >= maxFilesPerLib {
			capped = true
			slog.Warn("vendored file cap reached", "cap", maxFilesPerLib, "lib", libDir)
			return fs.SkipAll
		}
		return nil
	})

	return out, hasCpp
}

func md5File(fsys fs.FS, p string) (string, error) {
	f, err := fsys.Open(p)
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
// relPath is already an fs.FS path, so the vendored_path qualifier carries
// posix separators and the PURL is stable across Windows and Unix scans of the
// same source tree.
func libPURL(name, relPath string) string {
	return "pkg:generic/" + name + "?vendored_path=" + relPath
}
