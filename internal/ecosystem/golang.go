// ABOUTME: Go ecosystem. Extracts SHA-256 hashes from go.sum (zip hashes only; /go.mod lines skipped).
// ABOUTME: Go's h1: prefix carries the base64-encoded SHA-256 of the module zip.
package ecosystem

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"io/fs"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/vendormodules"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// GoVendorManifest is the path, relative to a scan root, of the manifest a
// vendored Go module tree carries. scalibr's go/vendormodules extractor keys on
// exactly this name.
const GoVendorManifest = "vendor/modules.txt"

// vendor/modules.txt is not a detection marker: every walk skips directories
// named "vendor" (see fswalk), so the survey never reaches it. A tree with a
// vendor directory always has the go.mod that produced it, which flags the
// ecosystem — and HasGoVendorTree below is what makes the file reachable by the
// scan itself.
var golang = Ecosystem{
	Name:             "go",
	Filenames:        []string{"go.mod", "go.sum"},
	ScalibrPlugins:   []string{gomod.Name, gobinary.Name, vendormodules.Name},
	InstalledPlugins: []string{gobinary.Name},
	HashParsers: []Parser{
		{
			Name:      "go",
			Filenames: []string{"go.sum"},
			Parse:     parseGoSum,
		},
	},
}

// HasGoVendorTree reports whether the scan root holds a vendored Go module tree.
//
// It exists because the two halves of "scan a Go vendor tree" disagree: fswalk
// skips every directory named "vendor" (a blanket rule that keeps npm, composer
// and bundler install trees out of the walk), while go/vendormodules can only
// report the vendored module set if the scan reaches vendor/modules.txt. Rather
// than un-skip vendor for every repository, mode/repo asks this and carves out
// the exception only where the manifest is actually there — a Go vendor tree,
// which holds dependency source and licences but no foreign manifests, so
// walking it costs nothing but the modules it is meant to surface.
//
// One stat, not a walk: DirsToSkip holds absolute paths, so only the root-level
// vendor directory was ever skipped.
func HasGoVendorTree(fsys fs.FS) bool {
	info, err := fs.Stat(fsys, GoVendorManifest)
	return err == nil && !info.IsDir()
}

func parseGoSum(r io.Reader) (hashes.Map, error) {
	out := make(hashes.Map)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Each line is `<module> <version>[/go.mod] h1:<base64>`. Three
		// whitespace-separated fields.
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		module, version, h1 := fields[0], fields[1], fields[2]

		// Skip module-manifest hashes (only the zip hash is the deployable
		// artefact hash per Go's checksum scheme).
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		// h1: prefix is the only Go module hash algorithm in current use.
		// It carries the base64-encoded SHA-256 of the module zip.
		const prefix = "h1:"
		if !strings.HasPrefix(h1, prefix) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(h1[len(prefix):])
		if err != nil || len(raw) != sha256.Size {
			continue
		}
		out.Add(golangPURL(module, version), hashes.Hash{
			Algorithm: hashes.AlgSHA256,
			Hex:       hex.EncodeToString(raw),
		})
	}
	return out, scanner.Err()
}

// golangPURL builds the PURL form scalibr emits for Go modules: the conventional
// "v" prefix is dropped from semver versions to match scalibr's normalisation.
func golangPURL(module, version string) string {
	return "pkg:golang/" + module + "@" + strings.TrimPrefix(version, "v")
}
