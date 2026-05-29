// ABOUTME: Go ecosystem. Extracts SHA-256 hashes from go.sum (zip hashes only; /go.mod lines skipped).
// ABOUTME: Go's h1: prefix carries the base64-encoded SHA-256 of the module zip.
package ecosystem

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var golang = Ecosystem{
	Name:             "go",
	Filenames:        []string{"go.mod", "go.sum"},
	ScalibrPlugins:   []string{gomod.Name, gobinary.Name},
	InstalledPlugins: []string{gobinary.Name},
	HashParsers: []Parser{
		{
			Name:      "go",
			Filenames: []string{"go.sum"},
			Parse:     parseGoSum,
		},
	},
}

func parseGoSum(r io.Reader) (hashes.Map, error) {
	out := make(hashes.Map)
	scanner := bufio.NewScanner(r)
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
