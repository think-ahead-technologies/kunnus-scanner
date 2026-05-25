// ABOUTME: Extracts SHA-256 hashes from go.sum (Go module checksum file).
// ABOUTME: Keeps zip-hashes (h1:<base64>), skips /go.mod-suffixed lines (manifest-only hashes).
package hashes

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func parseGoSum(path string) (Map, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	out := make(Map)
	scanner := bufio.NewScanner(f)
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
		if err != nil || len(raw) != 32 {
			continue
		}
		// Scalibr's Go PURLs drop the conventional "v" prefix from
		// semver versions; match that to keep our PURL keys join-able
		// against scan output.
		out["pkg:golang/"+module+"@"+strings.TrimPrefix(version, "v")] = Hash{
			Algorithm: AlgSHA256,
			Hex:       hex.EncodeToString(raw),
		}
	}
	return out, scanner.Err()
}
