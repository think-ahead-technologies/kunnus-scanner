// ABOUTME: Recovers chisel package digests (the manifest's per-package sha256 field) that scalibr's chisel extractor drops.
// ABOUTME: Chiselled images have no other native hash source; this mines the manifest into a hashes.Map for the encoder.
package chiselchecksum

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/klauspost/compress/zstd"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// Mine recovers the per-package sha256 digest chisel records in its manifest
// but scalibr's os/chisel extractor discards (its dpkg-shaped metadata has no
// hash field). This re-reads the manifest referenced by each chisel package's
// location, takes the digest from that package's kind=package record, and
// returns a hashes.Map keyed by the package's purl so the SBOM encoder's hash
// injector attaches it. Deb packages from other sources (a dpkg status DB) are
// left alone: only packages whose location is a chisel manifest are chisel's
// to hash.
//
// Keying by inv's own pkg.PURL() (rather than a reconstructed string)
// guarantees the key matches the component the converter emits, including the
// namespace and arch/distro qualifiers.
//
// Per-manifest read or parse failures are logged and skipped — a missing or
// unreadable manifest must not fail the scan. Digests that are not lowercase
// hex SHA-256 are dropped rather than mislabelled.
func Mine(inv inventory.Inventory, fsys fs.FS) hashes.Map {
	out := make(hashes.Map)
	// Parse each distinct manifest once: many packages share one file.
	manifestCache := make(map[string]map[string]string)
	for _, p := range inv.Packages {
		if p == nil || p.PURLType != purl.TypeDebian || p.Name == "" {
			continue
		}
		manifestPath := p.Location.PathOrEmpty()
		if !strings.HasSuffix(manifestPath, "chisel/manifest.wall") {
			continue
		}
		digests, ok := manifestCache[manifestPath]
		if !ok {
			digests = parseDigests(fsys, manifestPath)
			manifestCache[manifestPath] = digests
		}
		digest := digests[p.Name]
		if !validSHA256(digest) {
			continue
		}
		u := p.PURL()
		if u == nil {
			continue
		}
		out.Add(u.String(), hashes.Hash{Algorithm: hashes.AlgSHA256, Hex: digest})
	}
	return out
}

// parseDigests reads a chisel manifest — a zstd-compressed jsonwall, one JSON
// object per line — and returns package name → sha256 from its kind=package
// records. Returns nil (a usable empty map) when the manifest cannot be opened
// or is not zstd.
func parseDigests(fsys fs.FS, path string) map[string]string {
	data, err := fs.ReadFile(fsys, path)
	if err != nil {
		slog.Debug("chisel checksum: read manifest failed", "path", path, "err", err)
		return nil
	}
	r, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		slog.Warn("chisel checksum: manifest is not zstd", "path", path, "err", err)
		return nil
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		slog.Warn("chisel checksum: manifest decompress error", "path", path, "err", err)
		return nil
	}

	out := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec struct {
			Kind   string `json:"kind"`
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Kind == "package" && rec.Name != "" && rec.SHA256 != "" {
			out[rec.Name] = rec.SHA256
		}
	}
	return out
}

// validSHA256 reports whether s is a lowercase hex SHA-256 digest — the only
// form chisel manifests carry. Anything else is rejected so a malformed or
// future-format value is dropped rather than emitted under the wrong algorithm.
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
