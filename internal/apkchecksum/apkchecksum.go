// ABOUTME: Recovers apk package pull-checksums (the Q1<base64-sha1> "C" field) that scalibr's apk extractor drops.
// ABOUTME: Container scans have no native hash source otherwise; this mines the installed-DB into a hashes.Map for the encoder.
package apkchecksum

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/os/apk/apkutil"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// Mine recovers the per-package integrity checksum apk records in its installed
// database but scalibr's os/apk extractor discards. scalibr copies only a subset
// of the DB record into each package (name, version, arch, …) and drops the "C"
// field — the Q1<base64-sha1> pull checksum — so a container SBOM carries no
// component hashes at all. This re-reads the DB referenced by each apk package's
// location, decodes that field to a SHA-1 digest, and returns a hashes.Map keyed
// by the package's purl so the SBOM encoder's hash injector attaches it.
//
// Keying by inv's own pkg.PURL() (rather than a reconstructed string) guarantees
// the key matches the component the converter emits, including the apk
// namespace and arch/distro/origin qualifiers.
//
// Per-DB read or parse failures are logged and skipped — a missing or unreadable
// copyright/DB must not fail the scan. Checksums that are not a valid Q1 SHA-1
// are dropped rather than mislabelled (apk has only ever used Q1 = SHA-1).
func Mine(inv inventory.Inventory, fsys fs.FS) hashes.Map {
	out := make(hashes.Map)
	// Parse each distinct DB once: many packages share one installed file.
	dbCache := make(map[string]map[string]string)
	for _, p := range inv.Packages {
		if p == nil || p.PURLType != purl.TypeApk || p.Name == "" || p.Location.PathOrEmpty() == "" {
			continue
		}
		dbPath := p.Location.PathOrEmpty()
		db, ok := dbCache[dbPath]
		if !ok {
			db = parseChecksums(fsys, dbPath)
			dbCache[dbPath] = db
		}
		hexSum, ok := decodeQ1(db[p.Name])
		if !ok {
			continue
		}
		u := p.PURL()
		if u == nil {
			continue
		}
		out.Add(u.String(), hashes.Hash{Algorithm: hashes.AlgSHA1, Hex: hexSum})
	}
	return out
}

// parseChecksums reads an apk installed database and returns package name → raw
// "C" checksum field. It reuses scalibr's apkutil scanner so the record parsing
// stays identical to the extractor that produced the inventory. Returns nil (a
// usable empty map) when the DB cannot be opened.
func parseChecksums(fsys fs.FS, path string) map[string]string {
	f, err := fsys.Open(path)
	if err != nil {
		slog.Debug("apk checksum: open db failed", "path", path, "err", err)
		return nil
	}
	defer func() { _ = f.Close() }()

	out := make(map[string]string)
	sc := apkutil.NewScanner(f)
	for sc.Scan() {
		rec := sc.Record()
		if name, c := rec["P"], rec["C"]; name != "" && c != "" {
			out[name] = c
		}
	}
	if err := sc.Err(); err != nil {
		slog.Warn("apk checksum: db parse error", "path", path, "err", err)
	}
	return out
}

// decodeQ1 turns an apk "C" checksum field into a lowercase hex SHA-1 digest.
// The field is "Q1" followed by the base64 of the 20-byte SHA-1; the "Q1" prefix
// is apk's only checksum form. Anything without that prefix, or that does not
// base64-decode to exactly a SHA-1 digest, is rejected (ok=false) so a malformed
// or future-format value is dropped rather than emitted under the wrong
// algorithm.
func decodeQ1(field string) (string, bool) {
	const prefix = "Q1"
	if !strings.HasPrefix(field, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(field[len(prefix):])
	if err != nil || len(raw) != sha1.Size {
		return "", false
	}
	return hex.EncodeToString(raw), true
}
