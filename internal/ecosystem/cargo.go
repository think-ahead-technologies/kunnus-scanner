// ABOUTME: Rust/Cargo ecosystem. Extracts SHA-256 hashes from Cargo.lock checksums.
// ABOUTME: Cargo only ships SHA-256, so these don't satisfy BSI's SHA-512 check but help non-BSI integrity verification.
package ecosystem

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargotoml"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var cargo = Ecosystem{
	Name:           "cargo",
	Filenames:      []string{"Cargo.toml", "Cargo.lock"},
	ScalibrPlugins: []string{cargoauditable.Name, cargolock.Name, cargotoml.Name},
	HashParsers: []Parser{
		{
			Name:      "cargo",
			Filenames: []string{"Cargo.lock"},
			Parse:     parseCargoLock,
		},
	},
}

type cargoLockfile struct {
	Package []cargoPackage `toml:"package"`
}

type cargoPackage struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Source   string `toml:"source"`
	Checksum string `toml:"checksum"`
}

func parseCargoLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock cargoLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, p := range lock.Package {
		if p.Name == "" || p.Version == "" || p.Checksum == "" {
			continue
		}
		// Cargo writes lowercase hex SHA-256: 64 chars. Anything else is
		// either malformed or a future format change — skip rather than
		// emit junk.
		if len(p.Checksum) != 64 {
			continue
		}
		if _, err := hex.DecodeString(p.Checksum); err != nil {
			continue
		}
		out.Add(cargoPURL(p.Name, p.Version), hashes.Hash{
			Algorithm: hashes.AlgSHA256,
			Hex:       p.Checksum,
		})
	}
	return out, nil
}

func cargoPURL(name, version string) string {
	return "pkg:cargo/" + name + "@" + version
}
