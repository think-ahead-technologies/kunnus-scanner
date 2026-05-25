// ABOUTME: Extracts SHA-256 hashes from Cargo.lock. Cargo only ships SHA-256,
// ABOUTME: so these don't satisfy BSI's SHA-512 check but help non-BSI integrity verification.
package hashes

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type cargoLockfile struct {
	Package []cargoPackage `toml:"package"`
}

type cargoPackage struct {
	Name     string `toml:"name"`
	Version  string `toml:"version"`
	Source   string `toml:"source"`
	Checksum string `toml:"checksum"`
}

func parseCargoLock(path string) (Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock cargoLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(Map)
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
		out["pkg:cargo/"+p.Name+"@"+p.Version] = Hash{
			Algorithm: AlgSHA256,
			Hex:       p.Checksum,
		}
	}
	return out, nil
}
