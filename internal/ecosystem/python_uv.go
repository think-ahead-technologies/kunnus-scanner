// ABOUTME: Astral uv.lock parser — TOML [[package]] with separate sdist={hash} and wheels=[{hash}] fields.
// ABOUTME: Virtual packages (source = "."} have neither and produce no entries.
package ecosystem

import (
	"fmt"
	"io"

	"github.com/BurntSushi/toml"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

type uvLockfile struct {
	Packages []uvPackage `toml:"package"`
}

type uvPackage struct {
	Name    string           `toml:"name"`
	Version string           `toml:"version"`
	SDist   uvDistribution   `toml:"sdist"`
	Wheels  []uvDistribution `toml:"wheels"`
}

type uvDistribution struct {
	URL  string `toml:"url"`
	Hash string `toml:"hash"`
}

func parseUvLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock uvLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, p := range lock.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := pypiPURL(p.Name, p.Version)
		if p.SDist.Hash != "" {
			addPyPIFileHash(out, purl, p.SDist.Hash)
		}
		for _, w := range p.Wheels {
			if w.Hash != "" {
				addPyPIFileHash(out, purl, w.Hash)
			}
		}
	}
	return out, nil
}
