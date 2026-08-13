// ABOUTME: pylock.toml (PEP 751) parser — TOML [[packages]] with sdist={hashes} and wheels=[{hashes}] tables.
// ABOUTME: PEP 751 keys each digest by algorithm name, so only the sha256 entry is read; path and VCS packages have none.
package ecosystem

import (
	"fmt"
	"io"

	"github.com/BurntSushi/toml"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

type pylockFile struct {
	Packages []pylockPackage `toml:"packages"`
}

type pylockPackage struct {
	Name    string               `toml:"name"`
	Version string               `toml:"version"`
	SDist   pylockDistribution   `toml:"sdist"`
	Wheels  []pylockDistribution `toml:"wheels"`
}

// pylockDistribution is one published artifact. PEP 751 names its digests by
// algorithm ("hashes.sha256 = ..."), unlike the sha256: SRI string the other
// five PyPI formats carry, so the map is decoded and looked up by key.
type pylockDistribution struct {
	URL    string            `toml:"url"`
	Hashes map[string]string `toml:"hashes"`
}

func parsePylock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock pylockFile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, p := range lock.Packages {
		// A directory or VCS package has no version and no published
		// distribution; without a version there is no purl to key by.
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := pypiPURL(p.Name, p.Version)
		addPylockDistHash(out, purl, p.SDist)
		for _, w := range p.Wheels {
			addPylockDistHash(out, purl, w)
		}
	}
	return out, nil
}

// addPylockDistHash records dist's sha256 digest under purl, reusing the shared
// SRI decoder (which validates length and hex) by restoring the prefix PEP 751
// leaves out.
func addPylockDistHash(out hashes.Map, purl string, dist pylockDistribution) {
	if digest := dist.Hashes["sha256"]; digest != "" {
		addPyPIFileHash(out, purl, "sha256:"+digest)
	}
}
