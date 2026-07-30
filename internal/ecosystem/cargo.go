// ABOUTME: Rust/Cargo ecosystem. Extracts SHA-256 hashes from Cargo.lock checksums.
// ABOUTME: Cargo only ships SHA-256, so these don't satisfy BSI's SHA-512 check but help non-BSI integrity verification.
package ecosystem

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargotoml"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var cargo = Ecosystem{
	Name:             "cargo",
	Filenames:        []string{"Cargo.toml", "Cargo.lock"},
	ScalibrPlugins:   []string{cargoauditable.Name, cargolock.Name, cargotoml.Name},
	InstalledPlugins: []string{cargoauditable.Name},
	HashParsers: []Parser{
		{
			Name:      "cargo",
			Filenames: []string{"Cargo.lock"},
			Parse:     parseCargoLock,
		},
	},
	GraphParsers: []GraphParser{
		{
			Name:      "cargo",
			Filenames: []string{"Cargo.lock"},
			Parse:     parseCargoLockGraph,
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

// parseCargoLockGraph mines Cargo.lock's per-package dependencies lists into
// purl edges. A dependency entry is "name", "name version", or
// "name version (source)"; bare names resolve only when the lock pins exactly
// one version of that name (cargo itself writes the version whenever it would
// be ambiguous), and entries naming nothing in the lock are dropped — the
// parser never invents a purl.
func parseCargoLockGraph(r io.Reader) (graph.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock cargoLockGraphFile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	versionsByName := make(map[string][]string)
	for _, p := range lock.Package {
		if p.Name != "" && p.Version != "" {
			versionsByName[p.Name] = append(versionsByName[p.Name], p.Version)
		}
	}

	out := make(graph.Map)
	for _, p := range lock.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		for _, dep := range p.Dependencies {
			name, version := splitCargoDep(dep)
			if version == "" {
				vs := versionsByName[name]
				if len(vs) != 1 {
					continue // unknown name, or ambiguous bare reference
				}
				version = vs[0]
			} else if !slices.Contains(versionsByName[name], version) {
				continue
			}
			out.Add(cargoPURL(p.Name, p.Version), cargoPURL(name, version))
		}
	}
	return out, nil
}

// cargoLockGraphFile is the Cargo.lock shape the graph parser reads — like
// cargoLockfile but with each package's dependencies list.
type cargoLockGraphFile struct {
	Package []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Dependencies []string `toml:"dependencies"`
	} `toml:"package"`
}

// splitCargoDep decomposes a lockfile dependency entry into its name and
// optional version, discarding a trailing "(source)" qualifier.
func splitCargoDep(dep string) (name, version string) {
	fields := strings.Fields(dep)
	if len(fields) == 0 {
		return "", ""
	}
	name = fields[0]
	if len(fields) > 1 && !strings.HasPrefix(fields[1], "(") {
		version = fields[1]
	}
	return name, version
}
