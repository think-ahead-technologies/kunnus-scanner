// ABOUTME: ESP-IDF ecosystem (Espressif component manager). Mines SHA-256 component hashes from dependencies.lock.
// ABOUTME: Detection + hash extraction here; components come from the kunnus-native internal/espidf extractor the mode wires in (no scalibr plugin exists).
package ecosystem

import (
	"encoding/hex"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// espidf detects ESP-IDF (Espressif IoT Development Framework) projects by
// their component-manager files: idf_component.yml declares dependencies,
// dependencies.lock records the resolved versions plus a SHA-256
// component_hash per registry component. ESP-IDF has no scalibr extractor, so
// this entry sets NativeExtractor (mode/repo appends internal/espidf.New()) and
// carries a HashParser that mines the lockfile digests into the shared
// hashes.Map path — the same plumbing every other lockfile hash rides.
var espidf = Ecosystem{
	Name:            "espidf",
	Filenames:       []string{"idf_component.yml", "dependencies.lock"},
	NativeExtractor: true,
	HashParsers: []Parser{
		{
			Name:      "espidf",
			Filenames: []string{"dependencies.lock"},
			Parse:     parseESPIDFLock,
		},
	},
}

// espidfLockfile covers the dependencies.lock schema written by the IDF
// component manager: a dependencies map keyed by "namespace/name" (or the bare
// "idf" pseudo-component), each entry carrying the resolved version and, for
// registry components, a SHA-256 component_hash. The top-level version field is
// the lockfile schema version, not a package version, and is ignored.
type espidfLockfile struct {
	Dependencies map[string]struct {
		ComponentHash string `yaml:"component_hash"`
		Version       string `yaml:"version"`
	} `yaml:"dependencies"`
}

// parseESPIDFLock mines dependencies.lock for per-component SHA-256 digests,
// keyed by the same pkg:generic purls internal/espidf emits so the SBOM
// injector binds them without translation. Components without a hash (the idf
// framework itself, git/local sources) contribute no entry.
func parseESPIDFLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock espidfLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for name, dep := range lock.Dependencies {
		if name == "" || dep.Version == "" || !isSHA256Hex(dep.ComponentHash) {
			continue
		}
		out.Add("pkg:generic/"+name+"@"+dep.Version, hashes.Hash{
			Algorithm: hashes.AlgSHA256,
			Hex:       dep.ComponentHash,
		})
	}
	return out, nil
}

// isSHA256Hex reports whether s is a well-formed 64-char hex SHA-256 digest.
// Anything else (empty, truncated, non-hex) is dropped rather than emitted as a
// junk value.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
