// ABOUTME: C/C++ ecosystem (Conan). Extracts recipe revisions from conan.lock (v0.5+).
// ABOUTME: rrev is MD5 (32 hex) by default or SHA-1 (40 hex) under scm revision mode; both weaker than BSI's SHA-512 ask but match what Conan ships.
package ecosystem

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var cpp = Ecosystem{
	Name:           "cpp",
	Filenames:      []string{"conan.lock", "conanfile.txt", "conanfile.py"},
	ScalibrPlugins: []string{conanlock.Name},
	HashParsers: []Parser{
		{
			Name:      "conan",
			Filenames: []string{"conan.lock"},
			Parse:     parseConanLock,
		},
	},
}

// conanLockfile covers the v0.5+ schema. v0.4- (graph_lock.nodes) is left
// unparsed: the v2 arrays are simply absent and the file produces no entries.
type conanLockfile struct {
	Version        string   `json:"version"`
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
}

// conanRef holds the three fields we care about from a parsed reference.
// Conan's full grammar is name/version[@user[/channel]][#rrev][:pkgid[#prev]][%timestamp];
// user/channel/pkgid/prev/timestamp are ignored because they don't change the PURL
// or the integrity hash.
type conanRef struct {
	name    string
	version string
	rrev    string
}

func parseConanLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock conanLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, group := range [][]string{lock.Requires, lock.BuildRequires, lock.PythonRequires} {
		for _, raw := range group {
			ref := parseConanReference(raw)
			if ref.name == "" || ref.version == "" || ref.rrev == "" {
				continue
			}
			alg, ok := conanRrevAlgorithm(ref.rrev)
			if !ok {
				continue
			}
			out.Add(conanPURL(ref.name, ref.version), hashes.Hash{
				Algorithm: alg,
				Hex:       ref.rrev,
			})
		}
	}
	return out, nil
}

// parseConanReference peels the reference grammar from right to left so each
// step sees only the segment it owns:
//
//	name/version[@user[/channel]][#rrev][:pkgid[#prev]][%timestamp]
//
// Mirrors the strip order used by scalibr's conanlock extractor.
func parseConanReference(ref string) conanRef {
	if i := strings.Index(ref, "%"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	var rrev string
	if i := strings.Index(ref, "#"); i >= 0 {
		rrev = ref[i+1:]
		ref = ref[:i]
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	name, version, ok := strings.Cut(ref, "/")
	if !ok {
		// Bare "version" — a consumer conanfile, not a dependency.
		return conanRef{rrev: rrev}
	}
	return conanRef{name: name, version: version, rrev: rrev}
}

// conanRrevAlgorithm maps a recipe revision to its hash algorithm by length.
// 32 hex chars → MD5 (Conan 2 default "hash" mode); 40 hex chars → SHA-1
// (Conan 2 "scm" mode / git commit). Anything else is dropped rather than
// emitted as a junk value.
func conanRrevAlgorithm(rrev string) (hashes.Algorithm, bool) {
	if _, err := hex.DecodeString(rrev); err != nil {
		return "", false
	}
	switch len(rrev) {
	case 32:
		return hashes.AlgMD5, true
	case 40:
		return hashes.AlgSHA1, true
	}
	return "", false
}

func conanPURL(name, version string) string {
	return "pkg:conan/" + name + "@" + version
}
