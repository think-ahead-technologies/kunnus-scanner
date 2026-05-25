// ABOUTME: Extracts SHA-512 hashes from NuGet packages.lock.json.
// ABOUTME: contentHash is a raw base64 SHA-512 (no "sha512-" SRI prefix).
package hashes

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type nugetLockfile struct {
	// Dependencies is keyed by target framework moniker (e.g. "net6.0"),
	// whose value is keyed by package name.
	Dependencies map[string]map[string]nugetEntry `json:"dependencies"`
}

type nugetEntry struct {
	Type        string `json:"type"`
	Resolved    string `json:"resolved"`
	ContentHash string `json:"contentHash"`
}

func parseNuGetLock(path string) (Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock nugetLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(Map)
	for _, tfmDeps := range lock.Dependencies {
		for name, entry := range tfmDeps {
			if entry.Resolved == "" || entry.ContentHash == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(entry.ContentHash)
			if err != nil || len(raw) != 64 {
				continue
			}
			out[nugetPURL(name, entry.Resolved)] = Hash{
				Algorithm: AlgSHA512,
				Hex:       hex.EncodeToString(raw),
			}
		}
	}
	return out, nil
}

// nugetPURL matches scalibr's NuGet PURL form: case is preserved as written
// in the lockfile (downstream consumers do case-insensitive comparison per
// the spec).
func nugetPURL(name, version string) string {
	return "pkg:nuget/" + name + "@" + version
}
