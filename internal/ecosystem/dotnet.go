// ABOUTME: .NET ecosystem. Extracts SHA-512 hashes from NuGet's packages.lock.json.
// ABOUTME: contentHash is a raw base64 SHA-512 (no "sha512-" SRI prefix unlike npm).
package ecosystem

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/nugetcpm"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var dotnet = Ecosystem{
	Name:             "dotnet",
	Filenames:        []string{"packages.config", "packages.lock.json", "project.assets.json"},
	FilenameSuffixes: []string{".csproj", ".deps.json"},
	ScalibrPlugins:   []string{csproj.Name, depsjson.Name, nugetcpm.Name, packagesconfig.Name, packageslockjson.Name, dotnetpe.Name},
	HashParsers: []Parser{
		{
			Name:      "nuget",
			Filenames: []string{"packages.lock.json"},
			Parse:     parseNuGetLock,
		},
	},
}

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

func parseNuGetLock(r io.Reader) (hashes.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lock nugetLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}

	out := make(hashes.Map)
	for _, tfmDeps := range lock.Dependencies {
		for name, entry := range tfmDeps {
			if entry.Resolved == "" || entry.ContentHash == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(entry.ContentHash)
			if err != nil || len(raw) != sha512.Size {
				continue
			}
			out.Add(nugetPURL(name, entry.Resolved), hashes.Hash{
				Algorithm: hashes.AlgSHA512,
				Hex:       hex.EncodeToString(raw),
			})
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
