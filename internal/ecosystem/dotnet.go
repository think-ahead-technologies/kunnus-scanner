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
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/csproj"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/nugetcpm"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

var dotnet = Ecosystem{
	Name:             "dotnet",
	Filenames:        []string{"packages.config", "packages.lock.json", "project.assets.json"},
	FilenameSuffixes: []string{".csproj", ".deps.json"},
	ScalibrPlugins:   []string{csproj.Name, depsjson.Name, nugetcpm.Name, packagesconfig.Name, packageslockjson.Name, dotnetpe.Name},
	InstalledPlugins: []string{dotnetpe.Name},
	HashParsers: []Parser{
		{
			Name:      "nuget",
			Filenames: []string{"packages.lock.json"},
			Parse:     parseNuGetLock,
		},
	},
	GraphParsers: []GraphParser{
		{
			Name:      "nuget",
			Filenames: []string{"packages.lock.json"},
			Parse:     parseNuGetLockGraph,
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

// nugetGraphLockfile is the packages.lock.json shape the graph parser reads:
// per target framework, each package's resolved version and the packages it
// depends on.
type nugetGraphLockfile struct {
	Dependencies map[string]map[string]nugetGraphEntry `json:"dependencies"`
}

type nugetGraphEntry struct {
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
}

// parseNuGetLockGraph mines dependency edges from packages.lock.json. Each
// entry's "dependencies" map names packages plus the minimum version that was
// requested; the edge target is the version the lock actually *resolved* for
// that package, looked up within the same target framework block (the same id
// can resolve differently per framework). NuGet package ids are
// case-insensitive, so references are matched case-insensitively. A reference
// the lock does not pin is dropped — the parser never invents a purl.
func parseNuGetLockGraph(r io.Reader) (graph.Map, error) {
	var lock nugetGraphLockfile
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse packages.lock.json: %w", err)
	}

	out := make(graph.Map)
	// Frameworks and package names are walked in sorted order: one package can
	// appear under several frameworks, so even the order edges are appended in
	// must be stable for byte-identical SBOM output across runs.
	for _, framework := range slices.Sorted(maps.Keys(lock.Dependencies)) {
		pkgs := lock.Dependencies[framework]
		// Index this framework's entries by folded id so a differently-cased
		// reference still resolves, while the purl keeps the id's own casing.
		type resolved struct{ name, version string }
		byFoldedName := make(map[string]resolved, len(pkgs))
		for name, entry := range pkgs {
			if entry.Resolved != "" {
				byFoldedName[strings.ToLower(name)] = resolved{name: name, version: entry.Resolved}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(pkgs)) {
			entry := pkgs[name]
			if entry.Resolved == "" {
				continue
			}
			from := nugetPURL(name, entry.Resolved)
			// Sorted: see the npm parser — deterministic SBOM output.
			for _, dep := range slices.Sorted(maps.Keys(entry.Dependencies)) {
				target, ok := byFoldedName[strings.ToLower(dep)]
				if !ok {
					continue
				}
				out.Add(from, nugetPURL(target.name, target.version))
			}
		}
	}
	return out, nil
}
