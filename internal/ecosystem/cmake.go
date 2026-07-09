// ABOUTME: CMake ecosystem — projects pinning dependencies via FetchContent, ExternalProject, or CPM.cmake declares.
// ABOUTME: Detection + URL_HASH digest mining here; components come from the kunnus-native internal/cmake extractor the mode wires in (no scalibr plugin exists).
package ecosystem

import (
	"io"

	"github.com/think-ahead/kunnus-scanner/internal/cmakedecl"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// cmake detects projects that pin dependencies directly in CMake source:
// FetchContent_Declare, ExternalProject_Add, and the CPM.cmake wrapper. This
// flags "cmake" on essentially every C++ repo — that is correct and harmless:
// the extractor emits nothing unless a pinned declare exists. The .cmake
// suffix matters because CPM convention puts declares in cmake/*.cmake
// modules. The HashParser mines URL_HASH digests from FetchContent tarball
// declares; the parser dispatch table is exact-filename, so hash mining runs
// only for CMakeLists.txt (a *.cmake module's URL_HASH is not mined — extend
// Parser with suffix support if that ever bites). Both the parser here and
// internal/cmake delegate to internal/cmakedecl, which is scalibr-free, so
// their purls cannot drift and this package keeps its no-scalibr rule.
var cmake = Ecosystem{
	Name:             "cmake",
	Filenames:        []string{"CMakeLists.txt"},
	FilenameSuffixes: []string{".cmake"},
	NativeExtractor:  true,
	HashParsers: []Parser{
		{
			Name:      "cmake",
			Filenames: []string{"CMakeLists.txt"},
			Parse:     parseCMakeHashes,
		},
	},
}

// parseCMakeHashes mines URL_HASH digests from a CMake file's dependency
// declares, keyed by the same purls internal/cmake emits (cmakedecl derives
// both) so the SBOM injector binds them without translation.
func parseCMakeHashes(r io.Reader) (hashes.Map, error) {
	out := make(hashes.Map)
	for _, d := range cmakedecl.Parse(r) {
		if len(d.Hashes) == 0 {
			continue
		}
		purl := "pkg:" + d.PURLType + "/" + d.Name
		if d.Version != "" {
			purl += "@" + d.Version
		}
		for _, h := range d.Hashes {
			out.Add(purl, h)
		}
	}
	return out, nil
}
