// ABOUTME: CMake extractor — surfaces dependencies pinned in CMake source via FetchContent, ExternalProject, or CPM declares.
// ABOUTME: A kunnus filesystem.Extractor (no scalibr plugin exists for CMake): a thin shell over internal/cmakedecl, which owns the grammar.
package cmake

import (
	"context"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/think-ahead/kunnus-scanner/internal/cmakedecl"
)

// Name is the scalibr plugin name for the CMake extractor. It is a
// kunnus-native extractor appended directly by mode/repo (like modustoolbox),
// not a name in scalibr's registry.
const Name = "kunnus/cmake"

// cpmScript is the vendored CPM.cmake package-manager script itself — a
// function library, not a manifest. Its internal invocations are all
// variable-driven (which the ${...} rule would drop anyway); rejecting it in
// FileRequired is belt-and-braces.
const cpmScript = "cpm.cmake"

// Extractor surfaces dependencies pinned directly in CMake source:
// FetchContent_Declare / ExternalProject_Add (git URL + GIT_TAG, or tarball
// URL) and the CPM.cmake wrapper commands. The grammar lives in
// internal/cmakedecl, shared with the ecosystem registry's URL_HASH hash
// parser so both derive identical purls.
type Extractor struct{}

// New returns a CMake extractor.
func New() *Extractor { return &Extractor{} }

// Name returns the kunnus plugin name.
func (*Extractor) Name() string { return Name }

// Version is the plugin version, bumped on behavioural changes.
func (*Extractor) Version() int { return 0 }

// Requirements declares no special capabilities: the extractor reads file bytes
// through the scan input, so it works against a host filesystem or any abstract
// FS, on any OS.
func (*Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether path is CMake source that can carry declares:
// CMakeLists.txt or any *.cmake module (both matched case-insensitively),
// except the vendored CPM.cmake script itself.
func (*Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := strings.ToLower(path.Base(api.Path()))
	if base == cpmScript {
		return false
	}
	return base == "cmakelists.txt" || strings.HasSuffix(base, ".cmake")
}

// Extract parses the file's declares and emits one package per literal pin.
// Files without declares (the overwhelming majority of CMake source) yield no
// packages, and a malformed file yields no error: bad CMake must not fail the
// scan.
func (*Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	decls := cmakedecl.Parse(input.Reader)
	pkgs := make([]*extractor.Package, 0, len(decls))
	for _, d := range decls {
		pkgs = append(pkgs, &extractor.Package{
			Name:     d.Name,
			Version:  d.Version,
			PURLType: d.PURLType,
			Location: extractor.LocationFromPath(input.Path),
		})
	}
	return inventory.Inventory{Packages: pkgs}, nil
}
