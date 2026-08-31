// ABOUTME: Stage: drops the component a manifest emits for the project it describes.
// ABOUTME: That project is already metadata.component; listing it again describes the SBOM's subject twice.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pyprojecttoml"
	"github.com/google/osv-scalibr/inventory"
)

// suppressManifestSelfComponents drops components that exist only because a
// manifest names the project it describes.
//
// scalibr's python/pyprojecttoml emits one package per pyproject.toml: the
// project from its [project] table, with the declared dependencies carried as
// Metadata rather than as packages of their own. That project is the thing
// being scanned, so it is already the document's metadata.component — emitting
// it again as a component of itself states the subject twice. It is the same
// trait that kept misc/gitrepo out (see the git-submodule section of
// AGENTS.md).
//
// The plugin stays enabled: its Metadata is the only remaining record of what a
// pyproject.toml declares, and an enricher that surfaces those declarations as
// versionless components would need it.
//
// A purl survives unless *every* package behind it is such a self-component, so
// a lockfile that genuinely pins the same name and version keeps its component —
// the same two-signal caution as the binary-classifier overlap stage.
func suppressManifestSelfComponents(bom *cyclonedx.BOM, inv inventory.Inventory) {
	if bom == nil || bom.Components == nil {
		return
	}
	byPURL := indexInventoryByPURL(inv)
	comps := *bom.Components

	out := make([]cyclonedx.Component, 0, len(comps))
	for i := range comps {
		if isManifestSelfComponent(byPURL[comps[i].PackageURL]) {
			continue
		}
		out = append(out, comps[i])
	}
	*bom.Components = out
}

// isManifestSelfComponent reports whether every package behind one purl is a
// manifest's own project identity. An empty list is not — a component with no
// backing package (an ExtraComponent) is never one of these.
func isManifestSelfComponent(pkgs []*extractor.Package) bool {
	if len(pkgs) == 0 {
		return false
	}
	for _, p := range pkgs {
		if _, ok := p.Metadata.(*pyprojecttoml.Metadata); !ok {
			return false
		}
	}
	return true
}
