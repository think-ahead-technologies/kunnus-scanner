// ABOUTME: Stage: enriches every CDX component with supplier identity and BSI-required properties.
// ABOUTME: Looks up the matching scalibr Package by PURL to find the extractor metadata enrichment needs.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
)

// enrichCDXComponents walks every component in the BOM, finds the matching
// extractor.Package by PURL, and attaches a derived supplier plus BSI-required
// properties (filename / executable / archive / structured). Components without
// a matching package are left untouched — defensive against future drift.
func enrichCDXComponents(bom *cyclonedx.BOM, inv inventory.Inventory) {
	byPURL := indexInventoryByPURL(inv)
	forEachComponent(bom, func(c *cyclonedx.Component) {
		if c.PackageURL == "" {
			return
		}
		// Supplier derived from PURL — no inventory lookup needed.
		if c.Supplier == nil {
			if name, url := supplierFromPURL(c.PackageURL); name != "" {
				c.Supplier = &cyclonedx.OrganizationalEntity{
					Name: name,
					URL:  &[]string{url},
				}
			}
		}

		// Properties need extractor metadata (Locations + Plugins).
		pkg := byPURL[c.PackageURL]
		if pkg == nil {
			return
		}
		applyBSIProps(c, bsiProperties(pkg))
	})
}

// appendExtraComponents adds one CDX library Component per ExtraComponent.
// Hashes are not attached here — they live in hashMap keyed by PURL and the
// later injectHashesCDX stage stamps them onto every component (scalibr's and
// ours alike). A no-op when extras is empty.
//
// CDX components are stored as a pointer to a slice on the BOM; we allocate
// one if nil so callers don't have to special-case the empty BOM.
func appendExtraComponents(b *cyclonedx.BOM, extras []bom.ExtraComponent) {
	if len(extras) == 0 {
		return
	}
	if b.Components == nil {
		empty := make([]cyclonedx.Component, 0, len(extras))
		b.Components = &empty
	}
	for _, e := range extras {
		*b.Components = append(*b.Components, cyclonedx.Component{
			BOMRef:     e.BomRef,
			Type:       cyclonedx.ComponentType(e.Type),
			Name:       e.Name,
			PackageURL: e.PURL,
		})
	}
}

func indexInventoryByPURL(inv inventory.Inventory) map[string]*extractor.Package {
	out := make(map[string]*extractor.Package, len(inv.Packages))
	for _, p := range inv.Packages {
		if p == nil {
			continue
		}
		purl := p.PURL()
		if purl == nil {
			continue
		}
		out[purl.String()] = p
	}
	return out
}
