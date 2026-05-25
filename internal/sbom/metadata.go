// ABOUTME: Post-conversion CDX metadata fixups (creator identity, serial number, per-component supplier/properties).
// ABOUTME: Closes the BSI TR-03183-2 v2.1 gaps that scalibr's converter doesn't fill in by default.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/uuid"

	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Kunnus identity: the SBOM creator. Hardcoded here because the SBOM document
// it produces is always authored by kunnus regardless of what we scan. These
// values flow into BSI-required fields (sbom_creator, comp_creator fallback).
const (
	creatorName  = "Kunnus"
	creatorEmail = "kunnus@think-ahead.tech"
	creatorURL   = "https://kunnus.tech"
)

// enrichCDXMetadata patches the top-level BOM metadata after scalibr's
// converter has populated it. Adds:
//   - serialNumber (urn:uuid) — closes the sbom_uri optional check
//   - structured authors with email/URL — closes BSI sbom_creator (required)
//   - a kunnus tool entry next to SCALIBR — additional creator signal
func enrichCDXMetadata(bom *cyclonedx.BOM) {
	if bom == nil {
		return
	}
	if bom.SerialNumber == "" {
		bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	}
	if bom.Metadata == nil {
		bom.Metadata = &cyclonedx.Metadata{}
	}

	authors := []cyclonedx.OrganizationalContact{{
		Name:  creatorName,
		Email: creatorEmail,
	}}
	bom.Metadata.Authors = &authors

	bom.Metadata.Manufacturer = &cyclonedx.OrganizationalEntity{
		Name: creatorName,
		URL:  &[]string{creatorURL},
		Contact: &[]cyclonedx.OrganizationalContact{{
			Name:  creatorName,
			Email: creatorEmail,
		}},
	}

	kunnusTool := cyclonedx.Component{
		Type:    cyclonedx.ComponentTypeApplication,
		Name:    "kunnus",
		Version: version.Version,
		ExternalReferences: &[]cyclonedx.ExternalReference{
			{URL: creatorURL, Type: cyclonedx.ERTypeWebsite},
		},
	}
	if bom.Metadata.Tools == nil {
		bom.Metadata.Tools = &cyclonedx.ToolsChoice{}
	}
	if bom.Metadata.Tools.Components == nil {
		bom.Metadata.Tools.Components = &[]cyclonedx.Component{kunnusTool}
	} else {
		comps := append(*bom.Metadata.Tools.Components, kunnusTool)
		bom.Metadata.Tools.Components = &comps
	}

	enrichRootComponent(bom.Metadata.Component)
}

// enrichRootComponent backfills the BSI-required fields on the SBOM's root
// component (metadata.component), which scalibr creates as a sparse stub.
// It has no extractor metadata so the regular enrichCDXComponents loop skips
// it — we set conservative defaults here instead.
func enrichRootComponent(c *cyclonedx.Component) {
	if c == nil {
		return
	}
	if c.Version == "" {
		// Use the kunnus version as a date-of-creation proxy: BSI accepts any
		// stable identifier for the version field.
		c.Version = version.Version
	}
	if c.Supplier == nil {
		c.Supplier = &cyclonedx.OrganizationalEntity{
			Name: creatorName,
			URL:  &[]string{creatorURL},
		}
	}
	// The root component represents this SBOM document itself — it is
	// structured metadata, not an executable or archive.
	applyBSIProps(c, map[string]string{
		bsiPropFilename:   c.Name,
		bsiPropExecutable: "false",
		bsiPropArchive:    "false",
		bsiPropStructured: "true",
	})
}

// enrichCDXComponents walks every component in the BOM, finds the matching
// extractor.Package by PURL, and attaches a derived supplier plus BSI-required
// properties (filename / executable / archive / structured). Components without
// a matching package are left untouched — defensive against future drift.
func enrichCDXComponents(bom *cyclonedx.BOM, inv inventory.Inventory) {
	if bom == nil || bom.Components == nil {
		return
	}
	byPURL := indexInventoryByPURL(inv)

	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.PackageURL == "" {
			continue
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
			continue
		}
		applyBSIProps(c, bsiProperties(pkg))
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

func applyBSIProps(c *cyclonedx.Component, props map[string]string) {
	if len(props) == 0 {
		return
	}
	existing := map[string]bool{}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			existing[p.Name] = true
		}
	}
	additions := make([]cyclonedx.Property, 0, len(props))
	for name, value := range props {
		if existing[name] {
			continue
		}
		additions = append(additions, cyclonedx.Property{Name: name, Value: value})
	}
	if len(additions) == 0 {
		return
	}
	if c.Properties == nil {
		c.Properties = &additions
		return
	}
	combined := append(*c.Properties, additions...)
	c.Properties = &combined
}
