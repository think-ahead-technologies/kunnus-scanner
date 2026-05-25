// ABOUTME: Stage: enriches the top-level CDX metadata (creator identity, serial number, root component).
// ABOUTME: Per-component enrichment lives in components.go; this file only touches BOM-level fields.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
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
