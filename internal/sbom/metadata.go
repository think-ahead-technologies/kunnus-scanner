// ABOUTME: Stage: enriches the top-level CDX metadata (creator identity, serial number, root component).
// ABOUTME: Per-component enrichment lives in components.go; this file only touches BOM-level fields.
package sbom

import (
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
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
//   - serialNumber (urn:uuid) — closes the sbom_uri optional check; derived
//     deterministically from the series identity when one exists (see
//     serial.go), random otherwise
//   - version — for series members, the generation timestamp in epoch seconds,
//     so successive documents sharing a serial stay strictly ordered
//   - structured authors with email/URL — closes BSI sbom_creator (required)
//   - a kunnus tool entry next to SCALIBR — additional creator signal
func enrichCDXMetadata(cdxBom *cyclonedx.BOM, series bom.Series) error {
	if cdxBom == nil {
		return nil
	}
	if cdxBom.SerialNumber == "" {
		serial, deterministic, err := deriveSerial(series)
		if err != nil {
			return err
		}
		cdxBom.SerialNumber = serial
		if deterministic {
			var ts string
			if cdxBom.Metadata != nil {
				ts = cdxBom.Metadata.Timestamp
			}
			cdxBom.Version = bomVersion(ts, time.Now().UTC())
		}
	}
	if cdxBom.Metadata == nil {
		cdxBom.Metadata = &cyclonedx.Metadata{}
	}

	authors := []cyclonedx.OrganizationalContact{{
		Name:  creatorName,
		Email: creatorEmail,
	}}
	cdxBom.Metadata.Authors = &authors

	cdxBom.Metadata.Manufacturer = &cyclonedx.OrganizationalEntity{
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
	if cdxBom.Metadata.Tools == nil {
		cdxBom.Metadata.Tools = &cyclonedx.ToolsChoice{}
	}
	if cdxBom.Metadata.Tools.Components == nil {
		cdxBom.Metadata.Tools.Components = &[]cyclonedx.Component{kunnusTool}
	} else {
		comps := append(*cdxBom.Metadata.Tools.Components, kunnusTool)
		cdxBom.Metadata.Tools.Components = &comps
	}

	enrichRootComponent(cdxBom.Metadata.Component)
	return nil
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
