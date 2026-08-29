// ABOUTME: Stage: enriches the top-level CDX metadata (creator identity, serial number, root component).
// ABOUTME: Per-component enrichment lives in components.go; this file only touches BOM-level fields.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"

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
//   - lifecycles — the generation context the mode declared (CISA minimum
//     element): pre-build for source scans, post-build for artifact scans
//   - structured authors with email/URL — closes BSI sbom_creator (required)
//     and CISA's SBOM Author element: the operating entity when one was given
//     on the command line, the kunnus identity otherwise
//   - a kunnus tool entry next to SCALIBR — additional creator signal
//
// It reads the series, lifecycle and author from opts, and takes the current
// time and the identity-less serial from opts' injectable ports.
func enrichCDXMetadata(cdxBom *cyclonedx.BOM, opts Options) error {
	if cdxBom == nil {
		return nil
	}
	if cdxBom.SerialNumber == "" {
		serial, deterministic, err := deriveSerial(opts.Series, opts.newSerial)
		if err != nil {
			return err
		}
		cdxBom.SerialNumber = serial
		if deterministic {
			var ts string
			if cdxBom.Metadata != nil {
				ts = cdxBom.Metadata.Timestamp
			}
			cdxBom.Version = bomVersion(ts, opts.now().UTC())
		}
	}
	if cdxBom.Metadata == nil {
		cdxBom.Metadata = &cyclonedx.Metadata{}
	}

	if opts.Lifecycle != "" {
		cdxBom.Metadata.Lifecycles = &[]cyclonedx.Lifecycle{{
			Phase: cyclonedx.LifecyclePhase(opts.Lifecycle),
		}}
	}

	// CISA's SBOM Author is the entity operating the tool, not the tool: an
	// explicit author replaces the kunnus identity in authors and manufacturer
	// (the organization that created the BOM). Kunnus itself always stays
	// recorded under metadata.tools below.
	authorName, authorEmail := creatorName, creatorEmail
	authorURLs := &[]string{creatorURL}
	if !opts.Author.IsZero() {
		authorName, authorEmail = opts.Author.Name, opts.Author.Email
		authorURLs = nil
	}
	authors := []cyclonedx.OrganizationalContact{{
		Name:  authorName,
		Email: authorEmail,
	}}
	cdxBom.Metadata.Authors = &authors

	cdxBom.Metadata.Manufacturer = &cyclonedx.OrganizationalEntity{
		Name: authorName,
		URL:  authorURLs,
		Contact: &[]cyclonedx.OrganizationalContact{{
			Name:  authorName,
			Email: authorEmail,
		}},
	}

	// scalibr's converter emits its SCALIBR tool entry without a version;
	// backfill it from build info so the SBOM names the exact extractor
	// library release that produced it.
	backfillScalibrToolVersion(cdxBom, version.Scalibr())

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

// backfillScalibrToolVersion sets the given version on the SCALIBR entry in
// metadata.tools.components when the converter left it empty. A no-op for an
// empty version (dependency build info is absent in go-test binaries) or when
// scalibr ever starts stamping its own version.
func backfillScalibrToolVersion(cdxBom *cyclonedx.BOM, scalibrVersion string) {
	if scalibrVersion == "" || cdxBom.Metadata == nil || cdxBom.Metadata.Tools == nil || cdxBom.Metadata.Tools.Components == nil {
		return
	}
	comps := *cdxBom.Metadata.Tools.Components
	for i := range comps {
		if comps[i].Name == "SCALIBR" && comps[i].Version == "" {
			comps[i].Version = scalibrVersion
		}
	}
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
