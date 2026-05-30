// ABOUTME: Stage: attaches SPDX-conformant licenses to each CDX component from its scalibr packages.
// ABOUTME: Normalization (string -> SPDX id/expression/LicenseRef) lives in internal/license; this file only maps to CDX.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/license"
)

// injectLicensesCDX fills in Component.Licenses for any component that has a PURL
// and no licenses yet, from two sources: the matching scalibr packages'
// declared licenses (apk/rpm extractors, or the deps.dev enricher) and the
// offline licenseMap mined from lockfiles (e.g. composer.lock). Each value is
// normalized to an SPDX identifier, SPDX expression, or LicenseRef-... custom id
// (see internal/license) so the output satisfies BSI §6.1.
//
// Licenses are written with acknowledgement "concluded": the license a package
// declares in its own metadata is, for a component consumed as-is, the
// distribution license under which the licensee may use it — the BSI §5.2.2
// required field. Components with no license from either source are left
// untouched.
//
// Inventory licenses are matched on scalibr's raw PURL (this stage runs before
// normalizePURLsCDX); the offline map is keyed by the conventional PURL, so it
// is matched on the normalized component PURL.
func injectLicensesCDX(bom *cyclonedx.BOM, inv inventory.Inventory, licenseMap license.Map) {
	byPURL := indexInventoryByPURL(inv)
	forEachComponent(bom, func(c *cyclonedx.Component) {
		if c.PackageURL == "" {
			return
		}
		// Preserve any license the converter or dedup already established.
		if c.Licenses != nil && len(*c.Licenses) > 0 {
			return
		}
		raws := inventoryLicenses(byPURL[c.PackageURL])
		raws = append(raws, licenseMap[normalizePURL(c.PackageURL)]...)
		choices := licenseChoices(raws)
		if len(choices) > 0 {
			c.Licenses = &choices
		}
	})
}

// inventoryLicenses gathers the raw license strings across every package sharing
// a PURL.
func inventoryLicenses(pkgs []*extractor.Package) []string {
	var raws []string
	for _, p := range pkgs {
		if p != nil {
			raws = append(raws, p.Licenses...)
		}
	}
	return raws
}

// licenseChoices normalizes and deduplicates raw license strings into CDX
// license choices. Dedup is on the normalized value, so "MIT" and "mit" collapse
// to one entry.
func licenseChoices(raws []string) cyclonedx.Licenses {
	seen := make(map[string]bool)
	var out cyclonedx.Licenses
	for _, raw := range raws {
		n, ok := license.Normalize(raw)
		if !ok || seen[n.Value] {
			continue
		}
		seen[n.Value] = true
		out = append(out, licenseChoice(n))
	}
	return out
}

// licenseChoice maps one normalized license to its CDX representation. A single
// SPDX identifier and a LicenseRef use the structured License object (so the
// acknowledgement is carried and BSI's concluded-license check can see it); a
// compound expression uses the expression form, which CDX requires for
// operators.
func licenseChoice(n license.Normalized) cyclonedx.LicenseChoice {
	switch n.Kind {
	case license.KindExpression:
		ack := cyclonedx.LicenseAcknowledgementConcluded
		return cyclonedx.LicenseChoice{Expression: n.Value, Acknowledgement: &ack}
	case license.KindCustomRef:
		return cyclonedx.LicenseChoice{License: &cyclonedx.License{
			Name:            n.Value,
			Acknowledgement: cyclonedx.LicenseAcknowledgementConcluded,
		}}
	default: // KindID
		return cyclonedx.LicenseChoice{License: &cyclonedx.License{
			ID:              n.Value,
			Acknowledgement: cyclonedx.LicenseAcknowledgementConcluded,
		}}
	}
}
