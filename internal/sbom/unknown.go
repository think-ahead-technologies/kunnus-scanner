// ABOUTME: Stage: explicit unknown-information markers (CISA "Explicitly Identifying
// ABOUTME: Unknown Information"). Absent producer/version/hash/licence fields get
// kunnus:unknown:* properties so omission is a statement, not an accident.
package sbom

import cyclonedx "github.com/CycloneDX/cyclonedx-go"

// unknownMarkerPrefix namespaces the marker properties. Values are always the
// string "true" (the property-value convention documented in
// docs/sbom-properties.md). kunnus withholds nothing, so every marker means
// "unknown to the SBOM author", never "known but redacted".
const unknownMarkerPrefix = "kunnus:unknown:"

// markUnknownInfoCDX appends an explicit kunnus:unknown:<field> property for
// each CISA minimum-element field a component is missing: producer (no
// supplier could be derived — unknown provenance), version, hash, and license.
// It runs last in the encode pipeline so it sees the final state of every
// enrichment stage.
//
// Only enumerated components are swept. The root component is the author's own
// product — its name/version come from the operator's flags and its producer
// is the operator, so scanner-side unknown markers would be noise there.
func markUnknownInfoCDX(cdxBom *cyclonedx.BOM) {
	if cdxBom == nil || cdxBom.Components == nil {
		return
	}
	comps := *cdxBom.Components
	for i := range comps {
		c := &comps[i]
		if c.Supplier == nil {
			addUnknownMarker(c, "producer")
		}
		if c.Version == "" {
			addUnknownMarker(c, "version")
		}
		if c.Hashes == nil || len(*c.Hashes) == 0 {
			addUnknownMarker(c, "hash")
		}
		if c.Licenses == nil || len(*c.Licenses) == 0 {
			addUnknownMarker(c, "license")
		}
	}
}

func addUnknownMarker(c *cyclonedx.Component, field string) {
	prop := cyclonedx.Property{Name: unknownMarkerPrefix + field, Value: "true"}
	if c.Properties == nil {
		c.Properties = &[]cyclonedx.Property{prop}
		return
	}
	props := append(*c.Properties, prop)
	c.Properties = &props
}
