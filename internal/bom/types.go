// ABOUTME: Boundary types between the planner (mode) and the encoder (sbom).
// ABOUTME: Lives in its own package so neither side depends on the other for naming.
package bom

// Component type values for ComponentInfo.Type. These are the CycloneDX
// `metadata.component.type` strings; we list them here because every
// SBOM kunnus emits has to commit to one of these for its root component.
const (
	ComponentTypeApplication = "application"
	ComponentTypeOS          = "operating-system"
	ComponentTypeFirmware    = "firmware"
	ComponentTypeLibrary     = "library"
	ComponentTypeContainer   = "container"
)

// ComponentInfo describes the root component of the resulting SBOM.
// CycloneDX puts this in metadata.component.
type ComponentInfo struct {
	Name    string
	Version string
	Type    string // one of ComponentType* constants above
}

// ExtraComponent is one BOM component sourced outside scalibr. The fields are
// the minimum a CycloneDX library entry needs; everything else (hashes,
// per-file properties) flows through a hashes.Map keyed on PURL.
type ExtraComponent struct {
	// PURL is the package-url for the component. Vendored libs use the
	// pkg:generic type with a vendored_path qualifier.
	PURL string

	// Name is the short human-readable name (the vendored directory's basename).
	Name string

	// Type is the CycloneDX component type — "library" for vendored sources.
	Type string

	// BomRef is a stable identifier within the BOM ("vendored:<rel-path>").
	BomRef string
}
