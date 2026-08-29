// ABOUTME: Options is the single input boundary for Encode — what to encode, plus the ports it needs.
// ABOUTME: Holding the scan inventory directly is what keeps this package free of an internal/scan import.
package sbom

import (
	"time"

	"github.com/google/osv-scalibr/inventory"
	"github.com/google/uuid"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/graph"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
	"github.com/think-ahead/kunnus-scanner/internal/ownership"
)

// Options is everything Encode needs to produce one CycloneDX document. It
// takes the inventory rather than a scan result so the encoder does not depend
// on the adapter that drives the scanner. Every field but Inventory is
// optional; a zero value simply contributes nothing to the document.
type Options struct {
	// Inventory is the scan's package inventory, the document's subject matter.
	Inventory inventory.Inventory

	// Component describes the SBOM's root component.
	Component bom.ComponentInfo

	// Series identifies the document series for serial derivation. The zero
	// value yields a random serial per run (see bom.Series).
	Series bom.Series

	// Lifecycle is the mode's generation context. Empty omits the field.
	Lifecycle bom.Lifecycle

	// Author is the entity operating the scanner. Zero falls back to the
	// kunnus creator identity.
	Author bom.Author

	// Hashes maps PURL to native digests, typically mined from lockfiles.
	Hashes hashes.Map

	// Licenses maps conventional PURL to raw licence strings mined offline.
	Licenses license.Map

	// Graph maps purl to dependsOn purls, mined from resolved lockfiles.
	Graph graph.Map

	// Extras carries components scalibr did not produce (vendored libraries, a
	// container's OS). Their hashes ride in Hashes under the same PURL.
	Extras []bom.ExtraComponent

	// OwnedFiles is the set of OS-package-manager-owned paths driving binary
	// classifier overlap suppression. Nil for repo scans.
	OwnedFiles ownership.Set

	// Now supplies the wall clock, the encoder's only reading of the current
	// time. Nil means time.Now.
	Now func() time.Time

	// NewSerial supplies an identity-less document's serial as a bare UUID.
	// Nil means a random UUIDv4. A document with an identity never uses it.
	NewSerial func() string
}

// now reads the clock, defaulting to the wall clock.
func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// newSerial draws a serial for an identity-less document, defaulting to random.
func (o Options) newSerial() string {
	if o.NewSerial != nil {
		return o.NewSerial()
	}
	return randomSerial()
}

// randomSerial is the default identity-less serial source: a fresh UUIDv4.
func randomSerial() string { return uuid.New().String() }
