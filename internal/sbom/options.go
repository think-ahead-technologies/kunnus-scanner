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

// Options is everything Encode needs to produce one CycloneDX document.
//
// It takes the inventory rather than a scan result on purpose: the encoder is
// an output adapter and must not depend on the adapter that drives the
// scanner. Every optional field may be left at its zero value — an absent map
// simply contributes nothing to the document.
type Options struct {
	// Inventory is the scan's package inventory, the document's subject matter.
	Inventory inventory.Inventory

	// Component describes the SBOM's root component (CycloneDX
	// metadata.component).
	Component bom.ComponentInfo

	// Series identifies the document series for serial-number derivation. The
	// zero value yields a random serial per run (see bom.Series).
	Series bom.Series

	// Lifecycle is the generation context the mode declared (pre-build /
	// post-build). Empty omits metadata.lifecycles.
	Lifecycle bom.Lifecycle

	// Author is the entity operating the scanner (CISA's SBOM Author element).
	// The zero value falls back to the kunnus creator identity.
	Author bom.Author

	// Hashes maps PURL to native digests, typically mined from lockfiles.
	Hashes hashes.Map

	// Licenses maps conventional PURL to raw licence strings mined offline
	// from lockfiles (e.g. composer.lock).
	Licenses license.Map

	// Graph maps purl to dependsOn purls, mined offline from lockfiles that
	// pin a resolved dependency graph.
	Graph graph.Map

	// Extras carries components scalibr did not produce — vendored C/C++
	// libraries, a container image's OS. Their per-component hashes ride in
	// Hashes under the same PURL.
	Extras []bom.ExtraComponent

	// Owned is the set of filesystem paths the scan root's OS package manager
	// records as owned; it drives binary-classifier overlap suppression. Nil
	// for scans with no OS package database (repo mode).
	Owned ownership.Set

	// Now supplies the wall clock. It dates a series document whose converter
	// timestamp is unparseable, which is the only place the encoder reads the
	// current time. Nil means time.Now.
	Now func() time.Time

	// NewSerial supplies the serial number for a document with no stable
	// identity, as a bare UUID — deriveSerial adds the urn:uuid prefix. Nil
	// means a random UUIDv4. Documents that do have an identity never consult
	// it: their serial is derived from that identity.
	NewSerial func() string
}

// now reads the clock, defaulting to the wall clock when none was injected.
func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// newSerial draws a serial for an identity-less document, defaulting to a
// random UUIDv4 when no source was injected.
func (o Options) newSerial() string {
	if o.NewSerial != nil {
		return o.NewSerial()
	}
	return randomSerial()
}

// randomSerial is the default identity-less serial source: a fresh UUIDv4.
func randomSerial() string { return uuid.New().String() }
