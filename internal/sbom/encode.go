// ABOUTME: Encodes a scalibr inventory into CycloneDX 1.6 JSON.
// ABOUTME: Owns the enrichment-stage pipeline; the stages themselves live in their own files.
package sbom

import (
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/graph"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
	"github.com/think-ahead/kunnus-scanner/internal/ownership"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Encode converts the scan result into a CycloneDX 1.6 SBOM and writes JSON
// to out. hashMap is an optional map of PURL → native digests (one or more
// per package, typically populated from lockfiles); pass nil if unavailable.
// licenseMap is an optional map of conventional PURL → raw licence strings
// mined offline from lockfiles (e.g. composer.lock); pass nil if unavailable.
// extras carries components scalibr did not produce — today, vendored C/C++
// libraries surfaced by the kunnus walker. Their per-file hashes ride in
// hashMap under the same PURL.
// owned is the set of filesystem paths the scan root's OS package manager
// records as owned; it drives binary-classifier overlap suppression. Pass nil
// for scans with no OS package database (repo mode).
// series identifies the document series for serial-number derivation; the
// zero value yields a random serial per run (see bom.Series).
// lifecycle is the generation context the mode declared (pre-build /
// post-build); empty omits metadata.lifecycles.
// author is the entity operating the scanner (CISA's SBOM Author element);
// the zero value falls back to the kunnus creator identity.
// graphMap is an optional map of purl → dependsOn purls mined offline from
// lockfiles (Cargo.lock, composer.lock); pass nil if unavailable.
func Encode(out io.Writer, result *scan.Result, comp bom.ComponentInfo, series bom.Series, lifecycle bom.Lifecycle, author bom.Author, hashMap hashes.Map, licenseMap license.Map, graphMap graph.Map, extras []bom.ExtraComponent, owned ownership.Set) error {
	componentType := comp.Type
	if componentType == "" {
		componentType = bom.ComponentTypeApplication
	}
	cfg := converter.CDXConfig{
		ComponentName:    comp.Name,
		ComponentVersion: comp.Version,
		ComponentType:    componentType,
		Authors:          []string{"kunnus-" + version.Version},
	}

	cdxBom := converter.ToCDX(result.Inventory, cfg)
	// Order matters here. Constraints are marked [enforced] when a test in
	// encode_ordering_test.go fails if the stage is reordered (verified by
	// mutation testing), or [defensive] when the order is currently harmless to
	// change but kept to stay correct if a stage's inputs change.
	//   1. [defensive] dedupCDXComponents BEFORE enrichCDXComponents. The intent
	//      is that enrichment sees one component per PURL. Today enrichCDXComponents
	//      indexes result.Inventory (the scalibr packages), not the CDX component
	//      slice, so deduping components cannot change its output — but an
	//      enrichment that read the component slice would need this order.
	//   2. [defensive] enrichCDXMetadata BEFORE injectDepGraphCDX. The dep graph
	//      reads the root component's BOMRef; this order guarantees it is set
	//      first. Today scalibr's converter already sets the root BOMRef and
	//      enrichCDXMetadata never touches it, so the order is not yet load-bearing.
	//   3. injectDepGraphCDX LAST among the joining stages: it iterates every
	//      component's BOMRef, so any mutation that adds or renames components
	//      must precede it. (See the [enforced] extras-before-depgraph case below.)
	//   4. [defensive] injectLicensesCDX and injectCPEsCDX after dedup (so they
	//      see one component per PURL) and before normalizePURLsCDX: both index
	//      the inventory by the original PURL strings, like the enrichment
	//      stages (the CPE stage joins on it to reach the binary classifier's
	//      CPE templates). Mutation testing once enforced this via the licence
	//      join on scalibr's %2F-escaped npm purls; current scalibr emits
	//      unescaped separators, so normalizePURLsCDX is a no-op on every purl
	//      it produces and the order is not output-observable until an escaped
	//      shape returns.
	//   5. [defensive, same reason as #4] normalizePURLsCDX after all PURL-keyed
	//      joins: it rewrites the emitted PURL strings, so it must run once every
	//      stage that matches on the original strings is done.
	dedupCDXComponents(cdxBom)
	// After dedup (so OS and binary-classifier components are each collapsed
	// within their own PURL) and before every later stage: drop binary-classifier
	// pkg:generic twins of OS-managed packages so enrichment, CPEs and the dep
	// graph never see the redundant components.
	suppressOSManagedBinaries(cdxBom, owned)
	// Same placement and reason as the stage above, for the other double-count a
	// pair of extractors can produce: a dependency declared as a range in a
	// manifest and pinned by a lockfile next to it. Dedup cannot collapse those
	// (the versions, hence the PURLs, differ), so the declared twin is dropped
	// here — before CPEs are synthesized for a version that is not one, and
	// before the dep graph could reference it.
	suppressResolvedDeclarations(cdxBom)
	if err := enrichCDXMetadata(cdxBom, series, lifecycle, author); err != nil {
		return fmt.Errorf("failed to derive serial number: %w", err)
	}
	enrichCDXComponents(cdxBom, result.Inventory)
	injectLicensesCDX(cdxBom, result.Inventory, licenseMap)
	injectCPEsCDX(cdxBom, result.Inventory)
	// [enforced] Extras must be appended before injectHashesCDX so the hash
	// injector sees them in its PURL index, and before injectDepGraphCDX so their
	// BOMRefs participate in the dep graph.
	appendExtraComponents(cdxBom, extras)
	injectHashesCDX(cdxBom, hashMap)
	// After injectHashesCDX (its already-hashed guard must see the lockfile
	// digests) and before normalizePURLsCDX (it joins on the original purl
	// strings, like every inventory-keyed stage).
	injectClassifierHashesCDX(cdxBom, result.Inventory)
	injectDepGraphCDX(cdxBom, graphMap)
	normalizePURLsCDX(cdxBom)
	// [enforced] Last: CISA's "explicitly identify unknown information" sweep
	// judges the final state of every component, so every stage that can still
	// fill a producer/version/hash/licence must have run.
	markUnknownInfoCDX(cdxBom)

	// Emit CycloneDX 1.6, not the library's 1.7 default: 1.7 is too new for the
	// current SBOM consumer toolchain, which rejects it, and we use no 1.7-only
	// fields. EncodeVersion downgrades specVersion, $schema, and namespaces
	// together without mutating cdxBom.
	encoder := cyclonedx.NewBOMEncoder(out, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.EncodeVersion(cdxBom, cyclonedx.SpecVersion1_6); err != nil {
		return fmt.Errorf("encode cyclonedx: %w", err)
	}
	return nil
}
