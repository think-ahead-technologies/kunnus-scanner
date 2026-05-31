// ABOUTME: Encodes a scalibr inventory into CycloneDX 1.6 JSON.
// ABOUTME: Owns the enrichment-stage pipeline; the stages themselves live in their own files.
package sbom

import (
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
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
func Encode(out io.Writer, result *scan.Result, comp bom.ComponentInfo, hashMap hashes.Map, licenseMap license.Map, extras []bom.ExtraComponent) error {
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
	//   4. [enforced] injectLicensesCDX after dedup (so it sees one component per
	//      PURL) and before normalizePURLsCDX: it indexes the inventory by the
	//      original PURL strings, like the enrichment stages.
	//   5. [enforced] normalizePURLsCDX after all PURL-keyed joins: it rewrites the
	//      emitted PURL strings, so it must run once every stage that matches on
	//      the original strings is done.
	dedupCDXComponents(cdxBom)
	enrichCDXMetadata(cdxBom)
	enrichCDXComponents(cdxBom, result.Inventory)
	injectLicensesCDX(cdxBom, result.Inventory, licenseMap)
	injectCPEsCDX(cdxBom)
	// [enforced] Extras must be appended before injectHashesCDX so the hash
	// injector sees them in its PURL index, and before injectDepGraphCDX so their
	// BOMRefs participate in the dep graph.
	appendExtraComponents(cdxBom, extras)
	injectHashesCDX(cdxBom, hashMap)
	injectDepGraphCDX(cdxBom)
	normalizePURLsCDX(cdxBom)

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
