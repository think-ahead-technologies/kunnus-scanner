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
	// Order matters here. Constraints:
	//   1. dedupCDXComponents BEFORE enrichCDXComponents: enrichment indexes by
	//      PURL, and duplicates would shadow each other in that index.
	//   2. enrichCDXMetadata BEFORE injectDepGraphCDX: the dep graph reads the
	//      root component's BOMRef, which metadata enrichment may populate.
	//   3. injectDepGraphCDX LAST among the joining stages: it iterates every
	//      component's BOMRef, so any mutation that adds or renames components
	//      must precede it.
	//   4. injectLicensesCDX after dedup (so it sees one component per PURL) and
	//      before normalizePURLsCDX: it indexes the inventory by the original
	//      PURL strings, like the enrichment stages.
	//   5. normalizePURLsCDX after all PURL-keyed joins: it rewrites the emitted
	//      PURL strings, so it must run once every stage that matches on the
	//      original strings is done.
	dedupCDXComponents(cdxBom)
	enrichCDXMetadata(cdxBom)
	enrichCDXComponents(cdxBom, result.Inventory)
	injectLicensesCDX(cdxBom, result.Inventory, licenseMap)
	injectCPEsCDX(cdxBom)
	// Extras must be appended before injectHashesCDX so the hash injector sees
	// them in its PURL index, and before injectDepGraphCDX so their BOMRefs
	// participate in the dep graph.
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
