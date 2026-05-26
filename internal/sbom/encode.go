// ABOUTME: Encodes a scalibr inventory into CycloneDX 1.7 JSON.
// ABOUTME: Owns the enrichment-stage pipeline; the stages themselves live in their own files.
package sbom

import (
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Encode converts the scan result into a CycloneDX 1.7 SBOM and writes JSON
// to out. hashMap is an optional map of PURL → native digests (one or more
// per package, typically populated from lockfiles); pass nil if unavailable.
// extras carries components scalibr did not produce — today, vendored C/C++
// libraries surfaced by the kunnus walker. Their per-file hashes ride in
// hashMap under the same PURL.
func Encode(out io.Writer, result *scan.Result, comp bom.ComponentInfo, hashMap hashes.Map, extras []bom.ExtraComponent) error {
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
	//   3. injectDepGraphCDX LAST: it iterates every component's BOMRef, so any
	//      mutation that adds or renames components must precede it.
	dedupCDXComponents(cdxBom)
	enrichCDXMetadata(cdxBom)
	enrichCDXComponents(cdxBom, result.Inventory)
	injectCPEsCDX(cdxBom)
	// Extras must be appended before injectHashesCDX so the hash injector sees
	// them in its PURL index, and before injectDepGraphCDX so their BOMRefs
	// participate in the dep graph.
	appendExtraComponents(cdxBom, extras)
	injectHashesCDX(cdxBom, hashMap)
	injectDepGraphCDX(cdxBom)

	encoder := cyclonedx.NewBOMEncoder(out, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(cdxBom); err != nil {
		return fmt.Errorf("encode cyclonedx: %w", err)
	}
	return nil
}
