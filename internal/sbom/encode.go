// ABOUTME: Encodes a scalibr inventory into CycloneDX 1.7 JSON.
// ABOUTME: Owns the enrichment-stage pipeline; the stages themselves live in their own files.
package sbom

import (
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Encode converts the scan result into a CycloneDX 1.7 SBOM and writes JSON
// to out. hashMap is an optional map of PURL → native digests (one or more
// per package, typically populated from lockfiles); pass nil if unavailable.
func Encode(out io.Writer, result *scan.Result, comp mode.ComponentInfo, hashMap hashes.Map) error {
	componentType := comp.Type
	if componentType == "" {
		componentType = mode.ComponentTypeApplication
	}
	cfg := converter.CDXConfig{
		ComponentName:    comp.Name,
		ComponentVersion: comp.Version,
		ComponentType:    componentType,
		Authors:          []string{"kunnus-" + version.Version},
	}

	bom := converter.ToCDX(result.Inventory, cfg)
	// Order matters here. Constraints:
	//   1. dedupCDXComponents BEFORE enrichCDXComponents: enrichment indexes by
	//      PURL, and duplicates would shadow each other in that index.
	//   2. enrichCDXMetadata BEFORE injectDepGraphCDX: the dep graph reads the
	//      root component's BOMRef, which metadata enrichment may populate.
	//   3. injectDepGraphCDX LAST: it iterates every component's BOMRef, so any
	//      mutation that adds or renames components must precede it.
	dedupCDXComponents(bom)
	enrichCDXMetadata(bom)
	enrichCDXComponents(bom, result.Inventory)
	injectCPEsCDX(bom)
	injectHashesCDX(bom, hashMap)
	injectDepGraphCDX(bom)

	encoder := cyclonedx.NewBOMEncoder(out, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("encode cyclonedx: %w", err)
	}
	return nil
}
