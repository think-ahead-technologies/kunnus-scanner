// ABOUTME: Encodes a scalibr inventory into CycloneDX 1.7 JSON.
// ABOUTME: Wraps scalibr's converter package for the mapping; uses cyclonedx-go for serialization.
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
// to out. hashMap is an optional map of PURL → native SHA-512 digest
// (typically populated from lockfiles by internal/hashes); pass nil if
// unavailable.
func Encode(out io.Writer, result *scan.Result, comp mode.ComponentInfo, hashMap hashes.Map) error {
	componentType := comp.Type
	if componentType == "" {
		componentType = "application"
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

// injectHashesCDX attaches a native SHA-512 hash to every component whose PURL
// appears in hashMap. Two artefacts are added so both human-readable SBOMs and
// BSI TR-03183-2 v2.1 sbomqs checks find it:
//
//   - component.hashes[] — the standard CDX location
//   - component.externalReferences[type=distribution] with embedded hashes —
//     the location BSI v2.1 §5.2.2 specifically queries
//
// hashMap may be nil; in that case the function is a no-op.
func injectHashesCDX(bom *cyclonedx.BOM, hashMap hashes.Map) {
	if bom == nil || bom.Components == nil || len(hashMap) == 0 {
		return
	}
	for i := range *bom.Components {
		c := &(*bom.Components)[i]
		if c.PackageURL == "" {
			continue
		}
		h, ok := hashMap[c.PackageURL]
		if !ok || h.Hex == "" {
			continue
		}
		cdxHash := cyclonedx.Hash{
			Algorithm: algorithmToCDX(h.Algorithm),
			Value:     h.Hex,
		}
		c.Hashes = appendHashes(c.Hashes, &[]cyclonedx.Hash{cdxHash})

		// BSI v2.1 §5.2.2 requires the deployable hash to live on an
		// externalReference of type "distribution" or "distribution-intake".
		// We add a synthetic distribution reference rather than reuse the
		// (possibly absent) registry URL.
		distRef := cyclonedx.ExternalReference{
			URL:    "",
			Type:   cyclonedx.ERTypeDistribution,
			Hashes: &[]cyclonedx.Hash{cdxHash},
		}
		c.ExternalReferences = mergeExternalRefs(c.ExternalReferences, &[]cyclonedx.ExternalReference{distRef})
	}
}

func algorithmToCDX(a hashes.Algorithm) cyclonedx.HashAlgorithm {
	switch a {
	case hashes.AlgSHA512:
		return cyclonedx.HashAlgoSHA512
	case hashes.AlgSHA256:
		return cyclonedx.HashAlgoSHA256
	}
	return cyclonedx.HashAlgoSHA512
}

// injectCPEsCDX fills in Component.CPE for any component that has a PURL but
// no CPE yet. Scalibr only emits CPEs for packages that came from a parsed
// SBOM input; for everything else we synthesise one.
func injectCPEsCDX(bom *cyclonedx.BOM) {
	if bom == nil || bom.Components == nil {
		return
	}
	for i, c := range *bom.Components {
		if c.CPE != "" || c.PackageURL == "" {
			continue
		}
		if cpe := cpeFromPURL(c.PackageURL); cpe != "" {
			(*bom.Components)[i].CPE = cpe
		}
	}
}
