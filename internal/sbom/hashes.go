// ABOUTME: Stage: attaches native SHA-512 hashes harvested from lockfiles to matching CDX components.
// ABOUTME: Writes both component.hashes[] and a synthetic distribution externalReference for BSI conformance.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// injectHashesCDX attaches a native SHA-512 hash to every component whose PURL
// appears in hashMap. Two artefacts are added so both human-readable SBOMs and
// BSI TR-03183-2 v2.1 sbomqs checks find it:
//
//   - component.hashes[] — the standard CDX location
//   - component.externalReferences[type=distribution] with embedded hashes —
//     the location BSI v2.1 §5.2.2 specifically queries
//
// hashMap may be nil or empty; in that case the stage is a no-op.
func injectHashesCDX(bom *cyclonedx.BOM, hashMap hashes.Map) {
	if len(hashMap) == 0 {
		return
	}
	forEachComponent(bom, func(c *cyclonedx.Component) {
		if c.PackageURL == "" {
			return
		}
		h, ok := hashMap[c.PackageURL]
		if !ok || h.Hex == "" {
			return
		}
		cdxHash := cyclonedx.Hash{
			Algorithm: algorithmToCDX(h.Algorithm),
			Value:     h.Hex,
		}
		c.Hashes = mergeHashes(c.Hashes, &[]cyclonedx.Hash{cdxHash})

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
	})
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
