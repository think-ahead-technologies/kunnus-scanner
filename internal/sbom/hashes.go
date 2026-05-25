// ABOUTME: Stage: attaches native hashes harvested from lockfiles to matching CDX components.
// ABOUTME: Writes both component.hashes[] and a synthetic distribution externalReference for BSI conformance.
package sbom

import (
	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// injectHashesCDX attaches every hash recorded for a PURL to its component.
// Python wheels and conda channels publish one digest per distribution file
// (often dozens per package); the slice on hashes.Map preserves them all and
// surfaces them in two CDX locations:
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
		hs, ok := hashMap[c.PackageURL]
		if !ok {
			return
		}
		cdxHashes := make([]cyclonedx.Hash, 0, len(hs))
		for _, h := range hs {
			if h.Hex == "" {
				continue
			}
			cdxHashes = append(cdxHashes, cyclonedx.Hash{
				Algorithm: algorithmToCDX(h.Algorithm),
				Value:     h.Hex,
			})
		}
		if len(cdxHashes) == 0 {
			return
		}
		c.Hashes = mergeHashes(c.Hashes, &cdxHashes)

		// BSI v2.1 §5.2.2 requires the deployable hash to live on an
		// externalReference of type "distribution" or "distribution-intake".
		// We add a synthetic distribution reference rather than reuse the
		// (possibly absent) registry URL.
		distRef := cyclonedx.ExternalReference{
			URL:    "",
			Type:   cyclonedx.ERTypeDistribution,
			Hashes: &cdxHashes,
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
	case hashes.AlgSHA1:
		return cyclonedx.HashAlgoSHA1
	case hashes.AlgMD5:
		return cyclonedx.HashAlgoMD5
	}
	return cyclonedx.HashAlgoSHA512
}
