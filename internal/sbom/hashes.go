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
//     the location the BSI conformance check specifically queries
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
		// Path-bearing hashes (vendored C/C++ source files today) also surface
		// as a kunnus:vendored:file property so the platform can recover which
		// file each digest belongs to. Lockfile hashes have no Path → no property.
		var fileProps []cyclonedx.Property
		for _, h := range hs {
			if h.Hex == "" {
				continue
			}
			algo, ok := algorithmToCDX(h.Algorithm)
			if !ok {
				// Unrecognised algorithm: skip rather than mislabel it.
				// Extend algorithmToCDX when a new hashes.Algorithm lands.
				continue
			}
			cdxHashes = append(cdxHashes, cyclonedx.Hash{
				Algorithm: algo,
				Value:     h.Hex,
			})
			if h.Path != "" {
				fileProps = append(fileProps, cyclonedx.Property{
					Name:  "kunnus:vendored:file",
					Value: h.Path + ":" + string(h.Algorithm) + ":" + h.Hex,
				})
			}
		}
		if len(cdxHashes) == 0 {
			return
		}
		c.Hashes = mergeHashes(c.Hashes, &cdxHashes)
		if len(fileProps) > 0 {
			if c.Properties == nil {
				c.Properties = &fileProps
			} else {
				combined := append(*c.Properties, fileProps...)
				c.Properties = &combined
			}
		}

		// BSI conformance requires the deployable hash to live on an
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

// algorithmToCDX maps our internal algorithm tag to the cyclonedx constant.
// Returns ok=false for any unrecognised algorithm so the caller can drop the
// hash rather than emit a digest labelled with the wrong algorithm.
func algorithmToCDX(a hashes.Algorithm) (cyclonedx.HashAlgorithm, bool) {
	switch a {
	case hashes.AlgSHA512:
		return cyclonedx.HashAlgoSHA512, true
	case hashes.AlgSHA256:
		return cyclonedx.HashAlgoSHA256, true
	case hashes.AlgSHA1:
		return cyclonedx.HashAlgoSHA1, true
	case hashes.AlgMD5:
		return cyclonedx.HashAlgoMD5, true
	}
	return "", false
}
