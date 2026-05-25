// ABOUTME: Encodes a scalibr inventory into SPDX 2.3 or CycloneDX 1.5 JSON.
// ABOUTME: Wraps scalibr's converter package for the mapping; uses the format libs only for serialization.
package sbom

import (
	"encoding/json"
	"fmt"
	"io"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdx23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Format identifies the SBOM output format. Keep this small — every new
// value here is a new serialization branch to maintain.
type Format string

const (
	// FormatSPDX emits SPDX. The underlying library currently writes 2.3;
	// BSI TR-03183-2 v2.1 requires 3.0.1+, which is unmet pending library work.
	FormatSPDX Format = "spdx"

	// FormatCycloneDX emits CycloneDX. cyclonedx-go writes 1.7, which
	// satisfies BSI TR-03183-2 v2.1's "1.6 or higher" requirement.
	FormatCycloneDX Format = "cyclonedx"
)

// Encode converts the scan result into the chosen format and writes JSON to out.
// hashMap is an optional map of PURL → native SHA-512 digest (typically
// populated from lockfiles by internal/hashes); pass nil if unavailable.
func Encode(out io.Writer, format Format, result *scan.Result, comp mode.ComponentInfo, hashMap hashes.Map) error {
	switch format {
	case FormatSPDX:
		return encodeSPDX(out, result, comp)
	case FormatCycloneDX:
		return encodeCDX(out, result, comp, hashMap)
	default:
		return fmt.Errorf("unknown sbom format %q", format)
	}
}

// ParseFormat normalises a user-supplied format string. Older version-suffixed
// names ("spdx-2-3", "cyclonedx-1-5") are accepted as aliases so existing
// scripts keep working — they map to the un-versioned canonical form.
func ParseFormat(s string) (Format, error) {
	switch s {
	case string(FormatSPDX), "spdx-2-3", "spdx-2.3":
		return FormatSPDX, nil
	case string(FormatCycloneDX), "cyclonedx-1-5", "cyclonedx-1-6", "cyclonedx-1-7":
		return FormatCycloneDX, nil
	}
	return "", fmt.Errorf("unsupported sbom format %q (want %s or %s)", s, FormatSPDX, FormatCycloneDX)
}

func encodeSPDX(out io.Writer, result *scan.Result, comp mode.ComponentInfo) error {
	docName := comp.Name
	if docName == "" {
		docName = "kunnus-sbom"
	}
	cfg := spdx.Config{
		DocumentName:      docName,
		DocumentNamespace: fmt.Sprintf("https://kunnus.tech/sbom/%s/%s", docName, uuid.New().String()),
		Creators: []common.Creator{
			{CreatorType: "Tool", Creator: "kunnus-" + version.Version},
		},
	}

	doc := converter.ToSPDX23(result.Inventory, cfg)
	enrichSPDXCreators(doc)
	injectCPEsSPDX(doc)
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode spdx: %w", err)
	}
	return nil
}

// injectCPEsSPDX adds a SECURITY/cpe23Type external reference to every package
// that has a PURL but no existing CPE reference. Same rationale as the CDX
// counterpart: scalibr only emits CPEs for SBOM-sourced packages.
func injectCPEsSPDX(doc *spdx23.Document) {
	if doc == nil {
		return
	}
	for _, p := range doc.Packages {
		if p == nil || hasCPERef(p) {
			continue
		}
		purl := purlFromRefs(p)
		if purl == "" {
			continue
		}
		cpe := cpeFromPURL(purl)
		if cpe == "" {
			continue
		}
		p.PackageExternalReferences = append(p.PackageExternalReferences, &spdx23.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "cpe23Type",
			Locator:  cpe,
		})
	}
}

func hasCPERef(p *spdx23.Package) bool {
	for _, r := range p.PackageExternalReferences {
		if r != nil && r.RefType == "cpe23Type" {
			return true
		}
	}
	return false
}

func purlFromRefs(p *spdx23.Package) string {
	for _, r := range p.PackageExternalReferences {
		if r != nil && r.RefType == "purl" {
			return r.Locator
		}
	}
	return ""
}

func encodeCDX(out io.Writer, result *scan.Result, comp mode.ComponentInfo, hashMap hashes.Map) error {
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
