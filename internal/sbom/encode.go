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

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Format identifies the SBOM output format. Keep this small — every new
// value here is a new serialization branch to maintain.
type Format string

const (
	FormatSPDX23      Format = "spdx-2-3"
	FormatCycloneDX15 Format = "cyclonedx-1-5"
)

// Encode converts the scan result into the chosen format and writes JSON to out.
func Encode(out io.Writer, format Format, result *scan.Result, comp mode.ComponentInfo) error {
	switch format {
	case FormatSPDX23:
		return encodeSPDX(out, result, comp)
	case FormatCycloneDX15:
		return encodeCDX(out, result, comp)
	default:
		return fmt.Errorf("unknown sbom format %q", format)
	}
}

// ParseFormat normalises a user-supplied format string.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatSPDX23, FormatCycloneDX15:
		return Format(s), nil
	}
	return "", fmt.Errorf("unsupported sbom format %q (want %s or %s)", s, FormatSPDX23, FormatCycloneDX15)
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
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode spdx: %w", err)
	}
	return nil
}

func encodeCDX(out io.Writer, result *scan.Result, comp mode.ComponentInfo) error {
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
	encoder := cyclonedx.NewBOMEncoder(out, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("encode cyclonedx: %w", err)
	}
	return nil
}
