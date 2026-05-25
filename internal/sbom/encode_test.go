// ABOUTME: Tests for sbom.Encode: builds an inventory with one package and validates the output JSON.
// ABOUTME: Parses the encoded output rather than golden-file matching, since UUIDs / timestamps drift.
package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

func sampleResult() *scan.Result {
	pkg := &extractor.Package{
		Name:     "github.com/stretchr/testify",
		Version:  "1.8.0",
		PURLType: "golang",
		Plugins:  []string{"go/gomod"},
	}
	return &scan.Result{
		Inventory: inventory.Inventory{
			Packages: []*extractor.Package{pkg},
		},
	}
}

func TestEncode_CycloneDX_HasCPE(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, FormatCycloneDX15, sampleResult(), mode.ComponentInfo{Name: "x", Type: "application"}); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comps, _ := doc["components"].([]any)
	if len(comps) == 0 {
		t.Fatal("no components in output")
	}
	got, _ := comps[0].(map[string]any)["cpe"].(string)
	want := "cpe:2.3:a:stretchr:testify:1.8.0:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("CDX component cpe = %q, want %q", got, want)
	}
}

func TestEncode_SPDX_HasCPEExternalRef(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, FormatSPDX23, sampleResult(), mode.ComponentInfo{Name: "x"}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, `"referenceType": "cpe23Type"`) {
		t.Error("SPDX output missing cpe23Type external reference")
	}
	if !strings.Contains(body, "cpe:2.3:a:stretchr:testify:1.8.0:") {
		t.Errorf("SPDX output missing expected CPE string: %s", body)
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"spdx-2-3", "cyclonedx-1-5"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", ok, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(\"yaml\") want error, got nil")
	}
}

func TestEncode_SPDX23(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, FormatSPDX23, sampleResult(), mode.ComponentInfo{
		Name:    "my-component",
		Version: "1.0.0",
		Type:    "application",
	})
	if err != nil {
		t.Fatalf("Encode SPDX: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\nbody:\n%s", err, buf.String())
	}

	if v, _ := doc["spdxVersion"].(string); v != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3", doc["spdxVersion"])
	}
	if v, _ := doc["name"].(string); v != "my-component" {
		t.Errorf("name = %v, want my-component", doc["name"])
	}

	body := buf.String()
	if !strings.Contains(body, "testify") {
		t.Error("SPDX output missing testify package")
	}
	if !strings.Contains(body, "https://kunnus.tech/sbom/") {
		t.Error("SPDX output missing kunnus namespace")
	}
}

func TestEncode_CycloneDX15(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, FormatCycloneDX15, sampleResult(), mode.ComponentInfo{
		Name:    "my-os",
		Version: "22.04",
		Type:    "operating-system",
	})
	if err != nil {
		t.Fatalf("Encode CycloneDX: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\nbody:\n%s", err, buf.String())
	}

	if v, _ := doc["bomFormat"].(string); v != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}

	meta, _ := doc["metadata"].(map[string]any)
	if meta == nil {
		t.Fatal("missing metadata")
	}
	comp, _ := meta["component"].(map[string]any)
	if comp == nil {
		t.Fatal("missing metadata.component")
	}
	if v, _ := comp["name"].(string); v != "my-os" {
		t.Errorf("component.name = %v, want my-os", comp["name"])
	}
	if v, _ := comp["type"].(string); v != "operating-system" {
		t.Errorf("component.type = %v, want operating-system", comp["type"])
	}

	if !strings.Contains(buf.String(), "testify") {
		t.Error("CycloneDX output missing testify")
	}
}

func TestEncode_UnknownFormat(t *testing.T) {
	err := Encode(&bytes.Buffer{}, Format("yaml"), sampleResult(), mode.ComponentInfo{})
	if err == nil {
		t.Fatal("want error for unknown format")
	}
}
