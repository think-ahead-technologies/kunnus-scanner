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

func TestEncode_HasCPE(t *testing.T) {
	var buf bytes.Buffer
	if err := Encode(&buf, sampleResult(), mode.ComponentInfo{Name: "x", Type: "application"}, nil); err != nil {
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
		t.Errorf("component cpe = %q, want %q", got, want)
	}
}

func TestEncode_CycloneDX(t *testing.T) {
	var buf bytes.Buffer
	err := Encode(&buf, sampleResult(), mode.ComponentInfo{
		Name:    "my-os",
		Version: "22.04",
		Type:    "operating-system",
	}, nil)
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
