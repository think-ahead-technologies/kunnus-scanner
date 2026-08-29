// ABOUTME: Tests the encoder's treatment of kernel packages: a module's backfilled
// ABOUTME: pkg:generic purl (set by internal/scan) yields no CPE; the image keeps CPE-only.
package sbom

import (
	"bytes"
	"encoding/json"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
)

func TestInjectCPEsCDX_KernelModuleWithPURLGetsNoCPE(t *testing.T) {
	// Once modules carry a backfilled pkg:generic purl, the CPE stage's PURL
	// heuristic would invent cpe:2.3:a:intel_oaktrail:intel_oaktrail — but an
	// in-tree module has no NVD identity (its CVEs are filed against the
	// kernel), so module packages are excluded from the heuristic.
	inv := inventory.Inventory{Packages: []*extractor.Package{{
		Name:     "intel_oaktrail",
		Version:  "0.4ac1",
		PURLType: "generic",
		Metadata: &modulemeta.Metadata{PackageName: "intel_oaktrail", PackageVersion: "0.4ac1"},
	}}}
	b := cyclonedx.NewBOM()
	b.Components = &[]cyclonedx.Component{{
		Name:       "intel_oaktrail",
		Version:    "0.4ac1",
		PackageURL: "pkg:generic/intel_oaktrail@0.4ac1",
	}}
	injectCPEsCDX(b, inv)
	if got := (*b.Components)[0].CPE; got != "" {
		t.Errorf("kernel module got CPE %q, want none", got)
	}
}

func TestEncode_KernelModuleGetsPURLNoCPE(t *testing.T) {
	// Through Encode with the post-scan inventory shape (internal/scan has
	// already backfilled the module's pkg:generic PURLType): the module lands
	// with a purl (CISA Component Identifiers requires at least one
	// machine-processable identifier) and still no CPE; the kernel image keeps
	// the inverse — CPE, no purl.
	inv := inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:     "intel_oaktrail",
			Version:  "0.4ac1",
			PURLType: "generic",
			Metadata: &modulemeta.Metadata{PackageName: "intel_oaktrail", PackageVersion: "0.4ac1"},
			Plugins:  []string{"os/kernel/module"},
		},
		{
			Name:     "Linux Kernel",
			Version:  "6.8.0-49-generic",
			Metadata: &vmlinuzmeta.Metadata{Name: "Linux Kernel", Version: "6.8.0-49-generic"},
			Plugins:  []string{"os/kernel/vmlinuz"},
		},
	}}

	var buf bytes.Buffer
	if err := Encode(&buf, Options{
		Inventory: inv,
		Component: bom.ComponentInfo{Name: "fw", Type: "firmware"},
	}); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var doc struct {
		Components []struct {
			Name string `json:"name"`
			PURL string `json:"purl"`
			CPE  string `json:"cpe"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var moduleSeen, imageSeen bool
	for _, c := range doc.Components {
		switch c.Name {
		case "intel_oaktrail":
			moduleSeen = true
			if c.PURL != "pkg:generic/intel_oaktrail@0.4ac1" {
				t.Errorf("module purl = %q, want pkg:generic/intel_oaktrail@0.4ac1", c.PURL)
			}
			if c.CPE != "" {
				t.Errorf("module cpe = %q, want none", c.CPE)
			}
		case "Linux Kernel":
			imageSeen = true
			if c.PURL != "" {
				t.Errorf("kernel image purl = %q, want none", c.PURL)
			}
			if c.CPE != "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*" {
				t.Errorf("kernel image cpe = %q, want the truncated NVD form", c.CPE)
			}
		}
	}
	if !moduleSeen || !imageSeen {
		t.Fatalf("module seen=%v image seen=%v, want both; body:\n%s", moduleSeen, imageSeen, buf.String())
	}
}
