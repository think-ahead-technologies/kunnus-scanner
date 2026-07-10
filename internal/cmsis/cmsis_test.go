// ABOUTME: Tests for the CMSIS extractor: real-fixture extraction over scalibr's walk plus unit tests for pack-spec parsing.
// ABOUTME: The fixture is a realistic csolution file with versioned, range-versioned, versionless, local-path and wildcard packs.
package cmsis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"
)

// csolution is a real-shaped *.csolution.yml: pinned packs, a range
// constraint, a versionless pack, a local development pack (path:) that must
// be dropped, and a wildcard selection that names no single component.
const csolution = `solution:
  created-for: cmsis-toolbox@2.4.0
  cdefault:

  packs:
    - pack: ARM::CMSIS@5.9.0
    - pack: ARM::CMSIS-Driver@^2.8.0
    - pack: Keil::STM32F4xx_DFP@2.17.1
    - pack: Keil::ARM_Compiler
    - pack: MyVendor::LocalPack
      path: ./local-pack
    - pack: NXP::*

  target-types:
    - type: debug
      board: NUCLEO-F401RE

  projects:
    - project: ./app/app.cproject.yml
`

// TestExtract runs the extractor through scalibr's real filesystem walk,
// asserting pack specs surface as vendor-namespaced generic packages with
// their constraints verbatim, and that local-path and wildcard packs are
// dropped. A decoy cproject proves the FileRequired gate.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "ws", "app.csolution.yml"), csolution)
	writeFile(t, filepath.Join(root, "ws", "app", "app.cproject.yml"),
		"project:\n  packs:\n    - pack: Decoy::ShouldNotAppear@1.0.0\n")

	inv := run(t, root)

	want := map[string]string{ // name -> version
		"ARM/CMSIS":          "5.9.0",
		"ARM/CMSIS-Driver":   "^2.8.0",
		"Keil/STM32F4xx_DFP": "2.17.1",
		"Keil/ARM_Compiler":  "",
	}
	got := map[string]string{}
	for _, p := range inv.Packages {
		if strings.Contains(p.Name, "ShouldNotAppear") {
			t.Errorf("decoy cproject was parsed: %+v", p)
		}
		if strings.Contains(p.Name, "LocalPack") {
			t.Errorf("local path pack was emitted: %+v", p)
		}
		if strings.Contains(p.Name, "*") {
			t.Errorf("wildcard pack was emitted: %+v", p)
		}
		if p.PURLType != "generic" {
			t.Errorf("package %q has PURLType %q, want generic", p.Name, p.PURLType)
		}
		got[p.Name] = p.Version
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages %v, want %d", len(got), got, len(want))
	}
	for name, ver := range want {
		gotVer, ok := got[name]
		if !ok {
			t.Errorf("package %q missing (all: %v)", name, got)
			continue
		}
		if gotVer != ver {
			t.Errorf("package %q version = %q, want %q", name, gotVer, ver)
		}
	}
}

// TestParsePackSpec covers the pack-spec grammar directly: the
// Vendor::Pack[@constraint] form and the malformed specs that must drop.
func TestParsePackSpec(t *testing.T) {
	cases := []struct {
		name     string
		spec     string
		wantName string // "" = expect no package
		wantVer  string
	}{
		{"pinned", "ARM::CMSIS@5.9.0", "ARM/CMSIS", "5.9.0"},
		{"caret range", "ARM::CMSIS-Driver@^2.8.0", "ARM/CMSIS-Driver", "^2.8.0"},
		{"gte range", "Keil::STM32F4xx_DFP@>=2.0.0", "Keil/STM32F4xx_DFP", ">=2.0.0"},
		{"versionless", "Keil::ARM_Compiler", "Keil/ARM_Compiler", ""},
		{"whitespace tolerated", "  ARM::CMSIS @ 5.9.0 ", "ARM/CMSIS", "5.9.0"},
		{"vendor wildcard dropped", "NXP::*", "", ""},
		{"pack wildcard dropped", "ARM::CMSIS*", "", ""},
		{"no vendor separator", "JustAName@1.0", "", ""},
		{"empty vendor", "::Pack@1.0", "", ""},
		{"empty pack", "ARM::@1.0", "", ""},
		{"slash in vendor dropped", "A/B::Pack@1.0", "", ""},
		{"empty", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := parsePackSpec(tc.spec)
			if tc.wantName == "" {
				if p != nil {
					t.Fatalf("parsePackSpec(%q) = %+v, want nil", tc.spec, p)
				}
				return
			}
			if p == nil || p.name != tc.wantName || p.version != tc.wantVer {
				t.Fatalf("parsePackSpec(%q) = %+v, want %s@%s", tc.spec, p, tc.wantName, tc.wantVer)
			}
		})
	}
}

func run(t *testing.T, root string) inventory.Inventory {
	t.Helper()
	inv, _, err := filesystem.Run(context.Background(), &filesystem.Config{
		Extractors: []filesystem.Extractor{New()},
		ScanRoots:  scalibrfs.RealFSScanRoots(root),
		Stats:      stats.NoopCollector{},
	})
	if err != nil {
		t.Fatalf("filesystem.Run: %v", err)
	}
	return inv
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
