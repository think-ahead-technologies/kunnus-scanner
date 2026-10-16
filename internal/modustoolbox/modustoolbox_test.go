// ABOUTME: Tests for the ModusToolbox extractor: real-fixture extraction over scalibr's walk plus unit tests for .mtb line parsing.
// ABOUTME: Fixtures are real .mtb lines from an Infineon PSE84 firmware tree, so PURL generation is exercised end to end.
package modustoolbox

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

// TestExtract runs the extractor through scalibr's real filesystem walk over a
// tree of .mtb files drawn from a real ModusToolbox firmware project, asserting
// each surfaces a pkg:github package at the verbatim git ref. A decoy proves the
// FileRequired gate: a .mtbqueryapi file must not be parsed.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	// libs/*.mtb and deps/*.mtb both carry the "<url>#<ref>#<storage>" line.
	writeFile(t, filepath.Join(root, "proj", "libs", "cmsis.mtb"),
		"https://github.com/Infineon/cmsis#release-v6.1.0#$$ASSET_REPO$$/cmsis/release-v6.1.0\n")
	writeFile(t, filepath.Join(root, "proj", "libs", "device-db.mtb"),
		"https://github.com/Infineon/device-db#release-v4.37.0#$$GLOBAL$$/device-db/release-v4.37.0\n")
	writeFile(t, filepath.Join(root, "proj", "libs", "lwip.mtb"),
		"https://github.com/lwip-tcpip/lwip#STABLE-2_1_2_RELEASE#$$ASSET_REPO$$/lwip/STABLE-2_1_2_RELEASE\n")
	writeFile(t, filepath.Join(root, "proj", "libs", "BMI270_SensorAPI.mtb"),
		"https://github.com/BoschSensortec/BMI270_SensorAPI#v2.86.1#$$ASSET_REPO$$/BMI270_SensorAPI/v2.86.1\n")
	// Decoy: matches no .mtb suffix (ends in .mtbqueryapi), must be ignored.
	writeFile(t, filepath.Join(root, "proj", ".mtbqueryapi"),
		"https://github.com/Infineon/should-not-appear#release-v9.9.9#x\n")

	inv := run(t, root)

	// Asserted on the structured fields (PURLType + namespaced Name + Version),
	// not the rendered purl string: scalibr's String() escapes the "/" to %2F and
	// preserves case; the conventional "pkg:github/owner/repo" form is produced
	// only by the sbom encode pipeline and is covered there by want.txt fixtures.
	want := map[string]string{ // name -> version
		"Infineon/cmsis":                  "release-v6.1.0",
		"Infineon/device-db":              "release-v4.37.0",
		"lwip-tcpip/lwip":                 "STABLE-2_1_2_RELEASE",
		"BoschSensortec/BMI270_SensorAPI": "v2.86.1",
	}

	got := map[string]string{}
	for _, p := range inv.Packages {
		if p.Name == "Infineon/should-not-appear" {
			t.Errorf("decoy .mtbqueryapi was parsed: %+v", p)
		}
		if p.PURLType != "github" {
			t.Errorf("package %q has PURLType %q, want github", p.Name, p.PURLType)
		}
		got[p.Name] = p.Version
	}
	for name, ver := range want {
		if got[name] != ver {
			t.Errorf("package %q version = %q, want %q (all: %v)", name, got[name], ver, got)
		}
	}
}

// TestParseLine covers the line grammar directly: the three variants of git ref,
// both storage prefixes, and the malformed/non-github cases that must be dropped.
func TestParseLine(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantName string // "owner/repo", empty means "expect no package"
		wantVer  string
	}{
		{"release tag", "https://github.com/Infineon/cmsis#release-v6.1.0#$$ASSET_REPO$$/cmsis/release-v6.1.0", "Infineon/cmsis", "release-v6.1.0"},
		{"global storage", "https://github.com/Infineon/device-db#release-v4.37.0#$$GLOBAL$$/device-db/release-v4.37.0", "Infineon/device-db", "release-v4.37.0"},
		{"stable ref", "https://github.com/lwip-tcpip/lwip#STABLE-2_1_2_RELEASE#x", "lwip-tcpip/lwip", "STABLE-2_1_2_RELEASE"},
		{"plain v tag", "https://github.com/BoschSensortec/BMI270_SensorAPI#v2.86.1#x", "BoschSensortec/BMI270_SensorAPI", "v2.86.1"},
		{"trailing .git", "https://github.com/Infineon/cmsis.git#release-v6.1.0#x", "Infineon/cmsis", "release-v6.1.0"},
		{"crlf and spaces", "  https://github.com/Infineon/cmsis#release-v6.1.0#x  \r\n", "Infineon/cmsis", "release-v6.1.0"},
		{"non-github host", "https://gitlab.com/foo/bar#v1.0.0#x", "", ""},
		{"no ref segment", "https://github.com/Infineon/cmsis", "", ""},
		{"empty ref", "https://github.com/Infineon/cmsis##x", "", ""},
		{"not a url", "garbage line", "", ""},
		{"missing repo", "https://github.com/Infineon#release-v1.0.0#x", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := parseLine(tc.line)
			if tc.wantName == "" {
				if ref != nil {
					t.Fatalf("parseLine(%q) = %+v, want nil", tc.line, ref)
				}
				return
			}
			if ref == nil {
				t.Fatalf("parseLine(%q) = nil, want %s@%s", tc.line, tc.wantName, tc.wantVer)
			}
			if ref.name != tc.wantName || ref.version != tc.wantVer {
				t.Errorf("parseLine(%q) = %s@%s, want %s@%s", tc.line, ref.name, ref.version, tc.wantName, tc.wantVer)
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

// A .mtb whose line runs past maxLineBytes was not understood, it was cut off.
// Extract returns an error for that (unlike a malformed manifest, which yields
// no package and no error) so scalibr records a plugin status instead of the
// file reading as "declares no dependency".
func TestExtract_TruncatedManifestIsReported(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "huge.mtb"), strings.Repeat("x", maxLineBytes+1)+"\n")

	f, err := os.Open(filepath.Join(root, "huge.mtb"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inv, err := New().Extract(context.Background(), &filesystem.ScanInput{Path: "huge.mtb", Reader: f})

	if err == nil {
		t.Fatal("Extract: want an error for a manifest past maxLineBytes, got nil")
	}
	if len(inv.Packages) != 0 {
		t.Errorf("Extract returned %d packages for a truncated manifest, want 0", len(inv.Packages))
	}
}
