// ABOUTME: End-to-end CLI tests. Builds the kunnus binary once, then exercises subcommands.
// ABOUTME: Real binary, real flags, real I/O — closest thing to a user running it locally.
package main_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// kunnusBin holds the path to the built kunnus binary, populated once by TestMain.
var kunnusBin string

func TestMain(m *testing.M) {
	bin, err := buildBinary()
	if err != nil {
		_, _ = os.Stderr.WriteString("build kunnus: " + err.Error() + "\n")
		os.Exit(1)
	}
	kunnusBin = bin
	code := m.Run()
	_ = os.Remove(kunnusBin)
	os.Exit(code)
}

func buildBinary() (string, error) {
	dir, err := os.MkdirTemp("", "kunnus-bin-")
	if err != nil {
		return "", err
	}
	out := filepath.Join(dir, "kunnus")
	if runtime.GOOS == "windows" {
		// Windows refuses to exec a file without a recognised executable
		// extension, so build (and later run) kunnus.exe rather than kunnus.
		out += ".exe"
	}
	args := []string{"build", "-o", out}
	if testing.CoverMode() != "" {
		// When the test run collects coverage, instrument the binary so the
		// subprocess e2e exercises count toward the profile. -coverpkg spans the
		// whole module because the command/ and mode/ wiring is reachable only
		// through the binary — without this it shows as 0% despite being driven
		// end-to-end here. Subprocess counters merge via GOCOVERDIR (see
		// subprocessCoverDir). Builds without coverage stay uninstrumented.
		args = append(args, "-cover", "-coverpkg=github.com/think-ahead/kunnus-scanner/...")
	}
	args = append(args, "github.com/think-ahead/kunnus-scanner/cmd/kunnus")
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out, nil
}

// subprocessCoverDir returns the directory an instrumented kunnus binary should
// write its coverage data to, or "" when this run has no coverage enabled. When
// enabled it returns the same directory `go test` uses for its own coverage
// (passed as -test.gocoverdir), so the subprocess counters land in one place and
// merge into the final profile. Call only after flags are parsed — i.e. from a
// test, not from TestMain before m.Run.
func subprocessCoverDir() string {
	if testing.CoverMode() == "" {
		return ""
	}
	if f := flag.Lookup("test.gocoverdir"); f != nil {
		if dir := f.Value.String(); dir != "" {
			return dir
		}
	}
	return os.Getenv("GOCOVERDIR")
}

// withCoverEnv points cmd at the shared coverage directory via GOCOVERDIR when
// coverage is enabled, so the instrumented binary records its counters. A no-op
// otherwise. Preserves any environment the caller already set.
func withCoverEnv(cmd *exec.Cmd) {
	dir := subprocessCoverDir()
	if dir == "" {
		return
	}
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, "GOCOVERDIR="+dir)
}

func runKunnus(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, kunnusBin, args...)
	withCoverEnv(cmd)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return out.String(), errBuf.String(), err
}

func TestCLI_Help(t *testing.T) {
	stdout, _, err := runKunnus(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	for _, want := range []string{"sbom", "upload", "kunnus"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--help output missing %q\n%s", want, stdout)
		}
	}
}

func TestCLI_SBOM_Repo_GoMod(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.com/x\n\ngo 1.21\n\nrequire github.com/stretchr/testify v1.8.0\n")
	outPath := filepath.Join(t.TempDir(), "sbom.json")

	stdout, stderr, err := runKunnus(t,
		"sbom", "repo",
		"--output", outPath,
		root,
	)
	if err != nil {
		t.Fatalf("sbom repo failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, data)
	}
	if v, _ := doc["bomFormat"].(string); v != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	if !strings.Contains(string(data), "testify") {
		t.Error("SBOM missing testify dependency")
	}

	// Repo scans read source code, so the CISA generation context is pre-build.
	if !strings.Contains(string(data), `"phase": "pre-build"`) {
		t.Error("SBOM missing pre-build lifecycle phase (metadata.lifecycles)")
	}

	// Both scanners are recorded under metadata.tools. The SCALIBR entry must
	// carry the linked module version, read from the real binary's build info —
	// only a `go build` binary embeds it, so this is the one place the backfill
	// can be proven end to end.
	var toolDoc struct {
		Metadata struct {
			Tools struct {
				Components []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"components"`
			} `json:"tools"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &toolDoc); err != nil {
		t.Fatalf("unmarshal tools: %v", err)
	}
	scalibrSeen, kunnusSeen := false, false
	for _, tool := range toolDoc.Metadata.Tools.Components {
		switch tool.Name {
		case "SCALIBR":
			scalibrSeen = true
			if !strings.HasPrefix(tool.Version, "v") {
				t.Errorf("SCALIBR tool version = %q, want the linked osv-scalibr module version", tool.Version)
			}
		case "kunnus":
			kunnusSeen = true
		}
	}
	if !scalibrSeen {
		t.Error("no SCALIBR entry in metadata.tools.components")
	}
	if !kunnusSeen {
		t.Errorf("metadata.tools.components = %+v, want kunnus listed", toolDoc.Metadata.Tools.Components)
	}
}

func TestCLI_SBOM_Repo_SerialNumberSeries(t *testing.T) {
	// A supplied component identity must yield the same serialNumber across
	// runs (the CISA "relationship to earlier iterations" requirement), with
	// the document version derived from the generation timestamp so series
	// members stay strictly ordered.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"),
		"module example.com/x\n\ngo 1.21\n\nrequire github.com/stretchr/testify v1.8.0\n")

	generate := func(extra ...string) map[string]any {
		t.Helper()
		outPath := filepath.Join(t.TempDir(), "sbom.json")
		args := append([]string{"sbom", "repo", "--output", outPath}, extra...)
		args = append(args, root)
		stdout, stderr, err := runKunnus(t, args...)
		if err != nil {
			t.Fatalf("sbom repo failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("read sbom: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("sbom is not valid JSON: %v\n%s", err, data)
		}
		return doc
	}

	idFlags := []string{"--component-id", "acme/widget", "--component-version", "1.2.3"}
	first := generate(idFlags...)
	second := generate(idFlags...)

	serial, _ := first["serialNumber"].(string)
	if serial == "" || !strings.HasPrefix(serial, "urn:uuid:") {
		t.Fatalf("serialNumber = %q, want urn:uuid form", serial)
	}
	if serial != second["serialNumber"] {
		t.Errorf("serialNumber not stable across runs: %q vs %v", serial, second["serialNumber"])
	}
	if v, _ := first["version"].(float64); v <= 1 {
		t.Errorf("version = %v, want timestamp-derived (> 1)", first["version"])
	}

	// --component-version must land on the root component, not just the key.
	meta, _ := first["metadata"].(map[string]any)
	comp, _ := meta["component"].(map[string]any)
	if v, _ := comp["version"].(string); v != "1.2.3" {
		t.Errorf("metadata.component.version = %q, want 1.2.3", v)
	}

	// A different identity is a different series.
	other := generate("--component-id", "acme/gadget", "--component-version", "1.2.3")
	if other["serialNumber"] == serial {
		t.Error("different component-id produced the same serialNumber")
	}

	// An explicit serial number wins over derivation.
	pinned := generate(append(idFlags, "--serial-number", "b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7")...)
	if got, _ := pinned["serialNumber"].(string); got != "urn:uuid:b3c5bd21-1e46-4a44-9b62-8dcbcafb54b7" {
		t.Errorf("serialNumber = %q, want pinned urn:uuid:b3c5bd21-...", got)
	}

	// Without any identity, each run gets a fresh random serial and version 1.
	anonA := generate()
	anonB := generate()
	if anonA["serialNumber"] == anonB["serialNumber"] {
		t.Errorf("no-identity serials must differ per run, got %v twice", anonA["serialNumber"])
	}
	if v, _ := anonA["version"].(float64); v != 1 {
		t.Errorf("no-identity version = %v, want 1", anonA["version"])
	}
}

func TestCLI_SBOM_Repo_InvalidSerialFailsBeforeScan(t *testing.T) {
	// A malformed --serial-number must fail fast, before the (potentially
	// expensive) scan runs.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")

	_, stderr, err := runKunnus(t, "sbom", "repo", "--serial-number", "not-a-uuid", root)
	if err == nil {
		t.Fatal("want error for invalid --serial-number")
	}
	if !strings.Contains(stderr, "serial") {
		t.Errorf("stderr missing serial-number error: %s", stderr)
	}
}

func TestCLI_SBOM_Repo_AuthorFlag(t *testing.T) {
	// --author records the entity operating the scanner as the SBOM author
	// (CISA's SBOM Author element).
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")

	stdout, stderr, err := runKunnus(t,
		"sbom", "repo",
		"--author", "ACME GmbH <psirt@acme.example>",
		root,
	)
	if err != nil {
		t.Fatalf("sbom repo --author failed: %v\nstderr:\n%s", err, stderr)
	}
	var doc struct {
		Metadata struct {
			Authors      []struct{ Name, Email string }
			Manufacturer struct{ Name string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	if len(doc.Metadata.Authors) != 1 || doc.Metadata.Authors[0].Name != "ACME GmbH" || doc.Metadata.Authors[0].Email != "psirt@acme.example" {
		t.Errorf("metadata.authors = %+v, want ACME GmbH <psirt@acme.example>", doc.Metadata.Authors)
	}
	if doc.Metadata.Manufacturer.Name != "ACME GmbH" {
		t.Errorf("metadata.manufacturer.name = %q, want ACME GmbH", doc.Metadata.Manufacturer.Name)
	}
	// An explicit author is what the operator intended — no warning.
	if strings.Contains(stderr, "--author") {
		t.Errorf("unexpected author warning with --author set:\n%s", stderr)
	}
}

func TestCLI_SBOM_Repo_AuthorDefaultWarns(t *testing.T) {
	// Without --author the document records the kunnus identity as SBOM
	// author — correct only when think-ahead itself operates the scan. Warn
	// so other operators know they are shipping a placeholder author.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")

	stdout, stderr, err := runKunnus(t, "sbom", "repo", root)
	if err != nil {
		t.Fatalf("sbom repo failed: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "--author") {
		t.Errorf("stderr missing the default-author warning:\n%s", stderr)
	}
	var doc struct {
		Metadata struct {
			Authors []struct{ Name string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	if len(doc.Metadata.Authors) != 1 || doc.Metadata.Authors[0].Name != "Kunnus" {
		t.Errorf("metadata.authors = %+v, want the Kunnus default", doc.Metadata.Authors)
	}
}

func TestCLI_SBOM_Repo_InvalidAuthorFails(t *testing.T) {
	// Like --serial-number: a malformed --author is rejected with a message
	// naming the flag, instead of silently producing an SBOM.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")

	_, stderr, err := runKunnus(t, "sbom", "repo", "--author", "<psirt@acme.example>", root)
	if err == nil {
		t.Fatal("want error for invalid --author")
	}
	if !strings.Contains(stderr, "author") {
		t.Errorf("stderr missing author error: %s", stderr)
	}
}

func TestCLI_SBOM_Repo_VendoredOnly(t *testing.T) {
	// A vendored-only C/C++ repo (no Conan lockfile, no other manifest) must
	// produce a valid SBOM containing the vendored library as a component.
	// This exercises the full Plan → scan.Run (with zero scalibr plugins) →
	// sbom.Encode path; the unit tests cover each leg individually.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "third_party", "zlib", "deflate.c"), "// vendored\n")
	writeFile(t, filepath.Join(root, "third_party", "zlib", "zlib.h"), "// header\n")
	outPath := filepath.Join(t.TempDir(), "sbom.json")

	stdout, stderr, err := runKunnus(t,
		"sbom", "repo",
		"--output", outPath,
		root,
	)
	if err != nil {
		t.Fatalf("sbom repo failed on vendored-only tree: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v\n%s", err, data)
	}
	if v, _ := doc["bomFormat"].(string); v != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", v)
	}
	// The vendored component must appear with its generic PURL.
	if !strings.Contains(string(data), "pkg:generic/zlib?vendored_path=third_party/zlib") {
		t.Errorf("SBOM missing vendored zlib component; output:\n%s", data)
	}
	// And the per-file properties must be there so the platform can match.
	if !strings.Contains(string(data), "kunnus:vendored:file") {
		t.Error("SBOM missing kunnus:vendored:file properties")
	}
	// A vendored copy has no version, producer, or licence — CISA's
	// "explicitly identify unknown information" markers must say so.
	for _, marker := range []string{"kunnus:unknown:version", "kunnus:unknown:producer", "kunnus:unknown:license"} {
		if !strings.Contains(string(data), marker) {
			t.Errorf("SBOM missing %s marker on the vendored component", marker)
		}
	}
}

func TestCLI_SBOM_Repo_EmptyTreeFails(t *testing.T) {
	root := t.TempDir() // no manifests
	_, stderr, err := runKunnus(t, "sbom", "repo", root)
	if err == nil {
		t.Fatal("want error for empty tree, got nil")
	}
	if !strings.Contains(stderr, "no extractors") {
		t.Errorf("stderr missing expected error message: %s", stderr)
	}
}

func TestCLI_SBOM_Repo_AllEcosystems(t *testing.T) {
	// Kitchen-sink e2e: every ecosystem fixture in the shared corpus is dropped
	// into one scan root, so this exercises multi-ecosystem auto-detection, the
	// merged digest map, dedup, and the real CLI wiring in a single binary run.
	// Per-ecosystem extraction is covered faster at the scan seam; this proves
	// they all coexist in one SBOM.
	corpus := corpusDir(t)
	root := t.TempDir()
	copyTree(t, corpus, root)

	outPath := filepath.Join(t.TempDir(), "sbom.json")
	stdout, stderr, err := runKunnus(t, "sbom", "repo", "--output", outPath, root)
	if err != nil {
		t.Fatalf("sbom repo on all-ecosystems tree failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []struct {
			PURL     string `json:"purl"`
			CPE      string `json:"cpe"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
				Expression string `json:"expression"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}

	purls := make(map[string]bool)
	cpes := make(map[string]bool)
	licenses := make(map[string]bool)
	for _, c := range doc.Components {
		if c.PURL != "" {
			purls[c.PURL] = true
		}
		if c.CPE != "" {
			cpes[c.CPE] = true
		}
		for _, l := range c.Licenses {
			if l.License.ID != "" {
				licenses[l.License.ID] = true
			}
			if l.License.Name != "" {
				licenses[l.License.Name] = true
			}
			if l.Expression != "" {
				licenses[l.Expression] = true
			}
		}
	}

	entries, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		w := readWants(t, filepath.Join(corpus, e.Name()))
		for _, p := range w.purls {
			if !purls[p] {
				t.Errorf("ecosystem %q: expected purl %q missing from combined SBOM", e.Name(), p)
			}
		}
		for _, c := range w.cpes {
			if !cpes[c] {
				t.Errorf("ecosystem %q: expected cpe %q missing from combined SBOM", e.Name(), c)
			}
		}
		for _, l := range w.licenses {
			if !licenses[l] {
				t.Errorf("ecosystem %q: expected licence %q missing from combined SBOM", e.Name(), l)
			}
		}
	}
}

func TestCLI_SBOM_OS_Linux(t *testing.T) {
	// Binary e2e for OS-package scans: run the built CLI against each fixtured
	// Linux family root with --target-os linux, and assert the exact purl + cpe
	// each package DB produces. Cross-host: --target-os forces linux plugin
	// selection regardless of the test host. Families that cannot be fixtured
	// in-tree (rpm-based, etc.) are covered/skipped at the scan-seam tier.
	osCorpus := filepath.Join(moduleRoot(t), "testdata", "osfamilies")
	entries, err := os.ReadDir(osCorpus)
	if err != nil {
		t.Fatalf("read osfamilies corpus: %v", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			famDir := filepath.Join(osCorpus, e.Name())
			outPath := filepath.Join(t.TempDir(), "sbom.json")
			stdout, stderr, err := runKunnus(t,
				"sbom", "os", "--target-os", "linux", "--output", outPath, famDir)
			if err != nil {
				t.Fatalf("sbom os failed for %q: %v\nstdout:\n%s\nstderr:\n%s", e.Name(), err, stdout, stderr)
			}

			data, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("read sbom: %v", err)
			}
			var doc struct {
				BOMFormat  string `json:"bomFormat"`
				Components []struct {
					Name     string `json:"name"`
					Version  string `json:"version"`
					PURL     string `json:"purl"`
					CPE      string `json:"cpe"`
					Licenses []struct {
						License struct {
							ID   string `json:"id"`
							Name string `json:"name"`
						} `json:"license"`
						Expression string `json:"expression"`
					} `json:"licenses"`
				} `json:"components"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatalf("sbom is not valid JSON: %v", err)
			}
			if doc.BOMFormat != "CycloneDX" {
				t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
			}

			purls := make(map[string]bool)
			cpes := make(map[string]bool)
			licenses := make(map[string]bool)
			pkgs := make(map[string]bool)
			for _, c := range doc.Components {
				pkgs[c.Name+"@"+c.Version] = true
				if c.PURL != "" {
					purls[c.PURL] = true
				}
				if c.CPE != "" {
					cpes[c.CPE] = true
				}
				for _, l := range c.Licenses {
					if l.License.ID != "" {
						licenses[l.License.ID] = true
					}
					if l.License.Name != "" {
						licenses[l.License.Name] = true
					}
					if l.Expression != "" {
						licenses[l.Expression] = true
					}
				}
			}

			w := readWants(t, famDir)
			for _, p := range w.purls {
				if !purls[p] {
					t.Errorf("family %q: expected purl %q missing from SBOM", e.Name(), p)
				}
			}
			for _, c := range w.cpes {
				if !cpes[c] {
					t.Errorf("family %q: expected cpe %q missing from SBOM", e.Name(), c)
				}
			}
			for _, l := range w.licenses {
				if !licenses[l] {
					t.Errorf("family %q: expected license %q missing from SBOM", e.Name(), l)
				}
			}
			// name@version expectations, for components that carry no purl
			// (the kernel extractors set no PURLType).
			for _, p := range w.pkgs {
				if !pkgs[p] {
					t.Errorf("family %q: expected component %q missing from SBOM", e.Name(), p)
				}
			}
		})
	}
}

// TestCLI_SBOM_OS_NonPackagedBinary is the binary e2e for the binclass path:
// an OS scan over a root holding a real non-packaged binary (the libpython
// fixture — actual python:latest bytes) must surface it as pkg:generic with
// the classifier catalog's curated CPE and the second catalog template as a
// kunnus:cpe alias property. The python_software_foundation vendor proves the
// template path end to end: the PURL heuristic would say a:python:python.
//
// The root is assembled in a temp dir from the alpine fixture (os-release +
// apk db, so this is a realistic OS scan whose apk packages own nothing under
// usr/local — overlap suppression must keep the binary) plus the libpython
// fixture. It is deliberately NOT part of testdata/osfamilies/alpine: the BSI
// conformance gate scores that tree, and a non-packaged binary carries no
// licence, which would drag the required-elements score below the threshold.
func TestCLI_SBOM_OS_NonPackagedBinary(t *testing.T) {
	root := t.TempDir()
	alpine := filepath.Join(moduleRoot(t), "testdata", "osfamilies", "alpine")
	binclassFixtures := filepath.Join(moduleRoot(t), "internal", "binclass", "testdata")
	copyFixture(t, filepath.Join(alpine, "etc", "os-release"), filepath.Join(root, "etc", "os-release"))
	copyFixture(t, filepath.Join(alpine, "lib", "apk", "db", "installed"), filepath.Join(root, "lib", "apk", "db", "installed"))
	copyFixture(t, filepath.Join(binclassFixtures, "libpython3.14.so"), filepath.Join(root, "usr", "local", "lib", "libpython3.14.so"))

	outPath := filepath.Join(t.TempDir(), "sbom.json")
	stdout, stderr, err := runKunnus(t,
		"sbom", "os", "--target-os", "linux", "--output", outPath, root)
	if err != nil {
		t.Fatalf("sbom os failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc struct {
		Components []struct {
			PURL       string `json:"purl"`
			CPE        string `json:"cpe"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}

	const wantPURL = "pkg:generic/python@3.14.5"
	const wantCPE = "cpe:2.3:a:python_software_foundation:python:3.14.5:*:*:*:*:*:*:*"
	const wantAlias = "cpe:2.3:a:python:python:3.14.5:*:*:*:*:*:*:*"
	found := false
	for _, c := range doc.Components {
		if c.PURL != wantPURL {
			continue
		}
		found = true
		if c.CPE != wantCPE {
			t.Errorf("python cpe = %q, want curated %q", c.CPE, wantCPE)
		}
		hasAlias := false
		for _, p := range c.Properties {
			if p.Name == "kunnus:cpe" && p.Value == wantAlias {
				hasAlias = true
			}
		}
		if !hasAlias {
			t.Errorf("python component lacks kunnus:cpe alias %q; properties=%+v", wantAlias, c.Properties)
		}
	}
	if !found {
		t.Errorf("component %q missing from SBOM", wantPURL)
	}
}

// copyFixture copies a fixture file into a scan-root under construction,
// creating parent directories.
func copyFixture(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCLI_SBOM_Repo_OnlineLicenses exercises the real deps.dev licence
// enrichment over the ecosystem corpus. Offline, a repo scan yields no licences
// for these language ecosystems; with --online-licenses, deps.dev must populate
// at least some.
//
// It is network-gated twice over: it runs only when KUNNUS_ONLINE_E2E is set
// (so CI stays deterministically green without depending on deps.dev uptime),
// and additionally skips if deps.dev is unreachable. This mirrors the
// documented network-only paths (registry pull, local docker).
func TestCLI_SBOM_Repo_OnlineLicenses(t *testing.T) {
	if os.Getenv("KUNNUS_ONLINE_E2E") == "" {
		t.Skip("set KUNNUS_ONLINE_E2E=1 to run the online deps.dev licence e2e")
	}
	if c, err := net.DialTimeout("tcp", "api.deps.dev:443", 5*time.Second); err != nil {
		t.Skipf("deps.dev unreachable: %v", err)
	} else {
		_ = c.Close()
	}

	out := filepath.Join(t.TempDir(), "sbom.json")
	_, stderr, runErr := runKunnus(t, "sbom", "repo", "--online-licenses", "--output", out, corpusDir(t))

	// The SBOM is written even if some lookups fail (partial failure still
	// produces output), so assert on the file rather than the exit code.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no SBOM produced (run err=%v):\n%s", runErr, stderr)
	}
	var doc struct {
		Components []struct {
			PURL     string `json:"purl"`
			Licenses []any  `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom not valid JSON: %v", err)
	}
	licensed := 0
	for _, c := range doc.Components {
		if len(c.Licenses) > 0 {
			licensed++
		}
	}
	if licensed == 0 {
		t.Errorf("online enrichment produced no licences; want >0\nstderr:\n%s", stderr)
	}
	t.Logf("online licence enrichment: %d/%d components licensed", licensed, len(doc.Components))
}

// corpusDir resolves <module-root>/testdata/ecosystems. The corpus is shared
// with the scan-seam tier.
func corpusDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(moduleRoot(t), "testdata", "ecosystems")
}

// moduleRoot walks up to the directory containing go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (go.mod)")
		}
		dir = parent
	}
}

// wants holds the expected purls, cpes, and licenses declared in a fixture's
// want.txt. pkgs holds "name@version" expectations for components that carry
// no purl (scalibr's kernel extractors set no PURLType).
type wants struct {
	purls    []string
	cpes     []string
	licenses []string
	pkgs     []string
}

// readWants parses dir/want.txt. Each non-blank, non-comment line is
// "<kind> <value>" where kind is "purl", "cpe", "license", or "pkg".
func readWants(t *testing.T, dir string) wants {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "want.txt"))
	if err != nil {
		t.Fatalf("read want.txt in %s: %v", dir, err)
	}
	var w wants
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kind, value, found := strings.Cut(line, " ")
		value = strings.TrimSpace(value)
		if !found || value == "" {
			t.Fatalf("malformed want.txt line in %s: %q", dir, line)
		}
		switch kind {
		case "purl":
			w.purls = append(w.purls, value)
		case "cpe":
			w.cpes = append(w.cpes, value)
		case "license":
			w.licenses = append(w.licenses, value)
		case "pkg":
			w.pkgs = append(w.pkgs, value)
		default:
			t.Fatalf("unknown want.txt kind %q in %s", kind, dir)
		}
	}
	return w
}

// copyTree recursively copies the directory at src into dst, preserving the
// relative layout (the luarocks fixture depends on its rocks-X.Y/ tree).
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copy corpus tree: %v", err)
	}
}

func TestCLI_Upload_RoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer e2e-key" {
			t.Errorf("Authorization = %q", got)
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
		}
		f, _, ferr := r.FormFile("sbom")
		if ferr != nil {
			t.Errorf("FormFile: %v", ferr)
		} else {
			defer func() { _ = f.Close() }()
			_, _ = io.Copy(io.Discard, f)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sbom := filepath.Join(t.TempDir(), "sbom.json")
	writeFile(t, sbom, `{"format":"spdx"}`)

	stdout, stderr, err := runKunnus(t,
		"upload",
		"--url", srv.URL,
		"--api-key", "e2e-key",
		"--component-id", "e2e-comp",
		sbom,
	)
	if err != nil {
		t.Fatalf("upload: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, `"ok":true`) {
		t.Errorf("stdout missing server response: %s", stdout)
	}
}

func TestCLI_Upload_ServerErrorDoesNotLeakBodyByDefault(t *testing.T) {
	// On a non-2xx response, the default-verbosity stderr must carry only the
	// status line — never the server response body. Operators wanting the body
	// can re-run with --verbosity info, which is exercised by the sibling test
	// below. This is the safety net that keeps echoed headers / secrets out of
	// CI logs and monitoring scrapers.
	const sensitive = "MARKER-bearer-echo-do-not-leak"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"echo":"` + sensitive + `"}`))
	}))
	defer srv.Close()

	sbom := filepath.Join(t.TempDir(), "sbom.json")
	writeFile(t, sbom, "{}")

	_, stderr, err := runKunnus(t,
		"upload",
		"--url", srv.URL,
		"--api-key", "k",
		sbom,
	)
	if err == nil {
		t.Fatal("want non-zero exit on 401 response")
	}
	if strings.Contains(stderr, sensitive) {
		t.Errorf("stderr must not contain server body at default verbosity\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "401") {
		t.Errorf("stderr should mention status code, got:\n%s", stderr)
	}
}

func TestCLI_Upload_ServerErrorShowsBodyAtInfoVerbosity(t *testing.T) {
	// At --verbosity info the user opts in to seeing the server's response.
	// This is the troubleshooting path; the safety guarantee from the sibling
	// test (no body leak by default) is intentionally what protects users who
	// don't crank the verbosity.
	const detail = "invalid component_id"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"` + detail + `"}`))
	}))
	defer srv.Close()

	sbom := filepath.Join(t.TempDir(), "sbom.json")
	writeFile(t, sbom, "{}")

	_, stderr, err := runKunnus(t,
		"--verbosity", "info",
		"upload",
		"--url", srv.URL,
		"--api-key", "k",
		sbom,
	)
	if err == nil {
		t.Fatal("want non-zero exit on 400 response")
	}
	if !strings.Contains(stderr, detail) {
		t.Errorf("stderr at --verbosity info should include server body detail %q\nstderr:\n%s", detail, stderr)
	}
}

func TestCLI_Upload_MissingAPIKey(t *testing.T) {
	sbom := filepath.Join(t.TempDir(), "sbom.json")
	writeFile(t, sbom, "{}")
	// Clear any inherited env so the test is reproducible.
	cmd := exec.Command(kunnusBin, "upload", sbom)
	cmd.Env = append(os.Environ(), "KUNNUS_API_KEY=")
	withCoverEnv(cmd)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		t.Fatal("want error when api-key missing, got nil")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %T: %v", err, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
