// ABOUTME: End-to-end CLI tests. Builds the kunnus binary once, then exercises subcommands.
// ABOUTME: Real binary, real flags, real I/O — closest thing to a user running it locally.
package main_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	cmd := exec.Command("go", "build", "-o", out, "github.com/think-ahead/kunnus-scanner/cmd/kunnus")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out, nil
}

func runKunnus(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, kunnusBin, args...)
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
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	if v, _ := doc["bomFormat"].(string); v != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}

	haystack := strings.ToLower(string(data))
	entries, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		wants := readWants(t, filepath.Join(corpus, e.Name()))
		for _, w := range wants {
			if !strings.Contains(haystack, strings.ToLower(w)) {
				t.Errorf("ecosystem %q: expected component %q missing from combined SBOM", e.Name(), w)
			}
		}
	}
}

// corpusDir resolves <module-root>/testdata/ecosystems by walking up to the
// directory containing go.mod. The corpus is shared with the scan-seam tier.
func corpusDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "ecosystems")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate module root (go.mod)")
		}
		dir = parent
	}
}

// readWants returns the expected component substrings from dir/want.txt,
// skipping blank lines and #-comments.
func readWants(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "want.txt"))
	if err != nil {
		t.Fatalf("read want.txt in %s: %v", dir, err)
	}
	var wants []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		wants = append(wants, line)
	}
	return wants
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
