// ABOUTME: Integration tests for the 'kunnus upload' command.
// ABOUTME: Verifies upload behavior, form fields, authentication, and error handling.
package upload_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/kunnus/upload"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/testlogger"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

// capturedUpload holds data captured by a test upload server.
type capturedUpload struct {
	apiKey        string
	formValues    map[string]string
	fileContent   []byte
	fileName      string
}

// newCaptureServer creates a test HTTP server that captures the multipart upload.
func newCaptureServer(t *testing.T, statusCode int) (*httptest.Server, *capturedUpload) {
	t.Helper()

	captured := &capturedUpload{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		captured.apiKey = r.Header.Get("X-API-Key")
		captured.formValues = make(map[string]string)

		for k, v := range r.MultipartForm.Value {
			if len(v) > 0 {
				captured.formValues[k] = v[0]
			}
		}

		if files := r.MultipartForm.File["file"]; len(files) > 0 {
			f, err := files[0].Open()
			if err == nil {
				defer f.Close()
				captured.fileContent, _ = io.ReadAll(f)
				captured.fileName = files[0].Filename
			}
		}

		w.WriteHeader(statusCode)
	}))

	return server, captured
}

// run builds a minimal CLI app with the upload command and executes it, mirroring
// the exit code logic from cmd/kunnus/main.go.
func run(t *testing.T, args []string) (string, string, int) {
	t.Helper()

	var outBuf, errBuf bytes.Buffer

	logger := cmdlogger.New(&outBuf, &errBuf)

	handler, ok := slog.Default().Handler().(*testlogger.Handler)
	if !ok {
		t.Fatal("test not initialized with testlogger - check TestMain")
	}
	handler.AddInstance(logger)
	defer handler.Delete()

	app := &cli.Command{
		Name:      "kunnus",
		Writer:    &outBuf,
		ErrWriter: &errBuf,
		Commands: []*cli.Command{
			upload.Command(&outBuf, &errBuf, nil),
		},
		ExitErrHandler: func(_ context.Context, _ *cli.Command, _ error) {},
	}

	err := app.Run(context.Background(), args)

	exitCode := 0
	if err != nil {
		switch {
		case errors.Is(err, osvscanner.ErrAPIFailed):
			cmdlogger.Errorf("%v", err)
			exitCode = 3
		default:
			cmdlogger.Errorf("%v", err)
		}
	}

	// cmdlogger.Errorf routes through the slog handler, so HasErrored() reflects
	// any error logged during the run — including the default error branch above.
	if exitCode == 0 && logger.HasErrored() {
		exitCode = 2
	}

	return outBuf.String(), errBuf.String(), exitCode
}

// writeTempSBOM creates a temporary SBOM file for testing and returns its path.
func writeTempSBOM(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.spdx.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write temp SBOM: %v", err)
	}

	return path
}

func TestUploadMissingFileArg(t *testing.T) {
	t.Parallel()

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		"--version", "1.0.0",
	})

	if exitCode != 2 {
		t.Errorf("exit code: got %d, want 2", exitCode)
	}
}

func TestUploadMissingAPIKey(t *testing.T) {
	t.Parallel()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		sbomFile,
	})

	if exitCode != 2 {
		t.Errorf("exit code: got %d, want 2", exitCode)
	}
}

func TestUploadMissingComponentID(t *testing.T) {
	t.Parallel()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--version", "1.0.0",
		sbomFile,
	})

	if exitCode != 2 {
		t.Errorf("exit code: got %d, want 2", exitCode)
	}
}

func TestUploadMissingVersion(t *testing.T) {
	t.Parallel()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		sbomFile,
	})

	if exitCode != 2 {
		t.Errorf("exit code: got %d, want 2", exitCode)
	}
}

func TestUploadSuccess(t *testing.T) {
	t.Parallel()

	server, captured := newCaptureServer(t, http.StatusOK)
	defer server.Close()

	sbomContent := `{"spdxVersion":"SPDX-2.3","name":"test"}`
	sbomFile := writeTempSBOM(t, sbomContent)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test_key",
		"--component-id", "comp-abc-123",
		"--version", "2.1.0",
		"--url", server.URL,
		"--source", "CLI",
		sbomFile,
	})

	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	if captured.apiKey != "kns_test_key" {
		t.Errorf("X-API-Key: got %q, want %q", captured.apiKey, "kns_test_key")
	}

	if captured.formValues["version"] != "2.1.0" {
		t.Errorf("version field: got %q, want %q", captured.formValues["version"], "2.1.0")
	}

	if captured.formValues["componentId"] != "comp-abc-123" {
		t.Errorf("componentId field: got %q, want %q", captured.formValues["componentId"], "comp-abc-123")
	}

	if captured.formValues["source"] != "CLI" {
		t.Errorf("source field: got %q, want %q", captured.formValues["source"], "CLI")
	}

	if captured.formValues["markAsCurrent"] != "true" {
		t.Errorf("markAsCurrent field: got %q, want %q", captured.formValues["markAsCurrent"], "true")
	}

	if string(captured.fileContent) != sbomContent {
		t.Errorf("file content: got %q, want %q", string(captured.fileContent), sbomContent)
	}

	if captured.fileName != filepath.Base(sbomFile) {
		t.Errorf("file name: got %q, want %q", captured.fileName, filepath.Base(sbomFile))
	}
}

func TestUploadServerError(t *testing.T) {
	t.Parallel()

	server, _ := newCaptureServer(t, http.StatusInternalServerError)
	defer server.Close()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", server.URL,
		sbomFile,
	})

	if exitCode != 3 {
		t.Errorf("exit code: got %d, want 3 (ErrAPIFailed)", exitCode)
	}
}

func TestUploadClientError(t *testing.T) {
	t.Parallel()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", "http://127.0.0.1:1", // nothing listening here
		sbomFile,
	})

	if exitCode != 3 {
		t.Errorf("exit code: got %d, want 3 (ErrAPIFailed)", exitCode)
	}
}

func TestUploadRejectedByServer(t *testing.T) {
	t.Parallel()

	server, _ := newCaptureServer(t, http.StatusUnauthorized)
	defer server.Close()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "bad_key",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", server.URL,
		sbomFile,
	})

	if exitCode != 2 {
		t.Errorf("exit code: got %d, want 2 (HTTP 4xx error)", exitCode)
	}
}

func TestUploadMarkAsCurrentFalse(t *testing.T) {
	t.Parallel()

	server, captured := newCaptureServer(t, http.StatusOK)
	defer server.Close()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", server.URL,
		"--mark-as-current=false",
		sbomFile,
	})

	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	if captured.formValues["markAsCurrent"] != "false" {
		t.Errorf("markAsCurrent field: got %q, want %q", captured.formValues["markAsCurrent"], "false")
	}
}

func TestUploadCISourceAutoDetection(t *testing.T) {
	// Not parallel: t.Setenv is not goroutine-safe with parallel tests.
	t.Setenv("CI", "true")
	// Unset other CI vars to avoid interference from the test environment.
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	t.Setenv("JENKINS_URL", "")

	server, captured := newCaptureServer(t, http.StatusOK)
	defer server.Close()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", server.URL,
		// no --source flag: should auto-detect
		sbomFile,
	})

	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	if captured.formValues["source"] != "CiPipeline" {
		t.Errorf("source field: got %q, want %q", captured.formValues["source"], "CiPipeline")
	}
}

func TestUploadSourceFlagOverridesAutoDetection(t *testing.T) {
	// Not parallel: t.Setenv is not goroutine-safe with parallel tests.
	t.Setenv("CI", "true")

	server, captured := newCaptureServer(t, http.StatusOK)
	defer server.Close()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		"--api-key", "kns_test",
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", server.URL,
		"--source", "CLI",
		sbomFile,
	})

	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	if captured.formValues["source"] != "CLI" {
		t.Errorf("source field: got %q, want %q (--source flag should override CI detection)", captured.formValues["source"], "CLI")
	}
}

func TestUploadEnvVarAPIKey(t *testing.T) {
	// Not parallel: t.Setenv is not goroutine-safe with parallel tests.
	t.Setenv("KUNNUS_API_KEY", "env_api_key")

	server, captured := newCaptureServer(t, http.StatusOK)
	defer server.Close()

	sbomFile := writeTempSBOM(t, `{"spdxVersion":"SPDX-2.3"}`)

	_, _, exitCode := run(t, []string{
		"kunnus", "upload",
		// no --api-key flag: should pick up from env
		"--component-id", "comp-123",
		"--version", "1.0.0",
		"--url", server.URL,
		"--source", "CLI",
		sbomFile,
	})

	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}

	if captured.apiKey != "env_api_key" {
		t.Errorf("X-API-Key: got %q, want %q", captured.apiKey, "env_api_key")
	}
}
