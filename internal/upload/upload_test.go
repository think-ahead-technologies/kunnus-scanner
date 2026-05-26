// ABOUTME: Tests for upload.Do against a local httptest.Server. Real HTTP, no mocks.
// ABOUTME: Verifies bearer auth, multipart structure, component_id field, and error paths.
package upload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSBOM(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	return path
}

type capturedRequest struct {
	auth        string
	contentType string
	componentID string
	sboms       []byte
	sizeField   string
}

func newCaptureServer(t *testing.T, respondStatus int, respondBody string) (*httptest.Server, *capturedRequest) {
	t.Helper()
	cap := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.auth = r.Header.Get("Authorization")
		cap.contentType = r.Header.Get("Content-Type")

		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Errorf("ParseMultipartForm: %v", err)
		}
		cap.componentID = r.FormValue("component_id")
		cap.sizeField = r.FormValue("size")

		f, _, err := r.FormFile("sbom")
		if err != nil {
			t.Errorf("FormFile sbom: %v", err)
		} else {
			defer func() { _ = f.Close() }()
			b, _ := io.ReadAll(f)
			cap.sboms = b
		}

		w.WriteHeader(respondStatus)
		_, _ = w.Write([]byte(respondBody))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func TestDo_HappyPath(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusOK, `{"id":"sbom-123"}`)

	sbomContent := `{"format":"spdx"}`
	sbomFile := writeSBOM(t, sbomContent)

	body, err := Do(context.Background(), Options{
		URL:         srv.URL,
		APIKey:      "secret-key",
		ComponentID: "comp-42",
		File:        sbomFile,
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(body) != `{"id":"sbom-123"}` {
		t.Errorf("response body = %q, want sbom-123 envelope", body)
	}
	if cap.auth != "Bearer secret-key" {
		t.Errorf("Authorization = %q, want Bearer secret-key", cap.auth)
	}
	if !strings.HasPrefix(cap.contentType, "multipart/form-data") {
		t.Errorf("Content-Type = %q, want multipart prefix", cap.contentType)
	}
	if cap.componentID != "comp-42" {
		t.Errorf("component_id = %q, want comp-42", cap.componentID)
	}
	if !bytes.Equal(cap.sboms, []byte(sbomContent)) {
		t.Errorf("sbom file body = %q, want %q", cap.sboms, sbomContent)
	}
	if cap.sizeField == "" {
		t.Error("size field missing")
	}
}

func TestDo_WithoutComponentID(t *testing.T) {
	srv, cap := newCaptureServer(t, http.StatusCreated, "ok")
	sbomFile := writeSBOM(t, "{}")

	if _, err := Do(context.Background(), Options{
		URL:    srv.URL,
		APIKey: "k",
		File:   sbomFile,
	}); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if cap.componentID != "" {
		t.Errorf("component_id = %q, want empty when not provided", cap.componentID)
	}
}

func TestDo_MissingFileErrors(t *testing.T) {
	_, err := Do(context.Background(), Options{
		URL:    "http://example.invalid",
		APIKey: "k",
		File:   "",
	})
	if err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestDo_MissingAPIKeyErrors(t *testing.T) {
	_, err := Do(context.Background(), Options{
		URL:    "http://example.invalid",
		APIKey: "",
		File:   writeSBOM(t, "{}"),
	})
	if err == nil {
		t.Fatal("want error for missing api key")
	}
}

func TestDo_ServerError(t *testing.T) {
	srv, _ := newCaptureServer(t, http.StatusInternalServerError, `{"error":"boom"}`)
	body, err := Do(context.Background(), Options{
		URL:    srv.URL,
		APIKey: "k",
		File:   writeSBOM(t, "{}"),
	})
	if err == nil {
		t.Fatal("want error for 500 response")
	}
	if !strings.Contains(string(body), "boom") {
		t.Errorf("returned body should contain server error detail, got %q", body)
	}
}

func TestDo_NonexistentFile(t *testing.T) {
	_, err := Do(context.Background(), Options{
		URL:    "http://example.invalid",
		APIKey: "k",
		File:   filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	if err == nil {
		t.Fatal("want error for nonexistent file")
	}
}

func TestDo_ErrorMessageDoesNotEmbedResponseBody(t *testing.T) {
	// Server response bodies may contain anything — including, in a misbehaving
	// reverse proxy, an echo of the Authorization header. Keep them out of the
	// error chain so log aggregators that scrape stderr don't pick them up.
	// The body is still returned to the caller via the first return value.
	const secret = "leaked-bearer-token-DO-NOT-EMBED"
	srv, _ := newCaptureServer(t, http.StatusUnauthorized, `{"echo":"`+secret+`"}`)

	body, err := Do(context.Background(), Options{
		URL:    srv.URL,
		APIKey: "k",
		File:   writeSBOM(t, "{}"),
	})
	if err == nil {
		t.Fatal("want error for 401 response")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message must not embed response body, but contains %q\nerr: %s", secret, err.Error())
	}
	if !strings.Contains(string(body), secret) {
		t.Errorf("body return value should preserve server response for caller inspection, got %q", body)
	}
}

func TestDo_LimitsResponseBodySize(t *testing.T) {
	// A pathological server returning a giant body must not OOM us.
	// We accept up to MaxResponseBytes; bytes beyond that are dropped.
	huge := bytes.Repeat([]byte("A"), int(MaxResponseBytes)+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(huge)
	}))
	defer srv.Close()

	body, err := Do(context.Background(), Options{
		URL:    srv.URL,
		APIKey: "k",
		File:   writeSBOM(t, "{}"),
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if int64(len(body)) > MaxResponseBytes {
		t.Errorf("response body len = %d, want <= %d (MaxResponseBytes)", len(body), MaxResponseBytes)
	}
}

func TestDo_RespectsContextDeadline(t *testing.T) {
	// The caller's context must be the sole deadline source — no hidden
	// http.Client.Timeout fallback that ignores ctx.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := Do(ctx, Options{
		URL:    srv.URL,
		APIKey: "k",
		File:   writeSBOM(t, "{}"),
	})
	if err == nil {
		t.Fatal("want context-deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want errors.Is(err, context.DeadlineExceeded), got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Do took %v; context deadline should have cut it off promptly", elapsed)
	}
}
