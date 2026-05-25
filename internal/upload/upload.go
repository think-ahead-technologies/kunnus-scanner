// ABOUTME: Uploads an SBOM file to the Kunnus platform as multipart/form-data.
// ABOUTME: No SBOM-format awareness — pushes whatever bytes are on disk.
package upload

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// DefaultURL is the production upload endpoint. Override via the upload command flag/env.
const DefaultURL = "https://app.kunnus.tech/api/sboms/upload"

// Options bundles everything an upload needs. All fields except File are user-supplied.
type Options struct {
	URL         string
	APIKey      string
	ComponentID string
	File        string
	Client      *http.Client
}

// Do uploads opts.File to opts.URL and returns the server response body on success.
func Do(ctx context.Context, opts Options) ([]byte, error) {
	if opts.File == "" {
		return nil, fmt.Errorf("file path is required")
	}
	if opts.APIKey == "" {
		return nil, fmt.Errorf("api key is required")
	}
	if opts.URL == "" {
		opts.URL = DefaultURL
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 60 * time.Second}
	}

	f, err := os.Open(opts.File)
	if err != nil {
		return nil, fmt.Errorf("open sbom: %w", err)
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat sbom: %w", err)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if opts.ComponentID != "" {
		if err := writer.WriteField("component_id", opts.ComponentID); err != nil {
			return nil, fmt.Errorf("write component_id: %w", err)
		}
	}
	if err := writer.WriteField("size", strconv.FormatInt(stat.Size(), 10)); err != nil {
		return nil, fmt.Errorf("write size: %w", err)
	}

	part, err := writer.CreateFormFile("sbom", filepath.Base(opts.File))
	if err != nil {
		return nil, fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, fmt.Errorf("copy sbom body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close multipart: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.URL, &body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+opts.APIKey)

	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post sbom: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return respBody, fmt.Errorf("upload failed: %s: %s", resp.Status, string(respBody))
	}

	return respBody, nil
}
