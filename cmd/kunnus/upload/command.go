// ABOUTME: Implements the 'kunnus upload' subcommand for uploading SBOMs to the Kunnus platform.
// ABOUTME: Handles API key auth, multipart form upload, and CI environment source detection.
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

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

const defaultUploadURL = "https://app.kunnus.tech/api/sboms/upload"

// Command returns the 'upload' subcommand for uploading SBOMs to the Kunnus platform.
func Command(stdout, stderr io.Writer, client *http.Client) *cli.Command {
	return &cli.Command{
		Name:      "upload",
		Usage:     "upload an SBOM to the Kunnus platform",
		ArgsUsage: "<sbom-file>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "api-key",
				Aliases: []string{"k"},
				Usage:   "Kunnus API key (env: KUNNUS_API_KEY)",
				Sources: cli.EnvVars("KUNNUS_API_KEY"),
			},
			&cli.StringFlag{
				Name:    "component-id",
				Aliases: []string{"c"},
				Usage:   "component ID to associate the SBOM with (env: KUNNUS_COMPONENT_ID)",
				Sources: cli.EnvVars("KUNNUS_COMPONENT_ID"),
			},
			&cli.StringFlag{
				Name:  "version",
				Usage: "version string to associate with the SBOM",
			},
			&cli.StringFlag{
				Name:    "url",
				Usage:   "Kunnus upload API URL (env: KUNNUS_URL)",
				Value:   defaultUploadURL,
				Sources: cli.EnvVars("KUNNUS_URL"),
			},
			&cli.StringFlag{
				Name:  "source",
				Usage: "upload source identifier (auto-detected from CI environment if not set)",
			},
			&cli.BoolFlag{
				Name:        "mark-as-current",
				Usage:       "mark this SBOM as the current version for the component",
				Value:       true,
				DefaultText: "on",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(ctx, cmd, stdout, stderr, client)
		},
	}
}

func action(ctx context.Context, cmd *cli.Command, stdout, stderr io.Writer, client *http.Client) error {
	if !cmd.Args().Present() {
		return fmt.Errorf("missing required argument: <sbom-file>")
	}
	filePath := cmd.Args().First()

	apiKey := cmd.String("api-key")
	if apiKey == "" {
		return fmt.Errorf("missing required flag --api-key (or env KUNNUS_API_KEY)")
	}

	componentID := cmd.String("component-id")
	if componentID == "" {
		return fmt.Errorf("missing required flag --component-id (or env KUNNUS_COMPONENT_ID)")
	}

	version := cmd.String("version")
	if version == "" {
		version = time.Now().Format("2006-01-02")
	}

	uploadURL := cmd.String("url")

	source := cmd.String("source")
	if source == "" {
		source = detectSource()
	}

	markAsCurrent := cmd.Bool("mark-as-current")
	interactive := isTerminalWriter(stdout)

	if client == nil {
		client = http.DefaultClient
	}

	if interactive {
		fmt.Fprintf(stdout, "Uploading %s to Kunnus...\n", filepath.Base(filePath))
	}

	if err := doUpload(ctx, client, uploadURL, apiKey, filePath, componentID, version, source, markAsCurrent); err != nil {
		return err
	}

	if interactive {
		fmt.Fprintf(stdout, "SBOM uploaded.\n  Component: %s\n  Version:   %s\n", componentID, version)
	}

	return nil
}

// doUpload sends the SBOM file as a multipart/form-data POST to the Kunnus upload API.
func doUpload(ctx context.Context, client *http.Client, uploadURL, apiKey, filePath, componentID, version, source string, markAsCurrent bool) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer f.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	part, err := mw.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}

	if _, err := io.Copy(part, f); err != nil {
		return fmt.Errorf("failed to write SBOM to request: %w", err)
	}

	for _, field := range []struct{ name, value string }{
		{"version", version},
		{"componentId", componentID},
		{"source", source},
		{"markAsCurrent", strconv.FormatBool(markAsCurrent)},
	} {
		if err := mw.WriteField(field.name, field.value); err != nil {
			return fmt.Errorf("failed to write form field %q: %w", field.name, err)
		}
	}

	if err := mw.Close(); err != nil {
		return fmt.Errorf("failed to finalize multipart body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, &body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-API-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", osvscanner.ErrAPIFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: server returned %d", osvscanner.ErrAPIFailed, resp.StatusCode)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("upload rejected by server (HTTP %d)", resp.StatusCode)
	}

	return nil
}

// detectSource returns "CiPipeline" if a known CI environment variable is set, else "CLI".
func detectSource() string {
	if os.Getenv("GITHUB_ACTIONS") == "true" ||
		os.Getenv("GITLAB_CI") == "true" ||
		os.Getenv("JENKINS_URL") != "" ||
		os.Getenv("CI") == "true" {
		return "CiPipeline"
	}

	return "CLI"
}

// isTerminalWriter reports whether w is an *os.File connected to a terminal.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}

	return term.IsTerminal(int(f.Fd()))
}
