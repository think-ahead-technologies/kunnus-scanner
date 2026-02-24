// ABOUTME: Implements the 'kunnus sbom' subcommand for generating SBOMs from project dependencies.
// ABOUTME: Provides a simplified, user-friendly interface to osv-scanner's SBOM generation capabilities.
package sbom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/reporter"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

var sbomFormats = []string{"spdx-2-3", "cyclonedx-1-4", "cyclonedx-1-5"}

// Command returns the 'sbom' subcommand for generating Software Bill of Materials.
func Command(stdout, stderr io.Writer, client *http.Client) *cli.Command {
	return &cli.Command{
		Name:        "sbom",
		Usage:       "generate a Software Bill of Materials for a project's dependencies",
		Description: "scans a project's dependencies and generates an SBOM in spdx or cyclonedx format",
		ArgsUsage:   "[directory...]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "SBOM output format; value can be: " + strings.Join(sbomFormats, ", "),
				Value:   "spdx-2-3",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if !slices.Contains(sbomFormats, s) {
						return fmt.Errorf("unsupported format %q - must be one of: %s", s, strings.Join(sbomFormats, ", "))
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:      "output",
				Aliases:   []string{"o"},
				Usage:     "save the SBOM to the given file path",
				TakesFile: true,
			},
			&cli.BoolFlag{
				Name:    "recursive",
				Aliases: []string{"r"},
				Usage:   "scan subdirectories",
				Value:   true,
			},
			&cli.BoolFlag{
				Name:  "offline-vulnerabilities",
				Usage: "check for vulnerabilities using local databases that are already cached",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return action(ctx, cmd, stdout, stderr, client)
		},
	}
}

func action(_ context.Context, cmd *cli.Command, stdout, stderr io.Writer, client *http.Client) error {
	dirs := cmd.Args().Slice()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}

	format := cmd.String("format")
	outputPath := cmd.String("output")

	// SBOM output formats need log messages on stderr to keep the SBOM on stdout clean.
	cmdlogger.SendEverythingToStderr()

	scannerAction := osvscanner.ScannerActions{
		DirectoryPaths: dirs,
		Recursive:      cmd.Bool("recursive"),
		CompareOffline: cmd.Bool("offline-vulnerabilities"),
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			HTTPClient:       client,
			RequestUserAgent: "kunnus_sbom/" + version.OSVVersion,
		},
	}

	vulnResult, err := osvscanner.DoScan(scannerAction)

	// No packages is not an error for SBOM generation.
	if errors.Is(err, osvscanner.ErrNoPackagesFound) {
		cmdlogger.Warnf("No package sources found in the given directories")
		err = nil
	}

	// Vulnerabilities found is not an error for SBOM generation.
	if errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		err = nil
	}

	if err != nil {
		return err
	}

	if errPrint := printSBOM(stdout, stderr, outputPath, format, &vulnResult); errPrint != nil {
		return fmt.Errorf("failed to write SBOM: %w", errPrint)
	}

	return nil
}

// printSBOM writes the SBOM to stdout or to the given file path.
func printSBOM(stdout, _ io.Writer, outputPath, format string, vulnResult *models.VulnerabilityResults) error {
	termWidth := 0
	writer := stdout

	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		writer = f
	} else if stdoutAsFile, ok := stdout.(*os.File); ok {
		var err error
		termWidth, _, err = term.GetSize(int(stdoutAsFile.Fd()))
		if err != nil {
			termWidth = 0
		}
	}

	return reporter.PrintResult(vulnResult, format, writer, termWidth, false)
}
