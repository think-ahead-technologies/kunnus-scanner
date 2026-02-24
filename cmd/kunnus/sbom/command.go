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
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	kversion "github.com/google/osv-scanner/v2/cmd/kunnus/internal/version"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/reporter"
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
				Name:        "recursive",
				Aliases:     []string{"r"},
				Usage:       "scan subdirectories",
				Value:       true,
				DefaultText: "on",
			},
			&cli.BoolFlag{
				Name:  "offline-vulnerabilities",
				Usage: "check for vulnerabilities using local databases that are already cached",
			},
			&cli.StringFlag{
				Name:        "verbosity",
				Usage:       "log verbosity level; value can be: " + strings.Join(cmdlogger.Levels(), ", "),
				Value:       "warn",
				DefaultText: "warn",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					if _, err := cmdlogger.ParseLevel(s); err != nil {
						return err
					}

					return nil
				},
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
	interactive := isTerminalWriter(stdout)

	// Apply verbosity before scanning so progress messages are filtered correctly.
	if lvl, err := cmdlogger.ParseLevel(cmd.String("verbosity")); err == nil {
		cmdlogger.SetLevel(lvl)
	}

	// SBOM output formats need log messages on stderr to keep the SBOM on stdout clean.
	cmdlogger.SendEverythingToStderr()

	scannerAction := osvscanner.ScannerActions{
		DirectoryPaths: dirs,
		Recursive:      cmd.Bool("recursive"),
		CompareOffline: cmd.Bool("offline-vulnerabilities"),
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			HTTPClient:       client,
			RequestUserAgent: "kunnus_sbom/" + kversion.KunnusVersion,
		},
	}

	vulnResult, err := osvscanner.DoScan(scannerAction)

	noPackagesFound := errors.Is(err, osvscanner.ErrNoPackagesFound)

	// No packages is not an error for SBOM generation.
	if noPackagesFound {
		if !interactive {
			cmdlogger.Warnf("No package sources found in the given directories")
		}
		err = nil
	}

	// Vulnerabilities found is not an error for SBOM generation.
	if errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		err = nil
	}

	if err != nil {
		return err
	}

	if !interactive {
		// Pipe mode: write SBOM to stdout or to the given file (existing behavior unchanged).
		if errPrint := printSBOM(stdout, stderr, outputPath, format, &vulnResult); errPrint != nil {
			return fmt.Errorf("failed to write SBOM: %w", errPrint)
		}

		return nil
	}

	// Interactive/terminal mode: save SBOM to file and show a human-readable summary.
	savedPath := outputPath
	if savedPath == "" && !noPackagesFound {
		project := projectNameFromDir(dirs[0])
		date := time.Now().Format("2006-01-02")
		savedPath = buildFileName(project, format, date)
	}

	if savedPath != "" {
		if err := writeSBOMToFile(savedPath, format, &vulnResult); err != nil {
			return fmt.Errorf("failed to write SBOM: %w", err)
		}
	}

	fmt.Fprint(stdout, buildScanSummary(dirs, &vulnResult, savedPath))

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

// isTerminalWriter reports whether w is an *os.File connected to a terminal.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}

	return term.IsTerminal(int(f.Fd()))
}

// buildFileName constructs the auto-save filename for the SBOM.
func buildFileName(project, format, date string) string {
	ext := ".spdx.json"
	if strings.HasPrefix(format, "cyclonedx") {
		ext = ".cdx.json"
	}

	return fmt.Sprintf("sbom-%s-%s%s", project, date, ext)
}

// projectNameFromDir returns the base directory name for use in auto-generated filenames.
func projectNameFromDir(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Base(dir)
	}

	return filepath.Base(abs)
}

// primaryEcosystem returns the most common ecosystem across the given packages.
// Ties are broken alphabetically by ecosystem name.
func primaryEcosystem(packages []models.PackageVulns) string {
	counts := map[string]int{}
	for _, pkg := range packages {
		counts[pkg.Package.Ecosystem]++
	}

	// Sort ecosystem names for deterministic tie-breaking.
	ecosystems := make([]string, 0, len(counts))
	for eco := range counts {
		ecosystems = append(ecosystems, eco)
	}
	sort.Strings(ecosystems)

	best := ""
	bestCount := 0
	for _, eco := range ecosystems {
		if counts[eco] > bestCount {
			best = eco
			bestCount = counts[eco]
		}
	}

	return best
}

// buildScanSummary returns a formatted human-readable summary of the scan results.
func buildScanSummary(dirs []string, result *models.VulnerabilityResults, savedPath string) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Scanning %s\n\n", dirs[0])

	if len(result.Results) == 0 {
		sb.WriteString("  No package sources found.\n")

		return sb.String()
	}

	type summaryRow struct {
		ecosystem string
		count     int
		source    string // base filename of first source with this ecosystem
	}

	var rows []summaryRow
	ecoIndex := map[string]int{}
	total := 0

	for _, pkgSource := range result.Results {
		eco := primaryEcosystem(pkgSource.Packages)
		count := len(pkgSource.Packages)
		total += count
		sourceName := filepath.Base(pkgSource.Source.Path)

		if idx, ok := ecoIndex[eco]; ok {
			rows[idx].count += count
		} else {
			ecoIndex[eco] = len(rows)
			rows = append(rows, summaryRow{ecosystem: eco, count: count, source: sourceName})
		}
	}

	for _, row := range rows {
		fmt.Fprintf(&sb, "  %-12s %4d packages  (%s)\n", row.ecosystem, row.count, row.source)
	}

	sb.WriteString("  ────────────────────────────────────\n")
	fmt.Fprintf(&sb, "  %-12s %4d packages\n", "Total", total)

	if savedPath != "" {
		fmt.Fprintf(&sb, "\n  SBOM saved → %s\n", savedPath)
	}

	return sb.String()
}

// writeSBOMToFile writes the SBOM to the given file path.
func writeSBOMToFile(path, format string, result *models.VulnerabilityResults) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	return reporter.PrintResult(result, format, f, 0, false)
}
