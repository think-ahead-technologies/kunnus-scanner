// Package sbom implements the 'kunnus sbom' subcommand for SBOM generation.
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
		ArgsUsage:   "[directory...] (default: current directory)",
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
			&cli.BoolWithInverseFlag{
				Name:        "recursive",
				Aliases:     []string{"r"},
				Usage:       "scan subdirectories",
				Value:       true,
				DefaultText: "on",
			},
			&cli.BoolFlag{
				Name:  "offline-vulnerabilities",
				Usage: "check for vulnerabilities using locally cached databases (errors if no cache exists)",
			},
			&cli.BoolFlag{
				Name:        "all-packages",
				Usage:       "include all scanned packages in the SBOM, not just vulnerable ones",
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
	dirs := cmd.Args().Slice()
	if len(dirs) == 0 {
		dirs = []string{"."}
	}

	format := cmd.String("format")
	outputPath := cmd.String("output")
	interactive := isTerminalWriter(stdout)

	// SBOM output formats need log messages on stderr to keep the SBOM on stdout clean.
	cmdlogger.SendEverythingToStderr()

	scannerAction := osvscanner.ScannerActions{
		DirectoryPaths:  dirs,
		Recursive:       cmd.Bool("recursive"),
		CompareOffline:  cmd.Bool("offline-vulnerabilities"),
		ShowAllPackages: cmd.Bool("all-packages"),
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			HTTPClient:       client,
			RequestUserAgent: "kunnus_sbom/" + kversion.KunnusVersion,
		},
	}

	vulnResult, err := osvscanner.DoScan(scannerAction) //nolint:contextcheck

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
		if errPrint := printSBOM(stdout, outputPath, format, &vulnResult); errPrint != nil {
			return fmt.Errorf("failed to write SBOM: %w", errPrint)
		}

		return nil
	}

	// Interactive/terminal mode: also append Windows OS packages from the registry.
	// In pipe mode the SBOM covers the scanned directories only; OS-level inventory
	// is added here so interactive users get a comprehensive machine snapshot.
	if winInv, winErr := runWindowsScan(ctx); winErr == nil {
		mergeWindowsInventory(winInv, &vulnResult)
	} else {
		cmdlogger.Warnf("Windows OS scan failed (non-fatal): %v", winErr)
	}

	// Re-check: DoScan may have set noPackagesFound before Windows packages were added.
	noPackagesFound = len(vulnResult.Results) == 0

	// Save SBOM to file and show a human-readable summary.
	savedPath := outputPath
	if savedPath == "" && !noPackagesFound {
		project := autoProjectName(dirs)
		date := time.Now().Format("2006-01-02")
		savedPath = buildFileName(project, format, date)
	}

	if savedPath != "" {
		if err := writeSBOMToFile(savedPath, format, &vulnResult); err != nil {
			return fmt.Errorf("failed to write SBOM: %w", err)
		}
	}

	fmt.Fprint(stdout, buildScanSummary(dirs, &vulnResult, savedPath))

	_ = stderr

	return nil
}

// printSBOM writes the SBOM to stdout or to the given file path.
func printSBOM(stdout io.Writer, outputPath, format string, vulnResult *models.VulnerabilityResults) error {
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

// countVulnerabilities returns the number of unique vulnerability IDs across all packages.
func countVulnerabilities(result *models.VulnerabilityResults) int {
	seen := map[string]struct{}{}
	for _, pkgSource := range result.Results {
		for _, pkg := range pkgSource.Packages {
			for _, v := range pkg.Vulnerabilities {
				seen[v.GetId()] = struct{}{}
			}
		}
	}

	return len(seen)
}

// buildScanSummary returns a formatted human-readable summary of the scan results.
func buildScanSummary(dirs []string, result *models.VulnerabilityResults, savedPath string) string {
	var sb strings.Builder

	switch len(dirs) {
	case 1:
		fmt.Fprintf(&sb, "Scanning %s\n\n", dirs[0])
	case 2, 3:
		fmt.Fprintf(&sb, "Scanning %s\n\n", strings.Join(dirs, ", "))
	default:
		fmt.Fprintf(&sb, "Scanning %d directories\n\n", len(dirs))
	}

	if len(result.Results) == 0 {
		sb.WriteString("  No package sources found.\n")

		return sb.String()
	}

	type summaryRow struct {
		ecosystem    string
		count        int
		source       string // base filename of first source with this ecosystem
		extraSources int    // number of additional sources merged into this row
	}

	var rows []summaryRow
	ecoIndex := map[string]int{}
	total := 0

	for _, pkgSource := range result.Results {
		eco := primaryEcosystem(pkgSource.Packages)
		// Windows Registry packages have no OSV ecosystem; label them by source path.
		if eco == "" && pkgSource.Source.Path == "Windows Registry" {
			eco = "Windows"
		}
		count := len(pkgSource.Packages)
		total += count
		sourceName := filepath.Base(pkgSource.Source.Path)

		if idx, ok := ecoIndex[eco]; ok {
			rows[idx].count += count
			rows[idx].extraSources++
		} else {
			ecoIndex[eco] = len(rows)
			rows = append(rows, summaryRow{ecosystem: eco, count: count, source: sourceName})
		}
	}

	for _, row := range rows {
		sourceDisplay := row.source
		if row.extraSources > 0 {
			sourceDisplay = fmt.Sprintf("%s +%d more", row.source, row.extraSources)
		}
		fmt.Fprintf(&sb, "  %-12s %4d packages  (%s)\n", row.ecosystem, row.count, sourceDisplay)
	}

	sb.WriteString("  ────────────────────────────────────\n")
	fmt.Fprintf(&sb, "  %-12s %4d packages\n", "Total", total)

	vulnCount := countVulnerabilities(result)
	if vulnCount == 0 {
		sb.WriteString("  No vulnerabilities found.\n")
	} else {
		fmt.Fprintf(&sb, "  %d vulnerabilities found.\n", vulnCount)
	}

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
