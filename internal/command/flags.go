// ABOUTME: Flags and helpers shared across the sbom repo / os subcommands.
// ABOUTME: Keeps both subcommand files focused on their unique target-selection logic.
package command

import (
	"context"
	"io"

	"github.com/urfave/cli/v3"

	scalibr "github.com/google/osv-scalibr"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// commonSBOMFlags are the flags accepted by every sbom subcommand.
func commonSBOMFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "write SBOM to file (default: stdout)",
		},
		&cli.StringFlag{
			Name:    "format",
			Aliases: []string{"f"},
			Value:   string(sbom.FormatCycloneDX15),
			Usage:   "SBOM format: spdx-2-3 | cyclonedx-1-5",
		},
		&cli.StringSliceFlag{
			Name:  "enable",
			Usage: "add a scalibr plugin by name (repeatable)",
		},
		&cli.StringSliceFlag{
			Name:  "disable",
			Usage: "remove a scalibr plugin by name (repeatable)",
		},
	}
}

// parseFormatFlag is a thin shim so subcommands don't import the sbom package directly.
func parseFormatFlag(s string) (sbom.Format, error) {
	return sbom.ParseFormat(s)
}

// scanRun is a thin shim so subcommands don't import the scan package directly.
func scanRun(ctx context.Context, cfg *scalibr.ScanConfig, logOut io.Writer) (*scan.Result, error) {
	return scan.Run(ctx, cfg, logOut)
}

// encodeSBOM is a thin shim so subcommands don't import the sbom package directly.
func encodeSBOM(out io.Writer, format sbom.Format, result *scan.Result, comp mode.ComponentInfo) error {
	return sbom.Encode(out, format, result, comp)
}
