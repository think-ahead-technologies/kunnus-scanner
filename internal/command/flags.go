// ABOUTME: Flags shared across the sbom repo / os subcommands.
// ABOUTME: Keeps both subcommand files focused on their unique target-selection logic.
package command

import "github.com/urfave/cli/v3"

// commonSBOMFlags are the flags accepted by every sbom subcommand.
// Output format is CycloneDX 1.6 (BSI-conformant).
func commonSBOMFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "output",
			Aliases: []string{"o"},
			Usage:   "write SBOM to file (default: stdout)",
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
