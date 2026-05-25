// ABOUTME: Defines the `kunnus sbom` parent command that owns the repo and os subcommands.
// ABOUTME: Parent owns shared flags (--output, --format); subcommands own scan-target flags.
package command

import "github.com/urfave/cli/v3"

// SBOM returns the `kunnus sbom` parent command.
func SBOM() *cli.Command {
	return &cli.Command{
		Name:  "sbom",
		Usage: "generate a Software Bill of Materials",
		Commands: []*cli.Command{
			sbomRepo(),
			sbomOS(),
		},
	}
}
