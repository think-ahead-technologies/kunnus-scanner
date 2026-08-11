// ABOUTME: Defines the `kunnus sbom` parent command that owns the repo, os, and container subcommands.
// ABOUTME: Parent owns shared flags (--output, --format); subcommands own scan-target flags.
package command

import "github.com/urfave/cli/v3"

// sbomCmd returns the `kunnus sbom` parent command.
func sbomCmd() *cli.Command {
	return &cli.Command{
		Name:   "sbom",
		Usage:  "generate a Software Bill of Materials",
		Action: dispatchOnly,
		Commands: []*cli.Command{
			sbomRepo(),
			sbomOS(),
			sbomContainer(),
		},
	}
}
