// ABOUTME: Wires the `kunnus sbom repo` subcommand: source-code SBOM generation.
// ABOUTME: Owns its flags and harvests lockfile hashes; the shared pipeline lives in pipeline.go.
package command

import (
	"context"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	repomode "github.com/think-ahead/kunnus-scanner/internal/mode/repo"
)

func sbomRepo() *cli.Command {
	return &cli.Command{
		Name:      "repo",
		Usage:     "generate an SBOM for a source-code repository",
		ArgsUsage: "[path] (default: .)",
		Flags: append(commonSBOMFlags(),
			&cli.StringSliceFlag{
				Name:  "ecosystem",
				Usage: "restrict to specific ecosystems (e.g. npm, dotnet, python)",
			},
		),
		Action: runRepoScan,
	}
}

func runRepoScan(ctx context.Context, cmd *cli.Command) error {
	path := cmd.Args().First()
	if path == "" {
		path = "."
	}
	ov := mode.Overrides{
		Ecosystems:     cmd.StringSlice("ecosystem"),
		EnablePlugins:  cmd.StringSlice("enable"),
		DisablePlugins: cmd.StringSlice("disable"),
	}

	// Re-parse lockfiles for native deployable hashes. This is a workaround
	// for scalibr dropping the hash data its lockfile extractors already see;
	// remove once they surface them upstream.
	hashMap := ecosystem.Hashes(path, os.Stderr)

	return runScan(ctx, cmd, repomode.New(), path, ov, hashMap)
}
