// ABOUTME: Wires the `kunnus sbom repo` subcommand: source-code SBOM generation.
// ABOUTME: Owns its flags; delegates all real work to mode/repo, scan, and sbom packages.
package command

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	repomode "github.com/think-ahead/kunnus-scanner/internal/mode/repo"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
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
	return runScan(ctx, cmd, repomode.New(), path, ov)
}

// runScan is the shared scan-and-encode pipeline used by both repo and os subcommands.
// It takes the chosen mode, plans the scan, runs it, and encodes the SBOM to the
// requested output (file or stdout).
func runScan(ctx context.Context, cmd *cli.Command, m mode.Mode, path string, ov mode.Overrides) error {
	cfg, comp, err := m.Plan(ctx, path, ov)
	if err != nil {
		return fmt.Errorf("plan %s scan: %w", m.Name(), err)
	}

	result, err := scan.Run(ctx, cfg, os.Stderr)
	if err != nil {
		return fmt.Errorf("run scan: %w", err)
	}

	// Re-parse lockfiles for native deployable hashes. This is a workaround
	// for scalibr dropping the hash data its lockfile extractors already see;
	// remove once they surface them upstream.
	hashMap := ecosystem.Hashes(path, os.Stderr)

	out, closer, err := openOutput(cmd.String("output"))
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer closer()

	if err := sbom.Encode(out, result, comp, hashMap); err != nil {
		return fmt.Errorf("encode sbom: %w", err)
	}
	return nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
