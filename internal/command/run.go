// ABOUTME: Entry point for the command layer: builds the root CLI and runs it.
// ABOUTME: Keeps urfave/cli encapsulated here so cmd/kunnus is just the binary shell.
package command

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Run builds the root kunnus command and executes it with the given args.
// commit and date are injected at build time by goreleaser and surface in
// `kunnus --version`. Returns the process exit code.
func Run(ctx context.Context, args []string, commit, date string) int {
	app := &cli.Command{
		Name:                  "kunnus",
		Usage:                 "Generate SBOMs and upload them to the Kunnus platform",
		Version:               version.Version,
		Commands:              []*cli.Command{sbomCmd(), uploadCmd()},
		EnableShellCompletion: true,
	}

	cli.VersionPrinter = func(cmd *cli.Command) {
		_, _ = fmt.Fprintf(os.Stdout, "kunnus %s (commit %s, built %s)\n", cmd.Version, commit, date)
	}

	if err := app.Run(ctx, args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "kunnus:", err)
		return 1
	}
	return 0
}
