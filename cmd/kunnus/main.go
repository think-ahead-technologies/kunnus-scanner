// ABOUTME: Entry point for the kunnus CLI binary.
// ABOUTME: Wires the root command, version banner, and top-level subcommand dispatch.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/think-ahead/kunnus-scanner/internal/command"
	"github.com/think-ahead/kunnus-scanner/internal/version"
	"github.com/urfave/cli/v3"
)

// Populated by goreleaser at build time.
var (
	commit = "n/a"
	date   = "n/a"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := &cli.Command{
		Name:    "kunnus",
		Usage:   "Generate SBOMs and upload them to the Kunnus platform",
		Version: version.Version,
		Commands: []*cli.Command{
			command.SBOM(),
			command.Upload(),
		},
		EnableShellCompletion: true,
	}

	cli.VersionPrinter = func(cmd *cli.Command) {
		_, _ = fmt.Fprintf(os.Stdout, "kunnus %s (commit %s, built %s)\n", cmd.Version, commit, date)
	}

	if err := app.Run(ctx, os.Args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "kunnus:", err)
		return 1
	}
	return 0
}
