// ABOUTME: Entry point for the kunnus CLI binary, a user-friendly security tooling interface.
// ABOUTME: Provides SBOM generation and future kunnus platform integrations.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/osv-scanner/v2/cmd/kunnus/sbom"
	kversion "github.com/google/osv-scanner/v2/cmd/kunnus/internal/version"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	osvversion "github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

var (
	commit = "n/a"
	date   = "n/a"
)

func run(args []string, stdout, stderr io.Writer, client *http.Client) int {
	logger := cmdlogger.New(stdout, stderr)
	slog.SetDefault(slog.New(logger))

	cli.VersionPrinter = func(cmd *cli.Command) {
		fmt.Fprintf(stdout, "kunnus version: %s\n", cmd.Version)
		fmt.Fprintf(stdout, "osv-scanner version: %s\n", osvversion.OSVVersion)
		fmt.Fprintf(stdout, "commit: %s\n", commit)
		fmt.Fprintf(stdout, "built at: %s\n", date)
	}

	app := &cli.Command{
		Name:      "kunnus",
		Version:   kversion.KunnusVersion,
		Usage:     "SBOM generation and vulnerability scanning",
		Suggest:   true,
		Writer:    stdout,
		ErrWriter: stderr,
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("unknown command %q — run 'kunnus --help' for usage", cmd.Args().First())
			}
			return cli.ShowAppHelp(cmd)
		},
		Commands: []*cli.Command{
			sbom.Command(stdout, stderr, client),
		},
		// Prevent cli from calling os.Exit on errors - we handle exit codes ourselves.
		ExitErrHandler: func(_ context.Context, _ *cli.Command, _ error) {},
	}

	err := app.Run(context.Background(), args)

	if err != nil {
		switch {
		case errors.Is(err, osvscanner.ErrVulnerabilitiesFound):
			return 1
		case errors.Is(err, osvscanner.ErrAPIFailed):
			cmdlogger.Errorf("%v", err)
			return 129
		}
		cmdlogger.Errorf("%v", err)
	}

	if logger.HasErrored() {
		return 127
	}

	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr, nil))
}
