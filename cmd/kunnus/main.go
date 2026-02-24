// ABOUTME: Entry point for the kunnus CLI binary, a user-friendly security tooling interface.
// ABOUTME: Provides SBOM generation and future kunnus platform integrations.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/osv-scanner/v2/cmd/kunnus/sbom"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/version"
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
		cmdlogger.Infof("kunnus version: %s", cmd.Version)
		cmdlogger.Infof("commit: %s", commit)
		cmdlogger.Infof("built at: %s", date)
	}

	app := &cli.Command{
		Name:      "kunnus",
		Version:   version.OSVVersion,
		Usage:     "kunnus security tooling",
		Suggest:   true,
		Writer:    stdout,
		ErrWriter: stderr,
		Action: func(ctx context.Context, cmd *cli.Command) error {
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
		case errors.Is(err, osvscanner.ErrNoPackagesFound):
			cmdlogger.Errorf("No package sources found, --help for usage information.")
			return 128
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
