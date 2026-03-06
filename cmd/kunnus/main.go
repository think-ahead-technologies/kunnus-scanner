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
	"strings"

	kversion "github.com/google/osv-scanner/v2/cmd/kunnus/internal/version"
	"github.com/google/osv-scanner/v2/cmd/kunnus/sbom"
	"github.com/google/osv-scanner/v2/cmd/kunnus/upload"
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
		Name:    "kunnus",
		Version: kversion.KunnusVersion,
		Usage:   "SBOM generation and vulnerability scanning",
		Description: `Generate SBOMs and scan for vulnerabilities.

Examples:
   kunnus sbom                          # generate SBOM for current directory
   kunnus sbom --output sbom.spdx.json  # save SBOM to file
   kunnus upload sbom.spdx.json \       # upload SBOM to Kunnus platform
     --api-key $KUNNUS_API_KEY \
     --component-id $KUNNUS_COMPONENT_ID

Exit codes:
   0  success
   1  vulnerabilities found
   2  error (invalid arguments, scan failure, etc.)
   3  network or API request failed`,
		Suggest:               true,
		Writer:                stdout,
		ErrWriter:             stderr,
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "verbosity",
				Usage:       "log verbosity level; value can be: " + strings.Join(cmdlogger.Levels(), ", "),
				Value:       "warn",
				DefaultText: "warn",
				Action: func(_ context.Context, _ *cli.Command, s string) error {
					_, err := cmdlogger.ParseLevel(s)
					return err
				},
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "suppress progress and summary output on stderr; only errors are printed",
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			if lvl, err := cmdlogger.ParseLevel(cmd.String("verbosity")); err == nil {
				cmdlogger.SetLevel(lvl)
			}

			return ctx, nil
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("unknown command %q — run 'kunnus --help' for usage", cmd.Args().First())
			}

			return cli.ShowAppHelp(cmd)
		},
		Commands: []*cli.Command{
			sbom.Command(stdout, stderr, client),
			upload.Command(stdout, stderr, client),
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
			return 3
		}
		cmdlogger.Errorf("%v", err)
	}

	if logger.HasErrored() {
		return 2
	}

	return 0
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr, nil))
}
