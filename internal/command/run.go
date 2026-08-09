// ABOUTME: Entry point for the command layer: builds the root CLI and runs it.
// ABOUTME: Keeps urfave/cli encapsulated here so cmd/kunnus is just the binary shell.
package command

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/urfave/cli/v3"

	klog "github.com/think-ahead/kunnus-scanner/internal/log"
	"github.com/think-ahead/kunnus-scanner/internal/version"
)

// Run builds the root kunnus command and executes it with the given args.
// commit and date are injected at build time by goreleaser and surface in
// `kunnus --version`. Returns the process exit code.
func Run(ctx context.Context, args []string, commit, date string) int {
	app := newApp(commit, date)

	if err := app.Run(ctx, args); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "kunnus:", err)
		return 1
	}
	return 0
}

// newApp builds the root kunnus command. Split out of Run so tests can drive
// the real command tree with their own writers instead of the process's.
func newApp(commit, date string) *cli.Command {
	cli.VersionPrinter = func(cmd *cli.Command) {
		_, _ = fmt.Fprintf(os.Stdout, "kunnus %s (commit %s, built %s)\n", cmd.Version, commit, date)
	}

	app := &cli.Command{
		Name:    "kunnus",
		Usage:   "Generate SBOMs and upload them to the Kunnus platform",
		Version: version.Version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "verbosity",
				Value:   "warn",
				Sources: cli.EnvVars("KUNNUS_VERBOSITY"),
				Usage:   "log level: " + strings.Join(klog.Levels(), " | "),
			},
		},
		Before:                installLogger,
		Action:                dispatchOnly,
		Commands:              []*cli.Command{sbomCmd(), uploadCmd()},
		EnableShellCompletion: true,
	}
	installCompletion(app)
	return app
}

// installLogger reads --verbosity, builds a stderr text logger, and installs
// it as the slog default plus scalibr's logger. Operational output goes to
// stderr unconditionally so stdout can carry the SBOM payload.
func installLogger(ctx context.Context, cmd *cli.Command) (context.Context, error) {
	lvl, err := klog.ParseLevel(cmd.String("verbosity"))
	if err != nil {
		return ctx, err
	}
	logger := klog.New(lvl, os.Stderr)
	slog.SetDefault(logger)
	scalibrlog.SetLogger(&klog.ScalibrAdapter{Logger: logger})
	return ctx, nil
}
