// ABOUTME: Translates a parsed command line into an app.Request and runs the use case.
// ABOUTME: Everything CLI-shaped stays here: flag reads, the atomic output sink, the exit code.
package command

import (
	"context"
	"errors"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/app"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

// runScan builds the request for m from the parsed flags, runs the use case,
// and writes the SBOM to the requested output.
//
// File output is atomic: a sibling temp file is fsync'd and renamed only once
// generation succeeds, so a killed process leaves the final path absent or
// untouched. A scan whose plugins partly failed still writes, and returns a
// partialScanError so the CLI exits non-zero.
func runScan(ctx context.Context, cmd *cli.Command, m mode.Mode, target string, ov mode.Overrides) error {
	// The use case validates the rest of the request itself.
	author, err := parseAuthor(cmd.String("author"))
	if err != nil {
		return fmt.Errorf("--author: %w", err)
	}

	req := app.Request{
		Mode:             m,
		Target:           target,
		Overrides:        ov,
		ComponentID:      cmd.String("component-id"),
		ComponentVersion: cmd.String("component-version"),
		Author:           author,
		SerialNumber:     cmd.String("serial-number"),
	}

	sink, err := openOutput(cmd.String("output"))
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			sink.abort()
		}
	}()

	res, err := app.New().GenerateSBOM(ctx, sink.w, req)
	if err != nil {
		// Report a rejected field as the flag the user typed.
		var invalid *app.InvalidRequestError
		if errors.As(err, &invalid) {
			if flag, ok := flagForRequestField[invalid.Field]; ok {
				return fmt.Errorf("--%s: %w", flag, err)
			}
		}
		return err
	}
	if err := sink.commit(); err != nil {
		return fmt.Errorf("commit sbom: %w", err)
	}
	committed = true

	return pluginFailureError(res.FailedPlugins)
}
