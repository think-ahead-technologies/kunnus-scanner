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
// Output is written atomically: file targets stage to a sibling temp file that
// is fsync'd and renamed only after generation succeeds. If the process is
// killed or encoding fails mid-write, the final path either stays absent or
// keeps its pre-existing contents.
//
// When the scan finishes but some plugins reported failures, the SBOM still
// lands at the requested output and a non-nil error names the failed plugins
// so the CLI exits non-zero. Callers that only care about partial success can
// inspect this via errors.As(err, &partialScanError{}).
func runScan(ctx context.Context, cmd *cli.Command, m mode.Mode, target string, ov mode.Overrides) error {
	// A malformed author must fail before the scan; the rest of the request is
	// validated by the use case itself.
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

	res, err := app.GenerateSBOM(ctx, sink.w, req)
	if err != nil {
		// A rejected request names the field it came from; report it as the
		// flag the user actually typed.
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
