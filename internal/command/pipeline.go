// ABOUTME: Shared scan-and-encode pipeline used by every sbom subcommand.
// ABOUTME: Each subcommand picks its Mode and hands it here; the rest is mode-agnostic.
package command

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// runScan plans the scan via m, runs it, and encodes the SBOM to the requested
// output. The Plan returned by Mode carries any native digests the mode
// harvested while walking the tree, so this pipeline never walks again itself.
//
// Output is written atomically: file targets stage to a sibling temp file that
// is fsync'd and renamed only after Encode succeeds. If the process is killed
// or Encode fails mid-write, the final path either stays absent or keeps its
// pre-existing contents.
//
// When the scan finishes but some plugins reported failures, the SBOM still
// lands at the requested output and a non-nil error names the failed plugins
// so the CLI exits non-zero. Callers that only care about partial success can
// inspect this via errors.As(err, &partialScanError{}).
func runScan(ctx context.Context, cmd *cli.Command, m mode.Mode, path string, ov mode.Overrides) error {
	plan, err := m.Plan(ctx, path, ov)
	if err != nil {
		return fmt.Errorf("plan %s scan: %w", m.Name(), err)
	}

	result, err := scan.Run(ctx, plan.Config)
	if err != nil {
		return fmt.Errorf("run scan: %w", err)
	}

	return encodeResult(cmd, result, plan.Component, plan.Hashes, plan.Licenses, plan.ExtraComponents)
}

// encodeResult writes the SBOM for a completed scan to the requested output and
// returns a non-nil error naming any failed plugins so the CLI exits non-zero.
// Shared by every scan flavour: the steps after a scan completes are identical
// whether the result came from scan.Run or scan.RunContainer.
func encodeResult(cmd *cli.Command, result *scan.Result, component bom.ComponentInfo, h hashes.Map, lic license.Map, extras []bom.ExtraComponent) error {
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

	if err := sbom.Encode(sink.w, result, component, h, lic, extras); err != nil {
		return fmt.Errorf("encode sbom: %w", err)
	}
	if err := sink.commit(); err != nil {
		return fmt.Errorf("commit sbom: %w", err)
	}
	committed = true

	if failed := failedPlugins(result.PluginStatuses); len(failed) > 0 {
		return pluginFailureError(failed)
	}
	return nil
}
