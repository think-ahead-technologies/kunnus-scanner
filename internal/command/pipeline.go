// ABOUTME: Shared scan-and-encode pipeline used by every sbom subcommand.
// ABOUTME: Each subcommand picks its Mode and hands it here; the rest is mode-agnostic.
package command

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/graph"
	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/license"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/ownership"
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
func runScan(ctx context.Context, cmd *cli.Command, m mode.Mode, target string, ov mode.Overrides) error {
	// Validate the serial override up front: a malformed --serial-number must
	// fail before the (potentially expensive) scan, not after.
	serial := cmd.String("serial-number")
	if serial != "" {
		var err error
		if serial, err = sbom.NormalizeSerial(serial); err != nil {
			return fmt.Errorf("--serial-number: %w", err)
		}
	}

	// a malformed author must fail before the scan.
	author, err := parseAuthor(cmd.String("author"))
	if err != nil {
		return fmt.Errorf("--author: %w", err)
	}
	// The CLI cannot know who operates it: unset, the document falls back to
	// the kunnus creator identity — correct when think-ahead runs the scan,
	// a placeholder for everyone else. Say so instead of guessing.
	if author.IsZero() {
		slog.Warn("no --author given; recording Kunnus as SBOM author — pass --author \"Name <email>\" to name your organization")
	}

	plan, err := m.Plan(ctx, target, ov)
	if err != nil {
		return fmt.Errorf("plan %s scan: %w", m.Name(), err)
	}

	result, err := runPlan(ctx, plan)
	if err != nil {
		return fmt.Errorf("run %s scan: %w", m.Name(), err)
	}

	// Most digests are harvested during planning (plan.Hashes); a mode whose
	// digests depend on scan output (container apk checksums) supplies a
	// post-scan recovery hook instead. Merge the two so the encoder sees one map.
	hashMap := plan.Hashes
	if plan.PostScanHashes != nil {
		hashMap = mergeHashMaps(hashMap, plan.PostScanHashes(result.Inventory))
	}

	// Flags refine the mode's component identity: an explicit --component-id /
	// --component-version wins over anything the planner derived from the
	// target. The series key is built from the final values so the serial
	// derivation and the SBOM's root component can never disagree.
	component := plan.Component
	if id := cmd.String("component-id"); id != "" {
		component.ID = id
	}
	if v := cmd.String("component-version"); v != "" {
		component.Version = v
	}
	series := bom.Series{
		Mode:    m.Name(),
		ID:      component.ID,
		Version: component.Version,
		Serial:  serial,
	}

	return encodeResult(cmd, result, component, series, plan.Lifecycle, author, hashMap, plan.Licenses, plan.Graph, plan.ExtraComponents, plan.OwnedFiles)
}

// runPlan dispatches to the matching scalibr scan: a container scan when the
// mode opened an image, otherwise a filesystem scan over the configured scan
// roots. Keeping the branch here lets internal/scan stay free of mode types.
func runPlan(ctx context.Context, plan *mode.Plan) (*scan.Result, error) {
	if plan.Image != nil {
		return scan.RunContainer(ctx, plan.Image, plan.Config)
	}
	return scan.Run(ctx, plan.Config)
}

// mergeHashMaps folds extra into base, tolerating nil on either side, and
// returns the combined map.
func mergeHashMaps(base, extra hashes.Map) hashes.Map {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		return extra
	}
	base.Merge(extra)
	return base
}

// encodeResult writes the SBOM for a completed scan to the requested output and
// returns a non-nil error naming any failed plugins so the CLI exits non-zero.
// Shared by every scan flavour: the steps after a scan completes are identical
// whether the result came from scan.Run or scan.RunContainer.
func encodeResult(cmd *cli.Command, result *scan.Result, component bom.ComponentInfo, series bom.Series, lifecycle bom.Lifecycle, author bom.Author, h hashes.Map, lic license.Map, edges graph.Map, extras []bom.ExtraComponent, owned ownership.Set) error {
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

	if err := sbom.Encode(sink.w, result, component, series, lifecycle, author, h, lic, edges, extras, owned); err != nil {
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
