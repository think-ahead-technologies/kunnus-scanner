// ABOUTME: Shared scan-and-encode pipeline used by every sbom subcommand.
// ABOUTME: Each subcommand picks its Mode and hands it here; the rest is mode-agnostic.
package command

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/plugin"
	"github.com/urfave/cli/v3"

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

	if err := sbom.Encode(sink.w, result, plan.Component, plan.Hashes, plan.ExtraComponents); err != nil {
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

// sbomSink wraps the destination of a generated SBOM with explicit commit and
// abort steps. For stdout both are no-ops. For files, the writer is a sibling
// temp file; commit fsyncs, closes, and renames onto the final path; abort
// closes and removes the temp file.
type sbomSink struct {
	w      io.Writer
	commit func() error
	abort  func()
}

// openOutput returns an sbomSink that writes either to stdout (path "" or "-")
// or to a sibling temp file that is renamed onto path when commit succeeds.
// The parent directory of a file target must already exist — we surface that
// as an error so callers don't have to worry about partial cleanup.
func openOutput(path string) (*sbomSink, error) {
	if path == "" || path == "-" {
		return &sbomSink{
			w:      os.Stdout,
			commit: func() error { return nil },
			abort:  func() {},
		}, nil
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()

	return &sbomSink{
		w: tmp,
		commit: func() error {
			if err := tmp.Sync(); err != nil {
				_ = tmp.Close()
				_ = os.Remove(tmpPath)
				return err
			}
			if err := tmp.Close(); err != nil {
				_ = os.Remove(tmpPath)
				return err
			}
			return os.Rename(tmpPath, path)
		},
		abort: func() {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		},
	}, nil
}

// failedPlugins returns the names of plugins whose ScanStatus carries a
// non-empty FailureReason. scan.Run already logs these at WARN; this is the
// caller-facing list that drives the process exit code.
func failedPlugins(statuses []*plugin.Status) []string {
	var failed []string
	for _, ps := range statuses {
		if ps == nil || ps.Status == nil || ps.Status.FailureReason == "" {
			continue
		}
		failed = append(failed, ps.Name)
	}
	return failed
}

// pluginFailureError reports that the scan finished but one or more plugins
// failed. The SBOM has already been written to disk; the caller treats this
// as a non-zero exit so CI can distinguish "clean scan" from "degraded scan".
type partialScanError struct {
	plugins []string
}

func (e *partialScanError) Error() string {
	return fmt.Sprintf("scan completed with %d plugin failure(s): %s (SBOM written; see warnings above for per-plugin details)",
		len(e.plugins), strings.Join(e.plugins, ", "))
}

func pluginFailureError(names []string) error {
	if len(names) == 0 {
		return nil
	}
	return &partialScanError{plugins: names}
}
