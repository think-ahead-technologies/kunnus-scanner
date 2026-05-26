// ABOUTME: Shared scan-and-encode pipeline used by every sbom subcommand.
// ABOUTME: Each subcommand picks its Mode and (optionally) its hash sources, then hands them here.
package command

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// runScan plans the scan via m, runs it, and encodes the SBOM to the requested
// output. hashMap carries native deployable hashes harvested by the caller; pass
// nil when the mode has no hash sources of its own (e.g. OS scans).
func runScan(ctx context.Context, cmd *cli.Command, m mode.Mode, path string, ov mode.Overrides, hashMap hashes.Map) error {
	cfg, comp, err := m.Plan(ctx, path, ov)
	if err != nil {
		return fmt.Errorf("plan %s scan: %w", m.Name(), err)
	}

	result, err := scan.Run(ctx, cfg, os.Stderr)
	if err != nil {
		return fmt.Errorf("run scan: %w", err)
	}

	out, closer, err := openOutput(cmd.String("output"))
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer closer()

	if err := sbom.Encode(out, result, comp, hashMap); err != nil {
		return fmt.Errorf("encode sbom: %w", err)
	}
	return nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}
