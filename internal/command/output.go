// ABOUTME: Atomic SBOM output sink — stdout passthrough or temp-file-then-rename.
// ABOUTME: Keeps the durable-write plumbing out of the scan-and-encode pipeline.
package command

import (
	"io"
	"os"
	"path/filepath"
)

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
