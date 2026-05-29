// ABOUTME: The partial-scan error: scan finished but some plugins failed.
// ABOUTME: Lets the CLI exit non-zero on a degraded scan without discarding the SBOM it did produce.
package command

import (
	"fmt"
	"strings"

	"github.com/google/osv-scalibr/plugin"
)

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

// partialScanError reports that the scan finished but one or more plugins
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
