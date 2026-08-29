// ABOUTME: Names the plugins a completed scan reported failures for.
// ABOUTME: Separated from the use case so the reporting rule has one obvious home.
package app

import "github.com/google/osv-scalibr/plugin"

// failedPlugins returns the names of plugins whose ScanStatus carries a
// non-empty FailureReason. scan.Run already logs these at WARN; this is the
// caller-facing list, which the CLI turns into a non-zero exit so CI can tell
// a clean scan from a degraded one.
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
