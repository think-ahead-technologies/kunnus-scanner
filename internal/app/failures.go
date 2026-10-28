// ABOUTME: Names the plugins a completed scan reported failures for.
// ABOUTME: Separated from the use case so the reporting rule has one obvious home.
package app

import "github.com/google/osv-scalibr/plugin"

// failedPlugins names the plugins whose ScanStatus carries a FailureReason.
// scan.Run already logs these at WARN; this is the caller-facing list, which
// the CLI turns into a non-zero exit.
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
