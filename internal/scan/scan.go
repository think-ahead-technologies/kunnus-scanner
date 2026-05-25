// ABOUTME: Thin wrapper around scalibr.New().Scan(). Owns the per-plugin status reporting.
// ABOUTME: The only package that imports the scalibr Scanner; everything else stays decoupled.
package scan

import (
	"context"
	"fmt"
	"io"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Result wraps the scalibr inventory with the per-plugin statuses so callers
// can surface partial failures without re-importing scalibr types deeper in
// the call graph.
type Result struct {
	Inventory      inventory.Inventory
	PluginStatuses []*plugin.Status
}

// Run executes the scan described by cfg and writes a one-line summary of any
// plugin failures to logOut. It returns Result on overall success or partial
// success, and an error only when the scan as a whole failed (bad config,
// no scan root, etc.). Per-plugin failures are reported via logOut, not error.
func Run(ctx context.Context, cfg *scalibr.ScanConfig, logOut io.Writer) (*Result, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil ScanConfig")
	}

	res := scalibr.New().Scan(ctx, cfg)
	if res == nil {
		return nil, fmt.Errorf("scalibr returned nil result")
	}

	if res.Status != nil && res.Status.Status == plugin.ScanStatusFailed {
		return nil, fmt.Errorf("scan failed: %s", res.Status.FailureReason)
	}

	for _, ps := range res.PluginStatus {
		if ps == nil || ps.Status == nil || ps.Status.FailureReason == "" {
			continue
		}
		_, _ = fmt.Fprintf(logOut, "plugin %s v%d: %s\n", ps.Name, ps.Version, ps.Status.FailureReason)
	}

	return &Result{
		Inventory:      res.Inventory,
		PluginStatuses: res.PluginStatus,
	}, nil
}
