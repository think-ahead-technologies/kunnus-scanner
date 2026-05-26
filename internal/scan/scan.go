// ABOUTME: Thin wrapper around scalibr.New().Scan(). Owns the per-plugin status reporting.
// ABOUTME: The only package that imports the scalibr Scanner; everything else stays decoupled.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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

// Run executes the scan described by cfg. Per-plugin failures are logged at
// warn level via slog.Default() and surfaced as Result.PluginStatuses; an
// error is returned only when the scan as a whole failed (bad config, no scan
// root, etc.).
func Run(ctx context.Context, cfg *scalibr.ScanConfig) (*Result, error) {
	if cfg == nil {
		return nil, errors.New("nil ScanConfig")
	}

	res := scalibr.New().Scan(ctx, cfg)
	if res == nil {
		return nil, errors.New("scalibr returned nil result")
	}

	if res.Status != nil && res.Status.Status == plugin.ScanStatusFailed {
		return nil, fmt.Errorf("scan failed: %s", res.Status.FailureReason)
	}

	for _, ps := range res.PluginStatus {
		if ps == nil || ps.Status == nil || ps.Status.FailureReason == "" {
			continue
		}
		slog.Warn("scalibr plugin failed",
			"name", ps.Name,
			"version", ps.Version,
			"reason", ps.Status.FailureReason,
		)
	}

	return &Result{
		Inventory:      res.Inventory,
		PluginStatuses: res.PluginStatus,
	}, nil
}
