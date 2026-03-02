//go:build windows

package sbom

import (
	"context"

	"github.com/google/osv-scalibr/extractor/standalone"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"

	"github.com/google/osv-scalibr/extractor/standalone/windows/ospackages"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regosversion"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regpatchlevel"
)

// runWindowsScan extracts Windows OS packages, OS version, and patch level from the registry.
// Per-extractor failures surface in the []*plugin.Status slice, not in the returned error;
// only configuration-level errors are returned. The status slice is intentionally ignored here.
func runWindowsScan(ctx context.Context) (inventory.Inventory, error) {
	cfg := &standalone.Config{
		Extractors: []standalone.Extractor{
			ospackages.NewDefault(),
			regosversion.NewDefault(),
			regpatchlevel.NewDefault(),
		},
		// Registry extractors don't use the path; any real root works.
		ScanRoot: scalibrfs.RealFSScanRoot(`C:\`),
	}

	inv, _, err := standalone.Run(ctx, cfg)

	return inv, err
}
