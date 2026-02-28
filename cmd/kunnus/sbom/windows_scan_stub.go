// ABOUTME: Stub for runWindowsScan on non-Windows platforms.
// ABOUTME: Returns an empty inventory so the caller can proceed without OS-level registry access.

//go:build !windows

package sbom

import (
	"context"

	"github.com/google/osv-scalibr/inventory"
)

// runWindowsScan returns an empty inventory on non-Windows platforms.
func runWindowsScan(_ context.Context) (inventory.Inventory, error) {
	return inventory.Inventory{}, nil
}
