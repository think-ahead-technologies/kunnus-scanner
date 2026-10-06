// ABOUTME: Scanner is the struct form of Run/RunContainer, satisfying the port internal/app declares.
// ABOUTME: The package functions stay: they are what the integration tests and this type both call.
package scan

import (
	"context"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/artifact/image"
)

// Scanner adapts this package to the scanner port. It holds no state — the
// type exists so the use case can name what it depends on.
type Scanner struct{}

// Run executes a filesystem scan. See the package-level Run.
func (Scanner) Run(ctx context.Context, cfg *scalibr.ScanConfig) (*Result, error) {
	return Run(ctx, cfg)
}

// RunContainer executes a container-image scan. See the package-level RunContainer.
func (Scanner) RunContainer(ctx context.Context, img image.Image, cfg *scalibr.ScanConfig) (*Result, error) {
	return RunContainer(ctx, img, cfg)
}
