// ABOUTME: The driven ports: what the use case needs from the outside, declared by the side that needs it.
// ABOUTME: internal/scan and internal/sbom are the production implementations; Service wires them by default.
package app

import (
	"context"
	"io"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/artifact/image"

	"github.com/think-ahead/kunnus-scanner/internal/sbom"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// Scanner runs a planned scan. The two methods mirror the two scalibr entry
// points; the use case picks between them on Plan.Image, which keeps the
// mode-shaped dispatch here rather than in the adapter.
//
// Implemented by scan.Scanner.
type Scanner interface {
	Run(ctx context.Context, cfg *scalibr.ScanConfig) (*scan.Result, error)
	RunContainer(ctx context.Context, img image.Image, cfg *scalibr.ScanConfig) (*scan.Result, error)
}

// Encoder writes one SBOM document. Implemented by sbom.Encoder.
type Encoder interface {
	Encode(out io.Writer, opts sbom.Options) error
}
