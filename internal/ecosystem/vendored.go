// ABOUTME: Exposes vendored C/C++ discovery through the target-introspection layer.
// ABOUTME: Delegates directory detection and per-file digests to the vendored package.
package ecosystem

import (
	"io/fs"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
	"github.com/think-ahead/kunnus-scanner/internal/vendored"
)

// SurveyVendored returns vendored C/C++ library hits and their per-file hashes.
// It runs independently of lockfile detection so vendored-only repositories
// are supported; directories without C/C++ source produce no hits.
func SurveyVendored(fsys fs.FS) ([]vendored.Hit, hashes.Map) {
	return vendored.Survey(fsys)
}
