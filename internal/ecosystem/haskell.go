// ABOUTME: Haskell ecosystem. Detected via cabal.project.freeze / stack.yaml.lock; scanned by scalibr's cabal + stacklock extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/stacklock"
)

var haskell = Ecosystem{
	Name:           "haskell",
	Filenames:      []string{"cabal.project.freeze", "stack.yaml.lock"},
	ScalibrPlugins: []string{cabal.Name, stacklock.Name},
}
