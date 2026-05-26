// ABOUTME: R ecosystem. Detected via renv.lock; scanned by scalibr's r/renvlock.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
)

var r = Ecosystem{
	Name:           "r",
	Filenames:      []string{"renv.lock"},
	ScalibrPlugins: []string{renvlock.Name},
}
