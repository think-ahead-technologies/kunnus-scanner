// ABOUTME: Swift / CocoaPods ecosystem. Detected via Package.resolved / Podfile.lock; scanned by scalibr's swift extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/packageresolved"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/podfilelock"
)

var swift = Ecosystem{
	Name:           "swift",
	Filenames:      []string{"Package.resolved", "Podfile.lock"},
	ScalibrPlugins: []string{packageresolved.Name, podfilelock.Name},
}
