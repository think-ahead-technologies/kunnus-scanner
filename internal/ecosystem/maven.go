// ABOUTME: Maven ecosystem. Detected via pom.xml; scanned by scalibr's pomxml + archive extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
)

var maven = Ecosystem{
	Name:           "maven",
	Filenames:      []string{"pom.xml"},
	ScalibrPlugins: []string{pomxml.Name, archive.Name},
}
