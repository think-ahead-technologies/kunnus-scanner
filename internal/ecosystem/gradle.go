// ABOUTME: Gradle ecosystem. Detected via build.gradle*/gradle.lockfile; scanned by scalibr's gradle extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
)

var gradle = Ecosystem{
	Name:           "gradle",
	Filenames:      []string{"build.gradle", "build.gradle.kts", "gradle.lockfile"},
	ScalibrPlugins: []string{gradlelockfile.Name, gradleverificationmetadataxml.Name},
}
