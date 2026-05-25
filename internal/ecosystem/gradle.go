// ABOUTME: Gradle ecosystem. Detected via build.gradle*/gradle.lockfile; scanned by scalibr's gradle extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

var gradle = Ecosystem{
	Name:           "gradle",
	Filenames:      []string{"build.gradle", "build.gradle.kts", "gradle.lockfile"},
	ScalibrPlugins: []string{"java/gradlelockfile", "java/gradleverificationmetadataxml"},
}
