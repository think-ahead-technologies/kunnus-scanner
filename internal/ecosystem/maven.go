// ABOUTME: Maven ecosystem. Detected via pom.xml; scanned by scalibr's pomxml + archive extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

var maven = Ecosystem{
	Name:           "maven",
	Filenames:      []string{"pom.xml"},
	ScalibrPlugins: []string{"java/pomxml", "java/archive"},
}
