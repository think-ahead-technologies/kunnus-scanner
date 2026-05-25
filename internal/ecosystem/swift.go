// ABOUTME: Swift / CocoaPods ecosystem. Detected via Package.resolved / Podfile.lock; scanned by scalibr's swift extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

var swift = Ecosystem{
	Name:           "swift",
	Filenames:      []string{"Package.resolved", "Podfile.lock"},
	ScalibrPlugins: []string{"swift/packageresolved", "swift/podfilelock"},
}
