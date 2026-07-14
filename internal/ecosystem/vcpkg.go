// ABOUTME: vcpkg ecosystem — C/C++ projects declaring dependencies in a vcpkg.json manifest.
// ABOUTME: Detection only; components come from the kunnus-native internal/vcpkg extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// vcpkg detects vcpkg manifest-mode projects by their vcpkg.json. vcpkg has no
// scalibr extractor, so this entry declares no ScalibrPlugins and instead sets
// NativeExtractor: mode/repo appends internal/vcpkg.New() when this ecosystem
// is detected — the same split as modustoolbox, keeping detection and plugin
// selection in one place. Classic mode (a CONTROL file per port inside a vcpkg
// checkout) is not detected: scanning the package manager's own tree is not a
// project scan.
var vcpkg = Ecosystem{
	Name:            "vcpkg",
	Filenames:       []string{"vcpkg.json"},
	NativeExtractor: true,
}
