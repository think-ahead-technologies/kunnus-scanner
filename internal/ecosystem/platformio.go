// ABOUTME: PlatformIO ecosystem — embedded projects declaring library dependencies in platformio.ini lib_deps.
// ABOUTME: Detection only; components come from the kunnus-native internal/platformio extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// platformio detects PlatformIO embedded projects by their platformio.ini
// project configuration. PlatformIO has no scalibr extractor, so this entry
// declares no ScalibrPlugins and instead sets NativeExtractor: mode/repo
// appends internal/platformio.New() when this ecosystem is detected — the same
// split as modustoolbox.
var platformio = Ecosystem{
	Name:            "platformio",
	Filenames:       []string{"platformio.ini"},
	NativeExtractor: true,
}
