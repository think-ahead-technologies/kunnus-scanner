// ABOUTME: Zephyr ecosystem — RTOS workspaces declaring their module tree in a west.yml manifest.
// ABOUTME: Detection only; components come from the kunnus-native internal/zephyr extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// zephyr detects Zephyr RTOS workspaces by their west manifest. Zephyr has no
// scalibr extractor, so this entry declares no ScalibrPlugins and instead sets
// NativeExtractor: mode/repo appends internal/zephyr.New() when this ecosystem
// is detected — the same split as modustoolbox.
var zephyr = Ecosystem{
	Name:            "zephyr",
	Filenames:       []string{"west.yml", "west.yaml"},
	NativeExtractor: true,
}
