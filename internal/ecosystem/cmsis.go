// ABOUTME: CMSIS-Solution ecosystem — ARM/Keil embedded projects declaring software packs in *.csolution.yml files.
// ABOUTME: Detection only; components come from the kunnus-native internal/cmsis extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// cmsis detects Open-CMSIS-Pack solution workspaces (Keil MDK, STM32/NXP/
// Infineon vendor toolchains) by their *.csolution.yml file, which declares
// the software packs (`Vendor::Pack@version`) the build consumes. Packs are
// solution-level in the csolution spec, so *.cproject.yml / *.clayer.yml are
// not markers. CMSIS has no scalibr extractor, so this entry sets
// NativeExtractor: mode/repo appends internal/cmsis.New() when this ecosystem
// is detected — the same split as modustoolbox.
var cmsis = Ecosystem{
	Name:             "cmsis",
	FilenameSuffixes: []string{".csolution.yml", ".csolution.yaml"},
	NativeExtractor:  true,
}
