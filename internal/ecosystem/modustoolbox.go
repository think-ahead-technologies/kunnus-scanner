// ABOUTME: ModusToolbox ecosystem — Infineon/Cypress embedded firmware whose dependencies live in .mtb manifests.
// ABOUTME: Detection only; components come from the kunnus-native internal/modustoolbox extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// modustoolbox detects Infineon ModusToolbox projects by their per-dependency
// ".mtb" manifest files. ModusToolbox has no scalibr extractor, so this entry
// declares no ScalibrPlugins and instead sets NativeExtractor: mode/repo
// appends internal/modustoolbox.New() when this ecosystem is detected. Keeping
// the marker here (rather than detecting .mtb inside the mode) preserves the
// rule that detection and plugin selection live in one place and cannot drift.
var modustoolbox = Ecosystem{
	Name:             "modustoolbox",
	FilenameSuffixes: []string{".mtb"},
	NativeExtractor:  true,
}
