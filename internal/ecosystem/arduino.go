// ABOUTME: Arduino ecosystem — sketches declaring dependencies in sketch.yaml profiles and libraries vendored with library.properties metadata.
// ABOUTME: Detection only; components come from the kunnus-native internal/arduino extractor the mode wires in (no scalibr plugin exists).
package ecosystem

// arduino detects Arduino projects by two component-bearing files: each
// vendored library's library.properties (the library's own name/version
// metadata, .gemspec-style) and arduino-cli's sketch.yaml (build profiles
// pinning libraries and platform cores). Arduino has no scalibr extractor, so
// this entry sets NativeExtractor: mode/repo appends internal/arduino.New()
// when this ecosystem is detected — the same split as modustoolbox.
var arduino = Ecosystem{
	Name:            "arduino",
	Filenames:       []string{"library.properties", "sketch.yaml", "sketch.yml"},
	NativeExtractor: true,
}
