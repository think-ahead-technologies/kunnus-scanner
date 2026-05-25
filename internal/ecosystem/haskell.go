// ABOUTME: Haskell ecosystem. Detected via cabal.project.freeze / stack.yaml.lock; scanned by scalibr's cabal + stacklock extractors.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

var haskell = Ecosystem{
	Name:           "haskell",
	Filenames:      []string{"cabal.project.freeze", "stack.yaml.lock"},
	ScalibrPlugins: []string{"haskell/cabal", "haskell/stacklock"},
}
