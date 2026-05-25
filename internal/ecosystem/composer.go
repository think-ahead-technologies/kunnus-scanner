// ABOUTME: PHP/Composer ecosystem. Detected via composer.json / composer.lock; scanned by scalibr's php/composerlock.
// ABOUTME: No kunnus-side hash parser yet — Composer's lockfile carries integrity values but we don't mine them.
package ecosystem

var composer = Ecosystem{
	Name:           "composer",
	Filenames:      []string{"composer.json", "composer.lock"},
	ScalibrPlugins: []string{"php/composerlock"},
}
