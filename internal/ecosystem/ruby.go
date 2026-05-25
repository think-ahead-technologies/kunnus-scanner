// ABOUTME: Ruby ecosystem. Detected via Gemfile / Gemfile.lock; scanned by scalibr's ruby/gemfilelock.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

var ruby = Ecosystem{
	Name:           "ruby",
	Filenames:      []string{"Gemfile", "Gemfile.lock"},
	ScalibrPlugins: []string{"ruby/gemfilelock"},
}
