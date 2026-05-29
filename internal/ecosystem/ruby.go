// ABOUTME: Ruby ecosystem. Detected via Gemfile / Gemfile.lock; scanned by scalibr's ruby/gemfilelock.
// ABOUTME: No kunnus-side hash parser yet.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
)

var ruby = Ecosystem{
	Name:             "ruby",
	Filenames:        []string{"Gemfile", "Gemfile.lock"},
	FilenameSuffixes: []string{".gemspec"},
	ScalibrPlugins:   []string{gemfilelock.Name, gemspec.Name},
	InstalledPlugins: []string{gemspec.Name},
}
