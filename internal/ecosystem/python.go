// ABOUTME: Python ecosystem aggregate. Five lockfile formats contribute SHA-256 hashes; pyproject.toml and setup.py flag detection only.
// ABOUTME: poetry.lock and pdm.lock share the same TOML schema and parse function.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setup"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
)

var python = Ecosystem{
	Name:      "python",
	Filenames: []string{"pyproject.toml", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.txt", "setup.py", "uv.lock"},
	ScalibrPlugins: []string{
		poetrylock.Name, pdmlock.Name, pipfilelock.Name,
		requirements.Name, setup.Name, uvlock.Name, wheelegg.Name,
	},
	HashParsers: []Parser{
		{Name: "poetry", Filenames: []string{"poetry.lock"}, Parse: parsePyPIPackagesFilesLock},
		{Name: "pdm", Filenames: []string{"pdm.lock"}, Parse: parsePyPIPackagesFilesLock},
		{Name: "pipfile", Filenames: []string{"Pipfile.lock"}, Parse: parsePipfileLock},
		{Name: "uv", Filenames: []string{"uv.lock"}, Parse: parseUvLock},
		{Name: "requirements", Filenames: []string{"requirements.txt"}, Parse: parseRequirementsTxt},
	},
}
