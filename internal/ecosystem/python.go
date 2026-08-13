// ABOUTME: Python ecosystem aggregate. Six lockfile formats contribute SHA-256 hashes; setup.py flags detection only.
// ABOUTME: poetry.lock and pdm.lock share the same TOML schema and parse function.
package ecosystem

import (
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/condameta"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pyprojecttoml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setup"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
)

// condameta matches paths like "envs/<env>/conda-meta/<pkg>.json" — a path
// pattern, not a basename, so kunnus detection alone cannot trigger it. The
// extractor runs whenever any other Python marker (pyproject.toml,
// requirements.txt, ...) flags the ecosystem. A pure-conda environment with no
// other Python markers would slip through detection.
//
// pylock.toml is PEP 751's standard lockfile. The spec also permits
// "pylock.<name>.toml" for named variants, which scalibr's extractor matches
// but detection here does not: a basename table cannot hold a glob, and a
// project carrying only a named variant is vanishingly rare (its pyproject.toml
// flags the ecosystem anyway). Same shape of gap as condameta's.
var python = Ecosystem{
	Name:      "python",
	Filenames: []string{"pyproject.toml", "poetry.lock", "pdm.lock", "Pipfile.lock", "pylock.toml", "requirements.txt", "setup.py", "uv.lock"},
	ScalibrPlugins: []string{
		poetrylock.Name, pdmlock.Name, pipfilelock.Name, pylock.Name,
		pyprojecttoml.Name, requirements.Name, setup.Name, uvlock.Name,
		wheelegg.Name, condameta.Name,
	},
	InstalledPlugins: []string{wheelegg.Name},
	HashParsers: []Parser{
		{Name: "poetry", Filenames: []string{"poetry.lock"}, Parse: parsePyPIPackagesFilesLock},
		{Name: "pdm", Filenames: []string{"pdm.lock"}, Parse: parsePyPIPackagesFilesLock},
		{Name: "pipfile", Filenames: []string{"Pipfile.lock"}, Parse: parsePipfileLock},
		{Name: "pylock", Filenames: []string{"pylock.toml"}, Parse: parsePylock},
		{Name: "uv", Filenames: []string{"uv.lock"}, Parse: parseUvLock},
		{Name: "requirements", Filenames: []string{"requirements.txt"}, Parse: parseRequirementsTxt},
	},
}
