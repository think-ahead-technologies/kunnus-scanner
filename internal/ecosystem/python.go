// ABOUTME: Python ecosystem aggregate. Five lockfile formats contribute SHA-256 hashes; pyproject.toml and setup.py flag detection only.
// ABOUTME: poetry.lock and pdm.lock share the same TOML schema and parse function.
package ecosystem

var python = Ecosystem{
	Name:      "python",
	Filenames: []string{"pyproject.toml", "poetry.lock", "pdm.lock", "Pipfile.lock", "requirements.txt", "setup.py", "uv.lock"},
	ScalibrPlugins: []string{
		"python/poetrylock", "python/pdmlock", "python/pipfilelock",
		"python/requirements", "python/setup", "python/uvlock", "python/wheelegg",
	},
	HashParsers: []Parser{
		{Name: "poetry", Filenames: []string{"poetry.lock"}, Parse: parsePyPIPackagesFilesLock},
		{Name: "pdm", Filenames: []string{"pdm.lock"}, Parse: parsePyPIPackagesFilesLock},
		{Name: "pipfile", Filenames: []string{"Pipfile.lock"}, Parse: parsePipfileLock},
		{Name: "uv", Filenames: []string{"uv.lock"}, Parse: parseUvLock},
		{Name: "requirements", Filenames: []string{"requirements.txt"}, Parse: parseRequirementsTxt},
	},
}
