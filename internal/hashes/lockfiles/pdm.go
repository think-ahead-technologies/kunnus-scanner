// ABOUTME: Extracts SHA-256 hashes from PDM's pdm.lock.
// ABOUTME: pdm.lock shares poetry's [[package]] + files=[{file, hash}] schema; we reuse parsePyPIPackagesFilesLock.
package lockfiles

var pdmParser = Parser{
	Name:      "pdm",
	Filenames: []string{"pdm.lock"},
	Parse:     parsePyPIPackagesFilesLock,
}
