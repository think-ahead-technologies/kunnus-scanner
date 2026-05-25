// ABOUTME: poetry.lock and pdm.lock parser — TOML [[package]] with inline files=[{file, hash}] or legacy [metadata.files].
// ABOUTME: Each package carries one hash per distribution file (wheel/sdist); we emit them all.
package ecosystem

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// pypiPackagesFilesLockfile mirrors the subset of poetry.lock / pdm.lock we
// read. Both formats agree on [[package]] with name/version and a files list;
// poetry pre-v1.1 instead used [metadata.files], indexed by package name —
// we accept both.
type pypiPackagesFilesLockfile struct {
	Packages []pypiPackageEntry `toml:"package"`
	Metadata pypiLegacyMetadata `toml:"metadata"`
}

type pypiPackageEntry struct {
	Name    string                   `toml:"name"`
	Version string                   `toml:"version"`
	Files   []pypiPackageFileHashRef `toml:"files"`
}

type pypiPackageFileHashRef struct {
	File string `toml:"file"`
	Hash string `toml:"hash"`
}

// pypiLegacyMetadata holds the pre-v1.1 poetry layout where file hashes lived
// outside the package blocks. New lockfiles set both Packages[*].Files and
// Metadata.Files; only one or the other actually populates depending on
// poetry's version, so we read whichever is present.
type pypiLegacyMetadata struct {
	Files map[string][]pypiPackageFileHashRef `toml:"files"`
}

func parsePyPIPackagesFilesLock(path string) (hashes.Map, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var lock pypiPackagesFilesLockfile
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	out := make(hashes.Map)
	for _, p := range lock.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := pypiPURL(p.Name, p.Version)
		for _, fh := range p.Files {
			addPyPIFileHash(out, purl, fh.Hash)
		}
		// Legacy fallback: pre-v1.1 poetry kept files under [metadata.files].
		for _, fh := range lock.Metadata.Files[p.Name] {
			addPyPIFileHash(out, purl, fh.Hash)
		}
	}
	return out, nil
}
