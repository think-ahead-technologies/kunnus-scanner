// ABOUTME: PHP/Composer ecosystem. Detected via composer.json / composer.lock; scanned by scalibr's php/composerlock.
// ABOUTME: composer.lock embeds a per-package licence array, which kunnus mines offline (PHP is not on deps.dev).
package ecosystem

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"

	"github.com/think-ahead/kunnus-scanner/internal/license"
)

var composer = Ecosystem{
	Name:           "composer",
	Filenames:      []string{"composer.json", "composer.lock"},
	ScalibrPlugins: []string{composerlock.Name},
	// No kunnus-side hash parser yet — composer.lock carries integrity values but
	// we don't mine them. We do mine licences (see parseComposerLock).
	LicenseParsers: []LicenseParser{
		{Name: "composer", Filenames: []string{"composer.lock"}, Parse: parseComposerLock},
	},
}

// composerLicense unmarshals composer.lock's "license" field, which is an array
// of SPDX-ish identifiers but is occasionally written as a bare string.
type composerLicense []string

func (c *composerLicense) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*c = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*c = arr
	return nil
}

type composerPackage struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	License composerLicense `json:"license"`
}

// parseComposerLock mines the per-package licence array from a composer.lock.
// It covers both "packages" and "packages-dev"; licences are keyed by the
// conventional composer purl (pkg:composer/<vendor>/<name>@<version>) so they
// match the SBOM component after purl normalization.
func parseComposerLock(r io.Reader) (license.Map, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock: %w", err)
	}
	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse composer.lock: %w", err)
	}

	out := make(license.Map)
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		if p.Name == "" || p.Version == "" {
			continue
		}
		purl := "pkg:composer/" + p.Name + "@" + p.Version
		for _, l := range p.License {
			out.Add(purl, l)
		}
	}
	return out, nil
}
