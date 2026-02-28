package sbom

import (
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scanner/v2/pkg/models"
)

// mergeWindowsInventory appends Windows OS packages from inv into result as a new PackageSource.
// Packages with a nil pointer in inv.Packages are silently skipped.
// The Ecosystem is hard-coded to "Windows" because scalibr's PURLType "windows" maps to an empty string.
// The Inventory pointer is set on each package so the SPDX formatter can access it without panicking.
func mergeWindowsInventory(inv inventory.Inventory, result *models.VulnerabilityResults) {
	var pkgVulns []models.PackageVulns

	for _, p := range inv.Packages {
		if p == nil {
			continue
		}

		pCopy := p // capture for Inventory pointer

		pkgVulns = append(pkgVulns, models.PackageVulns{
			Package: models.PackageInfo{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: "Windows",
				Inventory: pCopy,
			},
		})
	}

	if len(pkgVulns) == 0 {
		return
	}

	result.Results = append(result.Results, models.PackageSource{
		Source: models.SourceInfo{
			Path: "Windows Registry",
			Type: models.SourceTypeOSPackage,
		},
		Packages: pkgVulns,
	})
}
