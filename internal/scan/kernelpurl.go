// ABOUTME: Post-scan fix-up: gives kernel-module packages a pkg:generic purl so
// ABOUTME: they carry a machine identifier (CISA Component Identifiers) in the SBOM.
package scan

import (
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	"github.com/google/osv-scalibr/inventory"
)

// backfillKernelModulePURLs sets PURLType "generic" on kernel-module packages
// (scalibr's os/kernel/module) that carry none, so every consumer of
// scan.Result — the purl-keyed sbom stages and the SBOM itself — sees
// pkg:generic/<module>@<version> and each module has at least one
// machine-processable identifier. Upstream sets no PURLType on these
// (tracked in the AGENTS.md kernel section); only empty types are filled, so
// this becomes a no-op the day scalibr stamps its own.
//
// The kernel *image* (os/kernel/vmlinuz) is deliberately left purl-less: its
// identifier is the cpe:2.3:o:linux:linux_kernel CPE the sbom stage
// synthesises, and "Linux Kernel" would make a poor purl name.
func backfillKernelModulePURLs(inv inventory.Inventory) {
	for _, p := range inv.Packages {
		if p == nil || p.PURLType != "" {
			continue
		}
		if _, ok := p.Metadata.(*modulemeta.Metadata); ok {
			p.PURLType = "generic"
		}
	}
}
