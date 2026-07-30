// ABOUTME: Tests for the kernel-module purl backfill: modules must gain pkg:generic,
// ABOUTME: the kernel image and already-typed packages must stay untouched.
package scan

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/inventory"
)

func TestBackfillKernelModulePURLs(t *testing.T) {
	module := &extractor.Package{
		Name:     "intel_oaktrail",
		Version:  "0.4ac1",
		Metadata: &modulemeta.Metadata{PackageName: "intel_oaktrail", PackageVersion: "0.4ac1"},
	}
	kernelImage := &extractor.Package{
		Name:     "Linux Kernel",
		Version:  "6.8.0-49-generic",
		Metadata: &vmlinuzmeta.Metadata{Name: "Linux Kernel", Version: "6.8.0-49-generic"},
	}
	typed := &extractor.Package{
		Name:     "already-typed",
		Version:  "1.0",
		PURLType: "deb",
		Metadata: &modulemeta.Metadata{},
	}
	inv := inventory.Inventory{Packages: []*extractor.Package{module, kernelImage, typed}}

	backfillKernelModulePURLs(inv)

	if module.PURLType != "generic" {
		t.Errorf("module PURLType = %q, want generic", module.PURLType)
	}
	if purl := module.PURL(); purl == nil || purl.String() != "pkg:generic/intel_oaktrail@0.4ac1" {
		t.Errorf("module purl = %v, want pkg:generic/intel_oaktrail@0.4ac1", purl)
	}
	// The kernel image keeps its purl-less identity: its identifier is the
	// synthesised linux_kernel CPE, and "Linux Kernel" makes a poor purl name.
	if kernelImage.PURLType != "" {
		t.Errorf("kernel image PURLType = %q, want empty", kernelImage.PURLType)
	}
	// A package that already carries a type is never rewritten (the upstream-
	// fixes-it case).
	if typed.PURLType != "deb" {
		t.Errorf("typed package PURLType = %q, want deb kept", typed.PURLType)
	}
}
