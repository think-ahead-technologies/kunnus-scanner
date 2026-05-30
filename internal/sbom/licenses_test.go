// ABOUTME: Tests the CDX license-injection stage: scalibr package licenses -> component.licenses[].
// ABOUTME: Verifies SPDX id/expression/LicenseRef encoding, acknowledgement, dedup, and no-override.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
)

// licensedComponent builds a one-package inventory and a matching component,
// runs the stage, and returns the component's license choices.
func injectAndGet(t *testing.T, pkgLicenses []string, existing *cyclonedx.Licenses) cyclonedx.Licenses {
	t.Helper()
	pkg := &extractor.Package{
		Name:     "fixture",
		Version:  "1.0.0",
		PURLType: "cargo",
		Licenses: pkgLicenses,
	}
	purl := pkg.PURL().String()
	comp := cyclonedx.Component{PackageURL: purl}
	comp.Licenses = existing
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{comp}}
	inv := inventory.Inventory{Packages: []*extractor.Package{pkg}}

	injectLicensesCDX(bom, inv)

	got := (*bom.Components)[0].Licenses
	if got == nil {
		return nil
	}
	return *got
}

func TestInjectLicenses_SPDXIdentifier(t *testing.T) {
	lics := injectAndGet(t, []string{"MIT"}, nil)
	if len(lics) != 1 {
		t.Fatalf("got %d licenses, want 1", len(lics))
	}
	lc := lics[0]
	if lc.License == nil || lc.License.ID != "MIT" {
		t.Errorf("license = %+v, want License.ID=MIT", lc)
	}
	if lc.License.Name != "" {
		t.Errorf("License.Name = %q, want empty for an SPDX id", lc.License.Name)
	}
	if lc.License.Acknowledgement != cyclonedx.LicenseAcknowledgementConcluded {
		t.Errorf("acknowledgement = %q, want concluded", lc.License.Acknowledgement)
	}
}

func TestInjectLicenses_AliasToSPDX(t *testing.T) {
	lics := injectAndGet(t, []string{"GPLv2+"}, nil)
	if len(lics) != 1 || lics[0].License == nil || lics[0].License.ID != "GPL-2.0-or-later" {
		t.Fatalf("got %+v, want License.ID=GPL-2.0-or-later", lics)
	}
}

func TestInjectLicenses_Expression(t *testing.T) {
	lics := injectAndGet(t, []string{"MIT OR Apache-2.0"}, nil)
	if len(lics) != 1 {
		t.Fatalf("got %d licenses, want 1", len(lics))
	}
	if lics[0].Expression != "MIT OR Apache-2.0" {
		t.Errorf("expression = %q, want \"MIT OR Apache-2.0\"", lics[0].Expression)
	}
	if lics[0].License != nil {
		t.Errorf("License should be nil for an expression choice, got %+v", lics[0].License)
	}
}

func TestInjectLicenses_CustomRef(t *testing.T) {
	lics := injectAndGet(t, []string{"Weird Vendor EULA!"}, nil)
	if len(lics) != 1 || lics[0].License == nil {
		t.Fatalf("got %+v, want a License choice", lics)
	}
	if lics[0].License.ID != "" {
		t.Errorf("License.ID = %q, want empty for a custom ref", lics[0].License.ID)
	}
	if lics[0].License.Name != "LicenseRef-kunnus-Weird-Vendor-EULA" {
		t.Errorf("License.Name = %q, want LicenseRef-kunnus-Weird-Vendor-EULA", lics[0].License.Name)
	}
}

func TestInjectLicenses_DropsNoAssertion(t *testing.T) {
	if lics := injectAndGet(t, []string{"NOASSERTION", ""}, nil); len(lics) != 0 {
		t.Errorf("got %d licenses, want 0 for no-assertion input", len(lics))
	}
}

func TestInjectLicenses_DedupAndUnion(t *testing.T) {
	// Same license twice (one as alias) collapses; distinct ones both survive.
	lics := injectAndGet(t, []string{"MIT", "mit", "Apache-2.0"}, nil)
	ids := map[string]bool{}
	for _, lc := range lics {
		if lc.License != nil {
			ids[lc.License.ID] = true
		}
	}
	if len(lics) != 2 || !ids["MIT"] || !ids["Apache-2.0"] {
		t.Errorf("got %d licenses %v, want exactly MIT + Apache-2.0", len(lics), ids)
	}
}

func TestInjectLicenses_DoesNotOverrideExisting(t *testing.T) {
	existing := cyclonedx.Licenses{{License: &cyclonedx.License{ID: "BSD-3-Clause"}}}
	lics := injectAndGet(t, []string{"MIT"}, &existing)
	if len(lics) != 1 || lics[0].License.ID != "BSD-3-Clause" {
		t.Errorf("existing licenses were overwritten: got %+v", lics)
	}
}
