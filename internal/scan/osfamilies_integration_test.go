// ABOUTME: Registry-driven integration test for OS-package scans: each Linux family is fixtured or has a documented reason it cannot be.
// ABOUTME: Plans with mode/os (TargetOS linux) and runs real scalibr against fixture root trees — the seam tier beneath the binary e2e.
package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
	osmode "github.com/think-ahead/kunnus-scanner/internal/mode/os"
	"github.com/think-ahead/kunnus-scanner/internal/osfamily"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// osFamiliesWithoutFixture records why each Linux family has no in-tree fixture.
// A family that is neither fixtured nor listed here fails TestOSFamilies_EndToEnd
// — so adding a family to the osfamily registry forces a conscious decision:
// build a fixture, or document why it is impractical. This is the OS-scan analog
// of the ecosystem drift guard.
//
// The hard blockers are the binary database (rpm) and image-specific (cos)
// families; the fallback-only families have no on-disk fingerprint to fixture.
var osFamiliesWithoutFixture = map[string]string{
	"rhel":    "rpm uses a binary sqlite/bdb database; not hand-fixturable in-tree",
	"suse":    "rpm-based; same binary-database blocker as rhel",
	"cos":     "Container-Optimized OS layout is image-specific; not hand-fixturable",
	"flatpak": "fallback-only family with no on-disk fingerprint to fixture",
	"snap":    "fallback-only family with no on-disk fingerprint to fixture",
}

// TestOSFamilies_EndToEnd walks osfamily.LinuxFamilies() and, for each family
// with a fixture root tree under testdata/osfamilies/<name>/, plans an OS scan
// exactly as the CLI does (os.Plan with TargetOS "linux") and runs real
// scalibr, asserting every wanted purl appears in the inventory verbatim.
// Families without a fixture must carry a documented reason.
//
// TargetOS is forced to "linux" so these run from any host (e.g. macOS CI);
// the dpkg/apk extractors have no capability requirements.
func TestOSFamilies_EndToEnd(t *testing.T) {
	corpus := filepath.Join(moduleRoot(t), "testdata", "osfamilies")

	for _, fam := range osfamily.LinuxFamilies() {
		t.Run(fam.Name, func(t *testing.T) {
			dir := filepath.Join(corpus, fam.Name)
			if _, err := os.Stat(dir); err != nil {
				if reason, ok := osFamiliesWithoutFixture[fam.Name]; ok {
					t.Skipf("no in-tree fixture: %s", reason)
				}
				t.Fatalf("family %q has no fixture and no documented reason; add testdata/osfamilies/%s/ or record why in osFamiliesWithoutFixture",
					fam.Name, fam.Name)
			}

			want, err := readWants(dir)
			if err != nil {
				t.Fatalf("family %q: %v", fam.Name, err)
			}
			if len(want.purls) == 0 && len(want.pkgs) == 0 {
				t.Fatalf("family %q: want.txt declares no expected purls or pkgs", fam.Name)
			}

			plan, err := osmode.New().Plan(context.Background(), dir, mode.Overrides{TargetOS: "linux"})
			if err != nil {
				t.Fatalf("Plan(%s): %v", dir, err)
			}
			res, err := scan.Run(context.Background(), plan.Config)
			if err != nil {
				t.Fatalf("Run(%s): %v", dir, err)
			}

			got := inventoryPURLs(res)
			for _, p := range want.purls {
				if !got[p] {
					t.Errorf("expected purl %q in inventory; got:\n  %s",
						p, strings.Join(sortedKeys(got), "\n  "))
				}
			}
			// name@version expectations, for packages that carry no purl
			// (the kernel extractors set no PURLType).
			gotPkgs := inventoryPkgs(res)
			for _, p := range want.pkgs {
				if !gotPkgs[p] {
					t.Errorf("expected package %q in inventory; got:\n  %s",
						p, strings.Join(sortedKeys(gotPkgs), "\n  "))
				}
			}
		})
	}
}
