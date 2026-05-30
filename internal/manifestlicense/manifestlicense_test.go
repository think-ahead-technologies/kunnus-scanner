// ABOUTME: Tests the offline manifest-license enricher against an in-memory scan-root filesystem.
// ABOUTME: No network, no real scan — exercises the read-manifest-and-set-Licenses logic directly.
package manifestlicense

import (
	"context"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
)

func enrich(t *testing.T, fsys fstest.MapFS, pkg *extractor.Package) {
	t.Helper()
	inv := &inventory.Inventory{Packages: []*extractor.Package{pkg}}
	in := &enricher.ScanInput{ScanRoot: &scalibrfs.ScanRoot{FS: fsys}}
	if err := New().Enrich(context.Background(), in, inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
}

func TestEnrich_SetsLicenseFromPackageJSON(t *testing.T) {
	fsys := fstest.MapFS{
		"app/node_modules/left-pad/package.json": {Data: []byte(`{"name":"left-pad","version":"1.3.0","license":"WTFPL"}`)},
	}
	pkg := &extractor.Package{
		Name: "left-pad", Version: "1.3.0", PURLType: "npm",
		Plugins:   []string{packagejson.Name},
		Locations: []string{"app/node_modules/left-pad/package.json"},
	}
	enrich(t, fsys, pkg)
	if !reflect.DeepEqual(pkg.Licenses, []string{"WTFPL"}) {
		t.Errorf("Licenses = %v, want [WTFPL]", pkg.Licenses)
	}
}

func TestEnrich_KeepsExistingLicense(t *testing.T) {
	fsys := fstest.MapFS{
		"p/package.json": {Data: []byte(`{"license":"MIT"}`)},
	}
	pkg := &extractor.Package{
		Plugins:   []string{packagejson.Name},
		Locations: []string{"p/package.json"},
		Licenses:  []string{"already-set"},
	}
	enrich(t, fsys, pkg)
	if !reflect.DeepEqual(pkg.Licenses, []string{"already-set"}) {
		t.Errorf("Licenses = %v, want unchanged [already-set]", pkg.Licenses)
	}
}

func TestEnrich_IgnoresExtractorWithoutManifestParser(t *testing.T) {
	fsys := fstest.MapFS{"var/lib/dpkg/status": {Data: []byte("Package: x\n")}}
	pkg := &extractor.Package{
		Plugins:   []string{"os/dpkg"},
		Locations: []string{"var/lib/dpkg/status"},
	}
	enrich(t, fsys, pkg)
	if pkg.Licenses != nil {
		t.Errorf("Licenses = %v, want nil for an extractor with no manifest parser", pkg.Licenses)
	}
}

func TestEnrich_MissingFileIsSkipped(t *testing.T) {
	pkg := &extractor.Package{
		Plugins:   []string{packagejson.Name},
		Locations: []string{"does/not/exist/package.json"},
	}
	enrich(t, fstest.MapFS{}, pkg) // must not error
	if pkg.Licenses != nil {
		t.Errorf("Licenses = %v, want nil when the manifest is absent", pkg.Licenses)
	}
}
