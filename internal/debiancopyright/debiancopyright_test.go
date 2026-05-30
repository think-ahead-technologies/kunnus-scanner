// ABOUTME: Tests the Debian copyright enricher — licences live in /usr/share/doc/<pkg>/copyright (DEP-5), not dpkg status.
// ABOUTME: Covers DEP-5 short-name -> SPDX mapping and the enricher's path derivation from the package name.
package debiancopyright

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
)

func TestLicensesFromCopyright(t *testing.T) {
	cases := map[string]struct {
		copyright string
		want      []string
	}{
		"dep5 short names mapped + deduped": {
			"Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n" +
				"Files: *\nCopyright: 2020 X\nLicense: GPL-2+\n\n" +
				"Files: src/*\nCopyright: 2021 Y\nLicense: Apache-2.0\n\n" +
				"License: GPL-2+\n full text repeated, must dedup\n",
			[]string{"GPL-2.0-or-later", "Apache-2.0"},
		},
		"expat is MIT": {
			"Files: *\nLicense: Expat\n",
			[]string{"MIT"},
		},
		"public-domain is dropped (no SPDX id)": {
			"Files: *\nLicense: public-domain\n",
			nil,
		},
		"free-text copyright with no License field": {
			"This package was debianized by someone.\nThe upstream source is at example.com.\n",
			nil,
		},
		"indented continuation is not a License field": {
			"Files: *\nLicense: GPL-3+\n License: this is body text, not a field\n",
			[]string{"GPL-3.0-or-later"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := licensesFromCopyright(strings.NewReader(tc.copyright))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func enrich(t *testing.T, fsys fstest.MapFS, pkg *extractor.Package) {
	t.Helper()
	inv := &inventory.Inventory{Packages: []*extractor.Package{pkg}}
	in := &enricher.ScanInput{ScanRoot: &scalibrfs.ScanRoot{FS: fsys}}
	if err := New().Enrich(context.Background(), in, inv); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
}

func TestEnrich_SetsLicenseFromCopyright(t *testing.T) {
	fsys := fstest.MapFS{
		"usr/share/doc/adduser/copyright": {Data: []byte("Files: *\nLicense: GPL-2+\n")},
	}
	pkg := &extractor.Package{Name: "adduser", Version: "3.137", PURLType: "deb"}
	enrich(t, fsys, pkg)
	if !reflect.DeepEqual(pkg.Licenses, []string{"GPL-2.0-or-later"}) {
		t.Errorf("Licenses = %v, want [GPL-2.0-or-later]", pkg.Licenses)
	}
}

func TestEnrich_IgnoresNonDebPackages(t *testing.T) {
	fsys := fstest.MapFS{"usr/share/doc/foo/copyright": {Data: []byte("Files: *\nLicense: MIT\n")}}
	pkg := &extractor.Package{Name: "foo", PURLType: "npm"}
	enrich(t, fsys, pkg)
	if pkg.Licenses != nil {
		t.Errorf("Licenses = %v, want nil for a non-deb package", pkg.Licenses)
	}
}

func TestEnrich_KeepsExistingAndMissingFileSafe(t *testing.T) {
	// Existing licence preserved.
	pkg := &extractor.Package{Name: "x", PURLType: "deb", Licenses: []string{"set"}}
	enrich(t, fstest.MapFS{"usr/share/doc/x/copyright": {Data: []byte("Files: *\nLicense: MIT\n")}}, pkg)
	if !reflect.DeepEqual(pkg.Licenses, []string{"set"}) {
		t.Errorf("Licenses = %v, want unchanged [set]", pkg.Licenses)
	}
	// Missing copyright file must not error.
	pkg2 := &extractor.Package{Name: "missing", PURLType: "deb"}
	enrich(t, fstest.MapFS{}, pkg2)
	if pkg2.Licenses != nil {
		t.Errorf("Licenses = %v, want nil when copyright is absent", pkg2.Licenses)
	}
}
