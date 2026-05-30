// ABOUTME: Tests the Debian copyright enricher — licences live in /usr/share/doc/<pkg>/copyright (DEP-5), not dpkg status.
// ABOUTME: Covers DEP-5 short-name -> SPDX mapping and the enricher's path derivation from the package name.
package debiancopyright

import (
	"context"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
)

func TestParseDEP5(t *testing.T) {
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
			got := parseDEP5([]byte(tc.copyright))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCommonLicensePointers(t *testing.T) {
	cases := map[string]struct {
		copyright string
		want      []string
	}{
		"versioned GPL pointer": {
			"On Debian systems the full text is in /usr/share/common-licenses/GPL-2.\n",
			[]string{"GPL-2.0-only"},
		},
		"apache + bsd": {
			"see /usr/share/common-licenses/Apache-2.0\nand /usr/share/common-licenses/BSD\n",
			[]string{"Apache-2.0", "BSD-3-Clause"},
		},
		"bare GPL symlink is skipped (ambiguous version)": {
			"see /usr/share/common-licenses/GPL\n",
			nil,
		},
		"none": {"no pointer here\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := commonLicensePointers([]byte(tc.copyright))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLicensesFromCopyright_Priority(t *testing.T) {
	// DEP-5 is authoritative: its "GPL-2+" wins over the GPL-2 pointer in the
	// same file (the classifier is not consulted).
	dep5AndPointer := "Files: *\nLicense: GPL-2+\n On Debian see /usr/share/common-licenses/GPL-2\n"
	if got := licensesFromCopyright([]byte(dep5AndPointer)); !reflect.DeepEqual(got, []string{"GPL-2.0-or-later"}) {
		t.Errorf("DEP-5+pointer = %v, want [GPL-2.0-or-later] (DEP-5 wins)", got)
	}
	// Pointer-only (no DEP-5, no inline text): resolved by the pointer, cheaply.
	pointerOnly := "This package is free software.\nOn Debian see /usr/share/common-licenses/GPL-3 for the full text.\n"
	if got := licensesFromCopyright([]byte(pointerOnly)); !reflect.DeepEqual(got, []string{"GPL-3.0-only"}) {
		t.Errorf("pointer-only = %v, want [GPL-3.0-only]", got)
	}
}

func TestLicensesFromCopyright_ClassifierFallback(t *testing.T) {
	// A DEP-5 declaration is used as-is (deterministic), and the classifier is
	// never consulted for it.
	if got := licensesFromCopyright([]byte("Files: *\nLicense: GPL-2+\n")); !reflect.DeepEqual(got, []string{"GPL-2.0-or-later"}) {
		t.Errorf("DEP-5 path = %v, want [GPL-2.0-or-later]", got)
	}
	// A free-text copyright with no License field but inlined licence text falls
	// back to the classifier.
	freeText := "This package was debianized by someone.\n\n" + mitLicenseText
	got := licensesFromCopyright([]byte(freeText))
	found := false
	for _, id := range got {
		if id == "MIT" {
			found = true
		}
	}
	if !found {
		t.Errorf("classifier fallback = %v, want it to include MIT", got)
	}
}

const mitLicenseText = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

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
