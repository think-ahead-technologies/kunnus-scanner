// ABOUTME: Tests for the OS-managed-binary suppression stage and its version-coverage rule.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/ownership"
)

func TestSuppressOSManagedBinaries(t *testing.T) {
	// Two binaries owned by a package whose name differs from the binary's: the
	// postgres binary owned by postgresql-18, the xz binary owned by xz-utils.
	// The name signal cannot bridge these, but the ownership signal does.
	owned := ownership.Set{
		"usr/lib/postgresql/18/bin/postgres": {},
		"usr/bin/xz":                         {},
	}
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "bash", Version: "5.2.37-2+b9", PackageURL: "pkg:deb/debian/bash@5.2.37-2%2Bb9"},
		{Name: "bash", Version: "5.2.37", PackageURL: "pkg:generic/bash@5.2.37"},                              // drop: deb name+version covers it
		{Name: "gzip", Version: "1.13-1", PackageURL: "pkg:deb/debian/gzip@1.13-1"},
		{Name: "gzip", Version: "1.13", PackageURL: "pkg:generic/gzip@1.13"},                                 // drop
		{Name: "memcached", Version: "1.6.42", PackageURL: "pkg:generic/memcached@1.6.42", Evidence: occ("usr/local/bin/memcached")}, // keep: not owned, no OS twin
		{Name: "bar", Version: "1.130-1", PackageURL: "pkg:deb/debian/bar@1.130-1"},
		{Name: "bar", Version: "1.13", PackageURL: "pkg:generic/bar@1.13"},                                   // keep: 1.130 boundary, not owned
		{Name: "consul", Version: "1.18.0", PackageURL: "pkg:golang/github.com/hashicorp/consul@1.18.0"},     // keep: not generic
		{Name: "musl", Version: "1.2.5-r23", PackageURL: "pkg:apk/alpine/musl@1.2.5-r23"},
		{Name: "musl", Version: "1.2.5", PackageURL: "pkg:generic/musl@1.2.5"},                               // drop: apk name+version covers it
		{Name: "postgresql-18", Version: "18.4-1", PackageURL: "pkg:deb/debian/postgresql-18@18.4-1"},
		{Name: "postgresql", Version: "18.4", PackageURL: "pkg:generic/postgresql@18.4", Evidence: occ("usr/lib/postgresql/18/bin/postgres")}, // drop: owned by postgresql-18
		{Name: "xz-utils", Version: "5.8.1-1", PackageURL: "pkg:deb/debian/xz-utils@5.8.1-1"},
		{Name: "xz", Version: "5.8.1", PackageURL: "pkg:generic/xz@5.8.1", Evidence: occ("usr/bin/xz")},      // drop: owned by xz-utils
	}}

	suppressOSManagedBinaries(bom, owned)

	got := map[string]bool{}
	for _, c := range *bom.Components {
		got[c.PackageURL] = true
	}
	wantKept := []string{
		"pkg:deb/debian/bash@5.2.37-2%2Bb9",
		"pkg:deb/debian/gzip@1.13-1",
		"pkg:generic/memcached@1.6.42",
		"pkg:deb/debian/bar@1.130-1",
		"pkg:generic/bar@1.13",
		"pkg:golang/github.com/hashicorp/consul@1.18.0",
		"pkg:apk/alpine/musl@1.2.5-r23",
		"pkg:deb/debian/postgresql-18@18.4-1",
		"pkg:deb/debian/xz-utils@5.8.1-1",
	}
	wantDropped := []string{
		"pkg:generic/bash@5.2.37",
		"pkg:generic/gzip@1.13",
		"pkg:generic/musl@1.2.5",
		"pkg:generic/postgresql@18.4",
		"pkg:generic/xz@5.8.1",
	}
	for _, p := range wantKept {
		if !got[p] {
			t.Errorf("expected %q to be kept, but it was dropped", p)
		}
	}
	for _, p := range wantDropped {
		if got[p] {
			t.Errorf("expected %q to be dropped, but it was kept", p)
		}
	}
	if len(*bom.Components) != len(wantKept) {
		t.Errorf("got %d components, want %d", len(*bom.Components), len(wantKept))
	}
}

// occ builds an Evidence carrying a single occurrence at the given location, as
// scalibr's converter does from a package's Locations.
func occ(location string) *cyclonedx.Evidence {
	return &cyclonedx.Evidence{Occurrences: &[]cyclonedx.EvidenceOccurrence{{Location: location}}}
}

func TestVersionCovers(t *testing.T) {
	cases := []struct {
		osVer, binVer string
		want          bool
	}{
		{"5.2.37-2+b9", "5.2.37", true},
		{"1.13-1", "1.13", true},
		{"1.2.5-r23", "1.2.5", true}, // apk revision
		{"1.6.42", "1.6.42", true},   // identical
		{"1.130-1", "1.13", false},   // digit boundary, not a separator
		{"1.13", "1.130", false},     // binary longer than package
		{"2.0.0", "1.0.0", false},    // unrelated
		{"5.2.37", "", false},        // empty binary version
	}
	for _, tc := range cases {
		if got := versionCovers(tc.osVer, tc.binVer); got != tc.want {
			t.Errorf("versionCovers(%q, %q) = %v, want %v", tc.osVer, tc.binVer, got, tc.want)
		}
	}
}

func TestPurlType(t *testing.T) {
	cases := map[string]string{
		"pkg:generic/memcached@1.6.42":     "generic",
		"pkg:deb/debian/bash@5.2.37-2%2Bb9": "deb",
		"pkg:golang/github.com/x/y@1.0":     "golang",
		"":                                  "",
		"not-a-purl":                        "",
	}
	for purl, want := range cases {
		if got := purlType(purl); got != want {
			t.Errorf("purlType(%q) = %q, want %q", purl, got, want)
		}
	}
}
