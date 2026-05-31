// ABOUTME: Tests for the OS-managed-binary suppression stage and its version-coverage rule.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

func TestSuppressOSManagedBinaries(t *testing.T) {
	bom := &cyclonedx.BOM{Components: &[]cyclonedx.Component{
		{Name: "bash", Version: "5.2.37-2+b9", PackageURL: "pkg:deb/debian/bash@5.2.37-2%2Bb9"},
		{Name: "bash", Version: "5.2.37", PackageURL: "pkg:generic/bash@5.2.37"},                              // drop: deb covers it
		{Name: "gzip", Version: "1.13-1", PackageURL: "pkg:deb/debian/gzip@1.13-1"},
		{Name: "gzip", Version: "1.13", PackageURL: "pkg:generic/gzip@1.13"},                                 // drop
		{Name: "memcached", Version: "1.6.42", PackageURL: "pkg:generic/memcached@1.6.42"},                   // keep: no OS twin
		{Name: "bar", Version: "1.130-1", PackageURL: "pkg:deb/debian/bar@1.130-1"},
		{Name: "bar", Version: "1.13", PackageURL: "pkg:generic/bar@1.13"},                                   // keep: 1.130 boundary
		{Name: "consul", Version: "1.18.0", PackageURL: "pkg:golang/github.com/hashicorp/consul@1.18.0"},     // keep: not generic
		{Name: "musl", Version: "1.2.5-r23", PackageURL: "pkg:apk/alpine/musl@1.2.5-r23"},
		{Name: "musl", Version: "1.2.5", PackageURL: "pkg:generic/musl@1.2.5"},                               // drop: apk covers it
	}}

	suppressOSManagedBinaries(bom)

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
	}
	wantDropped := []string{
		"pkg:generic/bash@5.2.37",
		"pkg:generic/gzip@1.13",
		"pkg:generic/musl@1.2.5",
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
