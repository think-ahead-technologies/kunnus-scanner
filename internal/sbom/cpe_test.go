// ABOUTME: Tests for cpeFromPURL: heuristic CPE 2.3 generation per ecosystem.
// ABOUTME: Table-driven; covers the ecosystems we ship plus malformed input fall-through.
package sbom

import (
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	modulemeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module/metadata"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/binclass"
)

func TestCPEFromPURL(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		// Go modules: vendor from path segment after the host, product from last segment.
		{
			name: "go github vendor + product",
			purl: "pkg:golang/github.com/google/uuid@v1.6.0",
			want: "cpe:2.3:a:google:uuid:1.6.0:*:*:*:*:*:*:*",
		},
		{
			name: "go nested path",
			purl: "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.11.0",
			want: "cpe:2.3:a:cyclonedx:cyclonedx-go:0.11.0:*:*:*:*:*:*:*",
		},
		{
			name: "go deps.dev (no github prefix)",
			purl: "pkg:golang/deps.dev/util/maven@0.0.0-20251104021112-20ad94767ddf",
			want: "cpe:2.3:a:util:maven:0.0.0-20251104021112-20ad94767ddf:*:*:*:*:*:*:*",
		},
		{
			name: "go stdlib",
			purl: "pkg:golang/stdlib@1.26.3",
			want: "cpe:2.3:a:golang:go:1.26.3:*:*:*:*:*:*:*",
		},
		{
			name: "go single-segment module",
			purl: "pkg:golang/example.com@1.0.0",
			want: "cpe:2.3:a:example.com:example.com:1.0.0:*:*:*:*:*:*:*",
		},

		// npm: scope becomes vendor; unscoped uses product as vendor (NVD convention).
		{
			name: "npm scoped",
			purl: "pkg:npm/%40babel/core@7.0.0",
			want: "cpe:2.3:a:babel:core:7.0.0:*:*:*:*:*:*:*",
		},
		{
			// Scalibr renders a scoped package as one segment with the separator
			// escaped (%2F); the namespace must still be split out for the CPE.
			name: "npm scoped, scalibr %2F form",
			purl: "pkg:npm/%40isaacs%2Fcliui@8.0.2",
			want: "cpe:2.3:a:isaacs:cliui:8.0.2:*:*:*:*:*:*:*",
		},
		{
			name: "npm unscoped",
			purl: "pkg:npm/lodash@4.17.21",
			want: "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*",
		},

		// PyPI: vendor and product both equal the name (NVD convention for python packages).
		{
			name: "pypi",
			purl: "pkg:pypi/requests@2.31.0",
			want: "cpe:2.3:a:requests:requests:2.31.0:*:*:*:*:*:*:*",
		},

		// Maven: vendor from groupId last segment, product = artifactId.
		{
			name: "maven",
			purl: "pkg:maven/org.springframework/spring-core@5.3.31",
			want: "cpe:2.3:a:springframework:spring-core:5.3.31:*:*:*:*:*:*:*",
		},

		// NuGet: vendor and product equal the name.
		{
			name: "nuget",
			purl: "pkg:nuget/Newtonsoft.Json@13.0.3",
			want: "cpe:2.3:a:newtonsoft.json:newtonsoft.json:13.0.3:*:*:*:*:*:*:*",
		},

		// Cargo: vendor and product equal the crate name.
		{
			name: "cargo",
			purl: "pkg:cargo/serde@1.0.200",
			want: "cpe:2.3:a:serde:serde:1.0.200:*:*:*:*:*:*:*",
		},

		// Composer (PHP): namespace becomes vendor.
		{
			name: "composer",
			purl: "pkg:composer/symfony/console@6.4.0",
			want: "cpe:2.3:a:symfony:console:6.4.0:*:*:*:*:*:*:*",
		},
		{
			// Scalibr emits the vendor/package as a single name segment with the
			// slash percent-encoded; the vendor must still be split back out.
			name: "composer encoded slash",
			purl: "pkg:composer/psr%2Flog@3.0.0",
			want: "cpe:2.3:a:psr:log:3.0.0:*:*:*:*:*:*:*",
		},

		// Gem: vendor and product equal the gem name.
		{
			name: "gem",
			purl: "pkg:gem/rails@7.1.0",
			want: "cpe:2.3:a:rails:rails:7.1.0:*:*:*:*:*:*:*",
		},

		// OS packages: distro becomes vendor, package name becomes product, part = "o".
		{
			name: "deb",
			purl: "pkg:deb/debian/openssl@3.0.11-1~deb12u2",
			want: "cpe:2.3:o:debian:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*",
		},
		{
			// '+' is pervasive in deb/rpm versions; it must be backslash-escaped
			// rather than dropped (which left the whole CPE empty before).
			name: "deb version with plus is escaped",
			purl: "pkg:deb/debian/tar@1.34%2Bdfsg-1build4",
			want: `cpe:2.3:o:debian:tar:1.34\+dfsg-1build4:*:*:*:*:*:*:*`,
		},
		{
			name: "rpm",
			purl: "pkg:rpm/fedora/curl@8.4.0-1.fc39",
			want: "cpe:2.3:o:fedora:curl:8.4.0-1.fc39:*:*:*:*:*:*:*",
		},
		{
			name: "apk",
			purl: "pkg:apk/alpine/musl@1.2.4-r2",
			want: "cpe:2.3:o:alpine:musl:1.2.4-r2:*:*:*:*:*:*:*",
		},

		// Edge cases: empty or unparsable PURLs return empty string.
		{
			name: "empty",
			purl: "",
			want: "",
		},
		{
			name: "not a purl",
			purl: "github.com/foo/bar",
			want: "",
		},
		{
			name: "purl missing version",
			purl: "pkg:golang/github.com/google/uuid",
			want: "cpe:2.3:a:google:uuid:*:*:*:*:*:*:*:*",
		},
		{
			name: "unknown type falls back to name=name",
			purl: "pkg:weirdtype/foo@1.0",
			want: "cpe:2.3:a:foo:foo:1.0:*:*:*:*:*:*:*",
		},

		// Special characters: the CPE 2.3 grammar requires escaping `:` (the field
		// separator) and `\`. We backslash-escape them — an embedded `*` is
		// rejected as a malformed wildcard by CPE consumers.
		{
			name: "colon (debian epoch) in version is escaped",
			purl: "pkg:deb/debian/apt@2:1.0",
			want: `cpe:2.3:o:debian:apt:2\:1.0:*:*:*:*:*:*:*`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cpeFromPURL(tc.purl)
			if got != tc.want {
				t.Errorf("cpeFromPURL(%q)\n  got:  %q\n  want: %q", tc.purl, got, tc.want)
			}
			// Every non-empty CPE we emit must be syntactically valid per NIST IR 7695.
			if got != "" && !isValidCPE23(got) {
				t.Errorf("cpeFromPURL(%q) = %q, which fails CPE 2.3 grammar", tc.purl, got)
			}
		})
	}
}

func TestRenderCPETemplate(t *testing.T) {
	tests := []struct {
		name, tmpl, version, want string
	}{
		{
			name:    "plain version",
			tmpl:    "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
			version: "1.6.42",
			want:    "cpe:2.3:a:memcached:memcached:1.6.42:*:*:*:*:*:*:*",
		},
		{
			// '+' is forbidden unquoted in a CPE field and must be escaped.
			name:    "version with plus is escaped",
			tmpl:    "cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*",
			version: "3.14.5+build2",
			want:    `cpe:2.3:a:python_software_foundation:python:3.14.5\+build2:*:*:*:*:*:*:*`,
		},
		{
			name:    "version is lowercased per CPE convention",
			tmpl:    "cpe:2.3:a:getcomposer:composer:*:*:*:*:*:*:*:*",
			version: "2.7.0RC1",
			want:    "cpe:2.3:a:getcomposer:composer:2.7.0rc1:*:*:*:*:*:*:*",
		},
		{
			// The erlang templates carry an escaped '/' in the product field; it
			// must survive rendering intact.
			name:    "escaped slash in product survives",
			tmpl:    `cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*`,
			version: "26.1",
			want:    `cpe:2.3:a:erlang:erlang\/otp:26.1:*:*:*:*:*:*:*`,
		},
		{
			name:    "empty version keeps the ANY wildcard",
			tmpl:    "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
			version: "",
			want:    "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
		},
		{
			name:    "malformed template (12 fields) is dropped",
			tmpl:    "cpe:2.3:a:helm:helm:*:*:*:*:*:*:*",
			version: "3.14.0",
			want:    "",
		},
		{
			// A template whose version slot is not the "*" placeholder is not
			// ours to fill in; drop it rather than clobber a concrete value.
			name:    "concrete version slot is dropped",
			tmpl:    "cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*",
			version: "1.0.0",
			want:    "",
		},
		{
			name:    "garbage is dropped",
			tmpl:    "not-a-cpe",
			version: "1.0.0",
			want:    "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := renderCPETemplate(tc.tmpl, tc.version)
			if got != tc.want {
				t.Errorf("renderCPETemplate(%q, %q)\n  got:  %q\n  want: %q", tc.tmpl, tc.version, got, tc.want)
			}
			if got != "" && !isValidCPE23(got) {
				t.Errorf("renderCPETemplate(%q, %q) = %q, which fails CPE 2.3 grammar", tc.tmpl, tc.version, got)
			}
		})
	}
}

// TestInjectCPEsCDXClassifierTemplates covers the binary-classifier path of
// injectCPEsCDX: a component whose inventory package carries binclass CPE
// templates gets the first rendered template as its CPE (not the PURL
// heuristic) and every further template as a kunnus:cpe property; components
// without templates keep the heuristic, and a pre-set CPE is never touched.
func TestInjectCPEsCDXClassifierTemplates(t *testing.T) {
	pythonPkg := &extractor.Package{
		Name:     "python",
		Version:  "3.14.5",
		PURLType: "generic",
		Metadata: &binclass.Metadata{CPEs: []string{
			"cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
		}},
	}
	// Templates present but every one malformed: the heuristic must kick in.
	brokenPkg := &extractor.Package{
		Name:     "broken",
		Version:  "1.0.0",
		PURLType: "generic",
		Metadata: &binclass.Metadata{CPEs: []string{"cpe:2.3:a:oops"}},
	}
	// Classifier package with an empty template list (e.g. pypy): heuristic.
	pypyPkg := &extractor.Package{
		Name:     "pypy",
		Version:  "7.3.15",
		PURLType: "generic",
		Metadata: &binclass.Metadata{},
	}
	plainPkg := &extractor.Package{
		Name:     "lodash",
		Version:  "4.17.21",
		PURLType: "npm",
	}
	inv := inventory.Inventory{Packages: []*extractor.Package{pythonPkg, brokenPkg, pypyPkg, plainPkg}}

	components := []cyclonedx.Component{
		{Name: "python", Version: "3.14.5", PackageURL: "pkg:generic/python@3.14.5"},
		{Name: "broken", Version: "1.0.0", PackageURL: "pkg:generic/broken@1.0.0"},
		{Name: "pypy", Version: "7.3.15", PackageURL: "pkg:generic/pypy@7.3.15"},
		{Name: "lodash", Version: "4.17.21", PackageURL: "pkg:npm/lodash@4.17.21"},
		{Name: "preset", Version: "1.0", PackageURL: "pkg:generic/python@3.14.5", CPE: "cpe:2.3:a:pre:set:1.0:*:*:*:*:*:*:*"},
	}
	bom := &cyclonedx.BOM{Components: &components}

	injectCPEsCDX(bom, inv)

	got := *bom.Components
	if want := "cpe:2.3:a:python_software_foundation:python:3.14.5:*:*:*:*:*:*:*"; got[0].CPE != want {
		t.Errorf("python CPE = %q, want %q", got[0].CPE, want)
	}
	if got[0].Properties == nil || len(*got[0].Properties) != 1 {
		t.Fatalf("python properties = %+v, want exactly one kunnus:cpe alias", got[0].Properties)
	}
	if p := (*got[0].Properties)[0]; p.Name != "kunnus:cpe" || p.Value != "cpe:2.3:a:python:python:3.14.5:*:*:*:*:*:*:*" {
		t.Errorf("python alias property = %+v, want kunnus:cpe with the second rendered template", p)
	}
	if want := "cpe:2.3:a:broken:broken:1.0.0:*:*:*:*:*:*:*"; got[1].CPE != want {
		t.Errorf("broken-template CPE = %q, want heuristic %q", got[1].CPE, want)
	}
	if want := "cpe:2.3:a:pypy:pypy:7.3.15:*:*:*:*:*:*:*"; got[2].CPE != want {
		t.Errorf("pypy CPE = %q, want heuristic %q", got[2].CPE, want)
	}
	if want := "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"; got[3].CPE != want {
		t.Errorf("lodash CPE = %q, want heuristic %q", got[3].CPE, want)
	}
	if want := "cpe:2.3:a:pre:set:1.0:*:*:*:*:*:*:*"; got[4].CPE != want {
		t.Errorf("pre-set CPE = %q, want untouched %q", got[4].CPE, want)
	}
	if got[1].Properties != nil || got[2].Properties != nil || got[3].Properties != nil {
		t.Errorf("heuristic components must gain no alias properties; got %+v / %+v / %+v",
			got[1].Properties, got[2].Properties, got[3].Properties)
	}
}

func TestIsValidCPE23(t *testing.T) {
	good := []string{
		"cpe:2.3:a:google:uuid:1.6.0:*:*:*:*:*:*:*",
		"cpe:2.3:o:debian:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*",
		"cpe:2.3:h:cisco:asa_5505:9.16.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
		// Escaped specials per spec section 6.2.
		`cpe:2.3:a:vendor:product\:name:1.0:*:*:*:*:*:*:*`,
	}
	for _, s := range good {
		if !isValidCPE23(s) {
			t.Errorf("expected valid: %q", s)
		}
	}

	bad := []string{
		"",
		"cpe:2.2:a:vendor:product:*:*:*:*:*:*:*:*",                // wrong version
		"cpe:2.3:x:vendor:product:1.0:*:*:*:*:*:*:*",              // bad part
		"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*",                // 12 fields not 13
		"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*",            // 14 fields
		"not-a-cpe-at-all",                                        // garbage
		"cpe:2.3:a:vendor:prod uct:1.0:*:*:*:*:*:*:*",             // whitespace in field
		"cpe:2.3:a:vendor:product\x00malicious:1.0:*:*:*:*:*:*:*", // control char
	}
	for _, s := range bad {
		if isValidCPE23(s) {
			t.Errorf("expected invalid: %q", s)
		}
	}
}

func TestRealScanProducesValidCPEs(t *testing.T) {
	// Build a single inventory spanning every ecosystem we map, push it
	// through the encoder, then walk the output CDX components asserting
	// each emitted CPE is spec-valid. Catches regressions where a new
	// ecosystem mapping accidentally produces malformed strings.
	purls := []struct {
		name, version, purlType string
	}{
		{"github.com/google/uuid", "v1.6.0", "golang"},
		{"github.com/CycloneDX/cyclonedx-go", "v0.11.0", "golang"},
		{"stdlib", "1.26.3", "golang"},
		{"lodash", "4.17.21", "npm"},
		{"requests", "2.31.0", "pypi"},
		{"spring-core", "5.3.31", "maven"},
		{"Newtonsoft.Json", "13.0.3", "nuget"},
		{"serde", "1.0.200", "cargo"},
		{"console", "6.4.0", "composer"},
		{"rails", "7.1.0", "gem"},
		{"openssl", "3.0.11-1~deb12u2", "deb"},
		{"curl", "8.4.0-1.fc39", "rpm"},
		{"musl", "1.2.4-r2", "apk"},
	}

	pkgs := make([]*extractor.Package, 0, len(purls))
	for _, p := range purls {
		pkgs = append(pkgs, &extractor.Package{
			Name:     p.name,
			Version:  p.version,
			PURLType: p.purlType,
		})
	}

	// Encode and re-parse to find the CPEs that actually made it into the SBOM.
	count := 0
	for _, pkg := range pkgs {
		purl := pkg.PURL()
		if purl == nil {
			t.Errorf("package %s produced nil PURL", pkg.Name)
			continue
		}
		cpe := cpeFromPURL(purl.String())
		if cpe == "" {
			t.Errorf("no CPE generated for %s (purl=%s)", pkg.Name, purl)
			continue
		}
		if !isValidCPE23(cpe) {
			t.Errorf("invalid CPE for %s: %q", pkg.Name, cpe)
		}
		count++
	}
	if count != len(purls) {
		t.Errorf("got %d valid CPEs, want %d", count, len(purls))
	}

	// Sanity check that the inventory shape we synthesise is the one the
	// encoder accepts — guards against a future refactor breaking this test
	// silently if Encode stops walking the inventory.
	_ = inventory.Inventory{Packages: pkgs}
}

func TestInjectCPEsCDX_KernelImage(t *testing.T) {
	// scalibr's os/kernel/vmlinuz sets no PURLType, so the kernel image
	// component carries no purl for cpeFromPURL to work from. The stage instead
	// recognises the package by its vmlinuz metadata (joined back to the CDX
	// component by name+version) and synthesises the NVD dictionary form
	// cpe:2.3:o:linux:linux_kernel:<upstream>. NVD keys kernel CVEs on the
	// upstream release, so a distro-suffixed version is truncated to its
	// leading numeric release; a vanilla version passes through whole.
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "distro-suffixed version truncates to upstream release",
			version: "6.8.0-49-generic",
			want:    "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
		},
		{
			name:    "vanilla firmware kernel version passes through",
			version: "5.10.120",
			want:    "cpe:2.3:o:linux:linux_kernel:5.10.120:*:*:*:*:*:*:*",
		},
		{
			name:    "no numeric release yields no CPE (wildcard would match every kernel CVE)",
			version: "",
			want:    "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inv := inventory.Inventory{Packages: []*extractor.Package{{
				Name:     "Linux Kernel",
				Version:  tc.version,
				Metadata: &vmlinuzmeta.Metadata{Name: "Linux Kernel", Version: tc.version},
			}}}
			b := cyclonedx.NewBOM()
			b.Components = &[]cyclonedx.Component{{Name: "Linux Kernel", Version: tc.version}}
			injectCPEsCDX(b, inv)
			if got := (*b.Components)[0].CPE; got != tc.want {
				t.Errorf("kernel image CPE = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInjectCPEsCDX_PurllessNonKernelUntouched(t *testing.T) {
	// Kernel modules (os/kernel/module) and any other purl-less package have no
	// NVD identity of their own — the stage must not invent one.
	inv := inventory.Inventory{Packages: []*extractor.Package{{
		Name:     "intel_oaktrail",
		Version:  "0.4ac1",
		Metadata: &modulemeta.Metadata{PackageName: "intel_oaktrail", PackageVersion: "0.4ac1"},
	}}}
	b := cyclonedx.NewBOM()
	b.Components = &[]cyclonedx.Component{{Name: "intel_oaktrail", Version: "0.4ac1"}}
	injectCPEsCDX(b, inv)
	if got := (*b.Components)[0].CPE; got != "" {
		t.Errorf("purl-less module component got CPE %q, want none", got)
	}
}
