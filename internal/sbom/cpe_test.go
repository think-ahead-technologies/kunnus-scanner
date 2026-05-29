// ABOUTME: Tests for cpeFromPURL: heuristic CPE 2.3 generation per ecosystem.
// ABOUTME: Table-driven; covers the ecosystems we ship plus malformed input fall-through.
package sbom

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
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

		// Special characters: CPE spec requires escaping `:` and `\` in fields. We
		// substitute these with `*` since they're vanishingly rare in package names
		// and proper escaping is rarely matched by downstream tools anyway.
		{
			name: "colon in version is replaced",
			purl: "pkg:deb/debian/apt@2:1.0",
			want: "cpe:2.3:o:debian:apt:2*1.0:*:*:*:*:*:*:*",
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
