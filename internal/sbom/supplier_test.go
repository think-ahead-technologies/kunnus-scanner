// ABOUTME: Tests for supplierFromPURL: heuristic component-supplier identity per ecosystem.
// ABOUTME: Each supplier carries a URL the BSI checker accepts as a creator identifier.
package sbom

import "testing"

func TestSupplierFromPURL(t *testing.T) {
	tests := []struct {
		name     string
		purl     string
		wantName string
		wantURL  string
	}{
		{
			name:     "github-hosted Go module",
			purl:     "pkg:golang/github.com/google/uuid@v1.6.0",
			wantName: "google",
			wantURL:  "https://github.com/google",
		},
		{
			name:     "gitlab-hosted Go module",
			purl:     "pkg:golang/gitlab.com/gitlab-org/api/client-go@v1.0.0",
			wantName: "gitlab-org",
			wantURL:  "https://gitlab.com/gitlab-org",
		},
		{
			name:     "Go non-github host",
			purl:     "pkg:golang/deps.dev/util/maven@1.0.0",
			wantName: "deps.dev",
			wantURL:  "https://deps.dev",
		},
		{
			name:     "Go stdlib special case",
			purl:     "pkg:golang/stdlib@1.26.3",
			wantName: "The Go Authors",
			wantURL:  "https://go.dev",
		},
		{
			name:     "npm scoped",
			purl:     "pkg:npm/%40babel/core@7.0.0",
			wantName: "@babel",
			wantURL:  "https://www.npmjs.com/org/babel",
		},
		{
			name:     "npm unscoped",
			purl:     "pkg:npm/lodash@4.17.21",
			wantName: "lodash",
			wantURL:  "https://www.npmjs.com/package/lodash",
		},
		{
			name:     "pypi",
			purl:     "pkg:pypi/requests@2.31.0",
			wantName: "requests",
			wantURL:  "https://pypi.org/project/requests/",
		},
		{
			name:     "maven",
			purl:     "pkg:maven/org.springframework/spring-core@5.3.31",
			wantName: "org.springframework",
			wantURL:  "https://central.sonatype.com/artifact/org.springframework/spring-core",
		},
		{
			name:     "nuget",
			purl:     "pkg:nuget/Newtonsoft.Json@13.0.3",
			wantName: "Newtonsoft.Json",
			wantURL:  "https://www.nuget.org/packages/Newtonsoft.Json",
		},
		{
			name:     "cargo",
			purl:     "pkg:cargo/serde@1.0.200",
			wantName: "serde",
			wantURL:  "https://crates.io/crates/serde",
		},
		{
			name:     "composer (php)",
			purl:     "pkg:composer/symfony/console@6.4.0",
			wantName: "symfony",
			wantURL:  "https://packagist.org/packages/symfony/console",
		},
		{
			name:     "gem",
			purl:     "pkg:gem/rails@7.1.0",
			wantName: "rails",
			wantURL:  "https://rubygems.org/gems/rails",
		},
		{
			name:     "deb",
			purl:     "pkg:deb/debian/openssl@3.0.11-1",
			wantName: "Debian",
			wantURL:  "https://www.debian.org",
		},
		{
			name:     "rpm-fedora",
			purl:     "pkg:rpm/fedora/curl@8.4.0-1.fc39",
			wantName: "Fedora Project",
			wantURL:  "https://fedoraproject.org",
		},
		{
			name:     "apk",
			purl:     "pkg:apk/alpine/musl@1.2.4-r2",
			wantName: "Alpine Linux",
			wantURL:  "https://alpinelinux.org",
		},

		// When we cannot confidently derive a supplier, name and URL are
		// empty — the caller must not attach a Supplier in that case.
		{
			name:     "unknown ecosystem",
			purl:     "pkg:weirdtype/foo@1.0",
			wantName: "",
			wantURL:  "",
		},
		{
			name:     "garbage",
			purl:     "not-a-purl",
			wantName: "",
			wantURL:  "",
		},
		{
			name:     "empty",
			purl:     "",
			wantName: "",
			wantURL:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotURL := supplierFromPURL(tc.purl)
			if gotName != tc.wantName || gotURL != tc.wantURL {
				t.Errorf("supplierFromPURL(%q)\n  got:  name=%q url=%q\n  want: name=%q url=%q",
					tc.purl, gotName, gotURL, tc.wantName, tc.wantURL)
			}
		})
	}
}
