// ABOUTME: Tests for normalizePURL — decoding the escaped namespace separator while leaving version/qualifiers intact.
package sbom

import "testing"

func TestNormalizePURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "npm scoped escaped separator",
			in:   "pkg:npm/%40isaacs%2Fcliui@8.0.2",
			want: "pkg:npm/%40isaacs/cliui@8.0.2",
		},
		{
			name: "npm scoped with qualifiers preserved",
			in:   "pkg:npm/%40npmcli%2Farborist@7.5.4?source=UNKNOWN",
			want: "pkg:npm/%40npmcli/arborist@7.5.4?source=UNKNOWN",
		},
		{
			name: "composer vendor/package",
			in:   "pkg:composer/psr%2Flog@3.0.0",
			want: "pkg:composer/psr/log@3.0.0",
		},
		{
			name: "lowercase %2f also decoded",
			in:   "pkg:composer/psr%2flog@3.0.0",
			want: "pkg:composer/psr/log@3.0.0",
		},
		{
			name: "unscoped npm unchanged",
			in:   "pkg:npm/lodash@4.17.21",
			want: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "deb with epoch unchanged",
			in:   "pkg:deb/debian/bsdutils@1%3A2.41-5?arch=amd64",
			want: "pkg:deb/debian/bsdutils@1%3A2.41-5?arch=amd64",
		},
		{
			name: "escaped slash in qualifier is left alone",
			in:   "pkg:generic/zlib?vendored_path=third_party%2Fzlib",
			want: "pkg:generic/zlib?vendored_path=third_party%2Fzlib",
		},
		{
			name: "already-conventional scoped form unchanged",
			in:   "pkg:npm/%40babel/core@7.0.0",
			want: "pkg:npm/%40babel/core@7.0.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePURL(tc.in); got != tc.want {
				t.Errorf("normalizePURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
