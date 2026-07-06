// ABOUTME: Fuzz targets for the dpkg .list and apk installed-db line parsers, split out of the fs walk for testability.
// ABOUTME: parseDpkgList must never emit an empty path; parseApkInstalled echoes record content and must never panic.
package ownership

import "testing"

// FuzzParseDpkgList drives the dpkg .list line parser with arbitrary bytes. Its
// contract is that every path it records is non-empty (blank lines are dropped);
// an empty owned path would match nothing meaningful in Owns.
func FuzzParseDpkgList(f *testing.F) {
	seeds := []string{
		"",
		"/usr/bin/xz\n/usr/bin/xzcat\n",
		"/.\n/usr\n/usr/lib/postgresql/18/bin/postgres\n",
		"  /leading/space  \nno-leading-slash\n\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		for _, p := range parseDpkgList([]byte(data)) {
			if p == "" {
				t.Fatalf("parseDpkgList(%q) yielded an empty path", data)
			}
		}
	})
}

// FuzzParseApkInstalled drives the apk installed-db record parser with arbitrary
// bytes. The parser faithfully echoes whatever F:/R: records contain, so the
// universal invariant is simply that it never panics on malformed input (short
// lines, orphan R: records, non-record lines).
func FuzzParseApkInstalled(f *testing.F) {
	seeds := []string{
		"",
		"P:busybox\nV:1.37.0-r30\nF:bin\nR:busybox\nR:busybox.suid\nF:usr/sbin\nR:ssl_client\n",
		"F:\nR:toplevel\n",
		"garbage\nX:y\nR:orphan\nF\n:\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		_ = parseApkInstalled([]byte(data))
	})
}
