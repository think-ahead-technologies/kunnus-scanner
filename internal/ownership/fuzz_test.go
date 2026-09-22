// ABOUTME: Fuzz targets for the dpkg .list, apk installed-db and chisel jsonwall line parsers, split out of the fs walk for testability.
// ABOUTME: parseDpkgList and parseChiselManifest must never emit an empty path; parseApkInstalled echoes record content and must never panic.
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
		paths, _ := parseDpkgList([]byte(data))
		for _, p := range paths {
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
		_, _ = parseApkInstalled([]byte(data))
	})
}

// FuzzParseChiselManifest drives the chisel jsonwall line parser with arbitrary
// bytes (the decompressed form — zstd framing is the reader's concern, not the
// parser's). Non-JSON lines and non-path records are skipped, so the invariant
// is that it never panics and every recorded path is non-empty.
func FuzzParseChiselManifest(f *testing.F) {
	seeds := []string{
		"",
		`{"jsonwall":"1.0","schema":"1.0","count":2}` + "\n" + `{"kind":"path","path":"/usr/bin/openssl","mode":"0755"}` + "\n",
		`{"kind":"path","path":"/"}` + "\n" + `{"kind":"path"}` + "\n",
		`{"kind":"content","path":"/dup"}` + "\n" + "not json\n" + `{"kind":"path","path":"no-slash"}` + "\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		paths, _ := parseChiselManifest([]byte(data))
		for _, p := range paths {
			if p == "" {
				t.Fatalf("parseChiselManifest(%q) yielded an empty path", data)
			}
		}
	})
}
