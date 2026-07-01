// ABOUTME: Tests apk pull-checksum mining: the Q1<base64-sha1> field scalibr drops, recovered into a hashes.Map.
// ABOUTME: Real apk DB text + a real scalibr inventory; asserts the SHA-1 decode, the invalid-length guard, and non-apk skip.
package apkchecksum

import (
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func TestMine_AttachesSHA1FromValidQ1(t *testing.T) {
	const dbPath = "lib/apk/db/installed"
	// musl carries a real Q1 checksum (Q1 + base64 of a 20-byte SHA-1).
	// badpkg carries "Q1eVpkksZ6wkkjssudkkaXmIYCBN2A=" — valid base64 but it
	// decodes to 21 bytes, not a SHA-1, so it must be skipped, never mislabelled.
	db := "C:Q1jKMx2ZpwgZjUgK4EZTBYzhfDsQs=\nP:musl\nV:1.2.4-r2\nA:x86_64\n\n" +
		"C:Q1eVpkksZ6wkkjssudkkaXmIYCBN2A=\nP:badpkg\nV:1.0\n"
	fsys := fstest.MapFS{dbPath: {Data: []byte(db)}}

	inv := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "musl", Version: "1.2.4-r2", PURLType: purl.TypeApk, Location: extractor.LocationFromPath(dbPath)},
		{Name: "badpkg", Version: "1.0", PURLType: purl.TypeApk, Location: extractor.LocationFromPath(dbPath)},
		{Name: "left-pad", Version: "1.3.0", PURLType: purl.TypeNPM, Location: extractor.LocationFromPath("app/x")},
	}}

	got := Mine(inv, fsys)

	muslPURL := (&extractor.Package{Name: "musl", Version: "1.2.4-r2", PURLType: purl.TypeApk}).PURL().String()
	hs, ok := got[muslPURL]
	if !ok || len(hs) != 1 {
		t.Fatalf("musl: want exactly 1 hash under %q, got map %v", muslPURL, got)
	}
	if hs[0].Algorithm != hashes.AlgSHA1 {
		t.Errorf("musl hash algorithm = %q, want %q", hs[0].Algorithm, hashes.AlgSHA1)
	}
	const wantHex = "8ca331d99a708198d480ae04653058ce17c3b10b"
	if hs[0].Hex != wantHex {
		t.Errorf("musl hash = %q, want %q", hs[0].Hex, wantHex)
	}

	// Only musl yields a hash: badpkg's checksum is the wrong length (guard),
	// left-pad is not an apk package (skipped).
	if len(got) != 1 {
		t.Errorf("want exactly 1 entry (musl); got %d: %v", len(got), got)
	}
}

func TestMine_NoAPKDBIsEmpty(t *testing.T) {
	// An image with apk packages whose DB cannot be read yields an empty map,
	// never a panic — a missing checksum must not fail the scan.
	inv := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "musl", Version: "1.2.4-r2", PURLType: purl.TypeApk, Location: extractor.LocationFromPath("lib/apk/db/installed")},
	}}
	got := Mine(inv, fstest.MapFS{})
	if len(got) != 0 {
		t.Errorf("want empty map when the DB is absent, got %v", got)
	}
}

func TestDecodeQ1(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  string
		ok    bool
	}{
		{"valid sha1", "Q1jKMx2ZpwgZjUgK4EZTBYzhfDsQs=", "8ca331d99a708198d480ae04653058ce17c3b10b", true},
		{"wrong length (21 bytes)", "Q1eVpkksZ6wkkjssudkkaXmIYCBN2A=", "", false},
		{"not base64", "Q1!!!notbase64!!!", "", false},
		{"missing Q1 prefix", "jKMx2ZpwgZjUgK4EZTBYzhfDsQs=", "", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := decodeQ1(tc.field)
			if ok != tc.ok || got != tc.want {
				t.Errorf("decodeQ1(%q) = (%q, %v), want (%q, %v)", tc.field, got, ok, tc.want, tc.ok)
			}
		})
	}
}
