// ABOUTME: Fuzz target for the apk Q1 checksum decoder — arbitrary "C" fields in, hex SHA-1 or rejection out.
// ABOUTME: decodeQ1 must never panic and, when it accepts a field, return exactly a 40-char hex SHA-1 digest.
package apkchecksum

import (
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

// FuzzDecodeQ1 drives decodeQ1 with arbitrary checksum fields. The contract: a
// rejected field yields ("", false); an accepted field yields a lowercase hex
// SHA-1 digest of exactly sha1.Size bytes. Anything else would attach a bogus or
// mis-sized hash to a component.
func FuzzDecodeQ1(f *testing.F) {
	seeds := []string{
		"",
		"Q1",
		"Q1eVpkksZ6wkkjssudkkaXmIYCBN2A=",
		"Q1jKMx2ZpwgZjUgK4EZTBYzhfDsQs=",
		"Q1notbase64!!!",
		"Q2eVpkksZ6wkkjssudkkaXmIYCBN2A=",
		"XYZ",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, field string) {
		hexSum, ok := decodeQ1(field)
		if !ok {
			if hexSum != "" {
				t.Fatalf("decodeQ1(%q) rejected but returned non-empty hex %q", field, hexSum)
			}
			return
		}
		if len(hexSum) != 2*sha1.Size {
			t.Fatalf("decodeQ1(%q) accepted with %d hex chars, want %d", field, len(hexSum), 2*sha1.Size)
		}
		if _, err := hex.DecodeString(hexSum); err != nil {
			t.Fatalf("decodeQ1(%q) accepted but hex %q is not valid hex: %v", field, hexSum, err)
		}
	})
}
