// ABOUTME: Fuzz targets for the lockfile hash parsers — go.sum, Cargo.lock, and requirements.txt.
// ABOUTME: Each parser reads arbitrary bytes; it must never panic and every hash it emits must be valid hex under a non-empty PURL.
package ecosystem

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// assertHashesWellFormed checks the shared contract every hash parser owes the
// encoder: a non-empty PURL key mapping to hashes whose Hex is non-empty, valid
// lowercase hex. A parser that leaks a malformed digest would poison the SBOM.
func assertHashesWellFormed(t *testing.T, seed string, m hashes.Map) {
	t.Helper()
	for purl, hs := range m {
		if purl == "" {
			t.Fatalf("input %q produced a hash under an empty PURL key", seed)
		}
		for _, h := range hs {
			if h.Hex == "" {
				t.Fatalf("input %q: PURL %q has an empty hex digest", seed, purl)
			}
			if _, err := hex.DecodeString(h.Hex); err != nil {
				t.Fatalf("input %q: PURL %q hex %q is not valid hex: %v", seed, purl, h.Hex, err)
			}
		}
	}
}

// validH1 is a real-shaped go.sum module-zip hash: "h1:" + base64 of a 32-byte
// (SHA-256) digest.
var validH1 = "h1:" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))

// hex64 is a well-formed lowercase hex SHA-256, the form Cargo and pip pin.
const hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func FuzzParseGoSum(f *testing.F) {
	seeds := []string{
		"",
		"# comment only\n",
		"golang.org/x/net v0.55.0 " + validH1 + "\n",
		"golang.org/x/net v0.55.0/go.mod " + validH1 + "\n",
		"golang.org/x/net v0.55.0 h1:notbase64!!\n",
		"one two\n",
		"a b c d e\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		m, err := parseGoSum(bytes.NewReader([]byte(data)))
		if err != nil {
			return
		}
		assertHashesWellFormed(t, data, m)
	})
}

func FuzzParseCargoLock(f *testing.F) {
	seeds := []string{
		"",
		"not toml at all [[[",
		"version = 3\n",
		"[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nchecksum = \"" + hex64 + "\"\n",
		"[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nchecksum = \"tooshort\"\n",
		"[[package]]\nname = \"serde\"\nchecksum = \"" + hex64 + "\"\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		m, err := parseCargoLock(bytes.NewReader([]byte(data)))
		if err != nil {
			return
		}
		assertHashesWellFormed(t, data, m)
	})
}

func FuzzParseRequirementsTxt(f *testing.F) {
	seeds := []string{
		"",
		"# comment\n",
		"click==8.1.7 --hash=sha256:" + hex64 + "\n",
		"black==24.10.0 \\\n    --hash=sha256:" + hex64 + "\n",
		"requests[security]==2.31.0 --hash=sha256:" + hex64 + "\n",
		"-r other.txt\n",
		"foo>=1.0\n",
		"click==8.1.7 --hash=sha256:notvalidhex\n",
		strings.Repeat("a", 1<<10) + "==1.0 --hash=sha256:" + hex64 + "\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		m, err := parseRequirementsTxt(bytes.NewReader([]byte(data)))
		if err != nil {
			return
		}
		assertHashesWellFormed(t, data, m)
	})
}
