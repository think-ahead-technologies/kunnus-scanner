// ABOUTME: Fuzz targets for the lockfile hash parsers — go.sum, Cargo.lock, and requirements.txt.
// ABOUTME: Each parser reads arbitrary bytes; it must never panic and every hash it emits must be valid hex under a non-empty PURL.
package ecosystem

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// fuzzHashParser wires a lockfile hash parser into a fuzz target: seed it, then
// feed arbitrary bytes and assert every hash it emits is well-formed. Each
// hash parser has the same io.Reader → (hashes.Map, error) shape.
func fuzzHashParser(f *testing.F, seeds []string, parse func(io.Reader) (hashes.Map, error)) {
	f.Helper()
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		m, err := parse(bytes.NewReader([]byte(data)))
		if err != nil {
			return
		}
		assertHashesWellFormed(t, data, m)
	})
}

// fuzzLicenseParser wires a manifest licence parser into a fuzz target. Each has
// the io.Reader → ([]string, error) shape; the invariant is that no emitted
// licence identifier is empty.
func fuzzLicenseParser(f *testing.F, seeds []string, parse func(io.Reader) ([]string, error)) {
	f.Helper()
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		got, err := parse(bytes.NewReader([]byte(data)))
		if err != nil {
			return
		}
		assertLicensesWellFormed(t, data, got)
	})
}

// assertLicensesWellFormed checks a licence parser never emits an empty id — an
// empty licence string is meaningless to the downstream Normalize pipeline.
func assertLicensesWellFormed(t *testing.T, seed string, got []string) {
	t.Helper()
	for _, id := range got {
		if id == "" {
			t.Fatalf("input %q produced an empty licence id in %v", seed, got)
		}
	}
}

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

// sha512SRI is a real npm-style integrity value shared by the npm-family seeds.
const sha512SRI = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="

func FuzzParseBunLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		`{"packages":{"lodash":["lodash@4.17.21","",{},"` + sha512SRI + `"]}}`,
	}, parseBunLock)
}

func FuzzParseYarnLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		"# yarn lockfile v1\n\"lodash@^4.17.0\":\n  version \"4.17.21\"\n  integrity " + sha512SRI + "\n",
	}, parseYarnLock)
}

func FuzzParseNPMLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		`{"packages":{"node_modules/lodash":{"version":"4.17.21","integrity":"` + sha512SRI + `"}}}`,
	}, parseNPMLock)
}

func FuzzParsePNPMLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		"lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.21:\n    resolution:\n      integrity: " + sha512SRI + "\n",
	}, parsePNPMLock)
}

func FuzzParseConanLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		`{"version":"0.5","requires":["zlib/1.2.11#ffa77daf83a57094149707928bdce823%1667396813.184"]}`,
	}, parseConanLock)
}

func FuzzParseGemfileLockChecksums(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		"CHECKSUMS\n  rake (13.2.1) sha256=46cb38dae65d7d74b6020a4ac9d48afed8eb8149c040eccf0523bec91dff8e23\n",
	}, parseGemfileLockChecksums)
}

func FuzzParseNuGetLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		`{"dependencies":{"net6.0":{"Newtonsoft.Json":{"resolved":"13.0.3","contentHash":"HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="}}}}`,
	}, parseNuGetLock)
}

func FuzzParseUvLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		"[[package]]\nname = \"emoji\"\nversion = \"2.14.0\"\nsdist = { url = \"https://x.invalid/e.tar.gz\", hash = \"sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1\", size = 1 }\n",
	}, parseUvLock)
}

func FuzzParsePipfileLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		`{"default":{"itsdangerous":{"hashes":["sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"],"version":"==2.1.2"}}}`,
	}, parsePipfileLock)
}

func FuzzParseStackYamlLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		"packages:\n- completed:\n    hackage: mtl-2.3.1@sha256:5badb3e5b6e8e2bb5d32392ed1748231fb02e944c2247f4041a32ae8e8b75605,1799\n  original:\n    hackage: mtl-2.3.1\n",
	}, parseStackYamlLock)
}

func FuzzParsePyPIPackagesFilesLock(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		"[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\nfiles = [{file = \"requests-2.31.0.tar.gz\", hash = \"sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1\"}]\n",
	}, parsePyPIPackagesFilesLock)
}

func FuzzParseComposerLockHashes(f *testing.F) {
	fuzzHashParser(f, []string{
		"",
		`{"packages":[{"name":"psr/log","version":"3.0.0","dist":{"type":"zip","url":"https://x.test/l.zip","shasum":"fe5ea303b0887d5caefd3d431c3e61ad47037001"}}]}`,
	}, parseComposerLockHashes)
}

func FuzzParsePackageJSONLicense(f *testing.F) {
	fuzzLicenseParser(f, []string{
		"",
		`{"name":"x","version":"1","license":"MIT"}`,
	}, parsePackageJSONLicense)
}

func FuzzParseWheelMetadataLicense(f *testing.F) {
	fuzzLicenseParser(f, []string{
		"",
		"Metadata-Version: 2.1\nName: x\nLicense: BSD-3-Clause\n",
	}, parseWheelMetadataLicense)
}

func FuzzParseRockspecLicense(f *testing.F) {
	fuzzLicenseParser(f, []string{
		"",
		"license = 'Apache-2.0'\n",
	}, parseRockspecLicense)
}

func FuzzParseGemspecLicense(f *testing.F) {
	fuzzLicenseParser(f, []string{
		"",
		"Gem::Specification.new do |s|\n  s.license = \"MIT\"\nend\n",
	}, parseGemspecLicense)
}

// FuzzParseJavaArchiveLicense fuzzes the JAR licence parser, whose input is a
// zip archive rather than text. The seed is a minimal jar carrying a Maven
// pom.xml licence block; the invariant is that no emitted licence id is empty.
func FuzzParseJavaArchiveLicense(f *testing.F) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/maven/com.example/lib/pom.xml")
	if err != nil {
		f.Fatal(err)
	}
	if _, err := io.WriteString(w, `<project xmlns="http://maven.apache.org/POM/4.0.0"><licenses><license><name>Apache License, Version 2.0</name><url>https://www.apache.org/licenses/LICENSE-2.0.txt</url></license></licenses></project>`); err != nil {
		f.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		f.Fatal(err)
	}
	f.Add(buf.Bytes())
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := parseJavaArchiveLicense(bytes.NewReader(data))
		if err != nil {
			return
		}
		assertLicensesWellFormed(t, "<jar bytes>", got)
	})
}
