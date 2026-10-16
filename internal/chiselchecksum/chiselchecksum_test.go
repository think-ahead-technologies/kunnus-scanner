// ABOUTME: Tests chisel package-digest mining: the manifest's per-package sha256 that scalibr drops, recovered into a hashes.Map.
// ABOUTME: Real chiselled-noble manifest fixture + a real scalibr inventory; asserts the SHA-256 attach, malformed-digest guard, and non-chisel skip.
package chiselchecksum

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/klauspost/compress/zstd"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

const manifestPath = "var/lib/chisel/manifest.wall"

// fixtureFS serves the real chiselled-noble manifest (shared with the
// scan-seam and e2e tiers) at the conventional chisel manifest path.
func fixtureFS(t *testing.T) fstest.MapFS {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "osfamilies", "chisel", "var", "lib", "chisel", "manifest.wall"))
	if err != nil {
		t.Fatalf("read chisel fixture: %v", err)
	}
	return fstest.MapFS{manifestPath: {Data: data}}
}

func TestMine_AttachesSHA256FromManifest(t *testing.T) {
	inv := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "openssl", Version: "3.0.13-0ubuntu3.5", PURLType: purl.TypeDebian, Location: extractor.LocationFromPath(manifestPath)},
		// A deb package located in a dpkg status DB is not chisel's to hash.
		{Name: "bash", Version: "5.2", PURLType: purl.TypeDebian, Location: extractor.LocationFromPath("var/lib/dpkg/status")},
		// Non-deb packages are skipped outright.
		{Name: "left-pad", Version: "1.3.0", PURLType: purl.TypeNPM, Location: extractor.LocationFromPath("app/x")},
	}}

	got := Mine(inv, fixtureFS(t))

	opensslPURL := (&extractor.Package{Name: "openssl", Version: "3.0.13-0ubuntu3.5", PURLType: purl.TypeDebian}).PURL().String()
	hs, ok := got[opensslPURL]
	if !ok || len(hs) != 1 {
		t.Fatalf("openssl: want exactly 1 hash under %q, got map %v", opensslPURL, got)
	}
	if hs[0].Algorithm != hashes.AlgSHA256 {
		t.Errorf("openssl hash algorithm = %q, want %q", hs[0].Algorithm, hashes.AlgSHA256)
	}
	// The sha256 of openssl's package record in the fixture manifest.
	const wantHex = "00f9b292ff5636d49832e493789ec91e21cfd4e98ccc9fd23497e92a2cc9c76a"
	if hs[0].Hex != wantHex {
		t.Errorf("openssl hash = %q, want %q", hs[0].Hex, wantHex)
	}

	// Only openssl yields a hash: bash's location is not a chisel manifest and
	// left-pad is not a deb package.
	if len(got) != 1 {
		t.Errorf("want exactly 1 entry (openssl); got %d: %v", len(got), got)
	}
}

func TestMine_NoManifestIsEmpty(t *testing.T) {
	// A deb package whose manifest cannot be read yields an empty map, never a
	// panic — a missing digest must not fail the scan.
	inv := inventory.Inventory{Packages: []*extractor.Package{
		{Name: "openssl", Version: "3.0.13-0ubuntu3.5", PURLType: purl.TypeDebian, Location: extractor.LocationFromPath(manifestPath)},
	}}
	got := Mine(inv, fstest.MapFS{})
	if len(got) != 0 {
		t.Errorf("want empty map when the manifest is absent, got %v", got)
	}
}

func TestValidSHA256(t *testing.T) {
	cases := []struct {
		name  string
		field string
		ok    bool
	}{
		{"valid", "00f9b292ff5636d49832e493789ec91e21cfd4e98ccc9fd23497e92a2cc9c76a", true},
		{"too short", "00f9b292", false},
		{"not hex", "zzf9b292ff5636d49832e493789ec91e21cfd4e98ccc9fd23497e92a2cc9c76a", false},
		{"uppercase rejected (manifest digests are lowercase)", "00F9B292FF5636D49832E493789EC91E21CFD4E98CCC9FD23497E92A2CC9C76A", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSHA256(tc.field); got != tc.ok {
				t.Errorf("validSHA256(%q) = %v, want %v", tc.field, got, tc.ok)
			}
		})
	}
}

// captureSlog installs a buffer-backed slog.Default for one test and returns
// the buffer plus a restore func.
func captureSlog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf, func() { slog.SetDefault(prev) }
}

// A jsonwall record past the token cap ends the scan. The digests read so far
// are kept, but every package below the long record silently loses its
// checksum — an SBOM-visible gap that must not pass as a complete read.
func TestParseDigests_TruncationIsLogged(t *testing.T) {
	var wall bytes.Buffer
	wall.WriteString(`{"kind":"package","name":"openssl","sha256":"00f9"}` + "\n")
	wall.WriteString(`{"kind":"package","name":"` + strings.Repeat("x", 1024*1024) + `","sha256":"ab12"}` + "\n")
	wall.WriteString(`{"kind":"package","name":"libssl3t64","sha256":"cd34"}` + "\n")

	var compressed bytes.Buffer
	enc, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(wall.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}

	fsys := fstest.MapFS{manifestPath: &fstest.MapFile{Data: compressed.Bytes()}}
	logBuf, restore := captureSlog(t)
	defer restore()

	got := parseDigests(fsys, manifestPath)

	if got["openssl"] != "00f9" {
		t.Errorf("digests before the truncation were lost: %v", got)
	}
	if !strings.Contains(logBuf.String(), "truncated") {
		t.Errorf("expected a truncation warning, got %q", logBuf.String())
	}
}
