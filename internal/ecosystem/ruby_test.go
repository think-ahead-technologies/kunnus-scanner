// ABOUTME: Tests for Gemfile.lock CHECKSUMS extraction (Bundler >= 2.6).
// ABOUTME: Lines are `name (version[-platform]) sha256=<hex>`; platform suffixes strip to match scalibr's purl.
package ecosystem

import (
	"os"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// known-good SHA-256 hex strings (64 chars). They don't have to be real gem
// checksums — the parser cares about shape, not provenance.
const (
	gemShasum         = "46cb38dae65d7d74b6020a4ac9d48afed8eb8149c040eccf0523bec91dff8e23"
	gemShasumPlatform = "0b4e792d5b8b88b1f53e72e3cd6a691044bcd2ba31df40b988e22fb8ad732e87"
)

func TestParseGemfileLockChecksums(t *testing.T) {
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    rake (13.2.1)
    rspec-core (3.13.0)
      rspec-support (~> 3.13.0)

PLATFORMS
  ruby

DEPENDENCIES
  rake
  rspec-core

CHECKSUMS
  rake (13.2.1) sha256=` + gemShasum + `
  rspec-core (3.13.0) sha256=` + gemShasum + `

BUNDLED WITH
   2.6.2
`
	got, err := parseGemfileLockChecksums(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseGemfileLockChecksums: %v", err)
	}
	// Dashed gem names split at the parenthesis, not the dash.
	for _, want := range []string{"pkg:gem/rake@13.2.1", "pkg:gem/rspec-core@3.13.0"} {
		h, ok := firstHash(t, got, want)
		if !ok {
			t.Errorf("missing %q in %v", want, got)
			continue
		}
		if h.Algorithm != hashes.AlgSHA256 {
			t.Errorf("%q algorithm = %q, want SHA-256", want, h.Algorithm)
		}
		if h.Hex != gemShasum {
			t.Errorf("%q hex = %q, want %q", want, h.Hex, gemShasum)
		}
	}
	// Only the CHECKSUMS section feeds the map — the GEM specs carry no hashes.
	if len(got) != 2 {
		t.Errorf("want exactly 2 entries, got %d: %v", len(got), got)
	}
}

func TestParseGemfileLockChecksums_PlatformVariantsShareOnePURL(t *testing.T) {
	// Platform-specific gems repeat name@version with a platform suffix and a
	// different digest per artifact. scalibr's purl drops the suffix, so both
	// digests must land on the same purl — the multi-hash case hashes.Map
	// carries (like Python wheels).
	lock := `CHECKSUMS
  nokogiri (1.16.0) sha256=` + gemShasum + `
  nokogiri (1.16.0-arm64-darwin) sha256=` + gemShasumPlatform + `
`
	got, err := parseGemfileLockChecksums(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseGemfileLockChecksums: %v", err)
	}
	hs := got["pkg:gem/nokogiri@1.16.0"]
	if len(hs) != 2 {
		t.Fatalf("want 2 hashes under one purl, got %v", got)
	}
	hexes := map[string]bool{hs[0].Hex: true, hs[1].Hex: true}
	if !hexes[gemShasum] || !hexes[gemShasumPlatform] {
		t.Errorf("want both platform digests, got %v", hs)
	}
}

func TestParseGemfileLockChecksums_SkipsUncheckedAndMalformed(t *testing.T) {
	// Bundler writes a bare `name (version)` line when no checksum was
	// recorded; unknown algorithms and junk digests must be dropped rather
	// than emitted.
	lock := `CHECKSUMS
  unchecked (1.0.0)
  unknownalgo (1.0.0) md5=abcdefabcdefabcdefabcdefabcdefab
  badlen (1.0.0) sha256=deadbeef
  nonhex (1.0.0) sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
  good (1.0.0) sha256=` + gemShasum + `
`
	got, err := parseGemfileLockChecksums(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseGemfileLockChecksums: %v", err)
	}
	if _, ok := got["pkg:gem/good@1.0.0"]; !ok {
		t.Errorf("missing good package: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("unchecked/malformed lines must be skipped, got %v", got)
	}
}

func TestParseGemfileLockChecksums_RailsLockfileCorpus(t *testing.T) {
	// The shared ruby fixture is the real rails/rails Gemfile.lock (Bundler 4).
	// Parsing it here keeps the corpus and the parser from drifting apart:
	// a fixture update to a shape the parser misses turns this red.
	f, err := os.Open("../../testdata/ecosystems/ruby/Gemfile.lock")
	if err != nil {
		t.Fatalf("open corpus fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := parseGemfileLockChecksums(f)
	if err != nil {
		t.Fatalf("parseGemfileLockChecksums: %v", err)
	}
	// The lock records 250 sha256 lines; 5 are nokogiri platform variants
	// collapsing onto one purl, so well over 200 distinct purls must survive.
	if len(got) < 200 {
		t.Errorf("want >= 200 hashed purls from the rails lockfile, got %d", len(got))
	}
	if h, ok := firstHash(t, got, "pkg:gem/rake@13.3.0"); !ok {
		t.Error("missing pkg:gem/rake@13.3.0")
	} else if h.Hex != "96f5092d786ff412c62fde76f793cc0541bd84d2eb579caa529aa8a059934493" {
		t.Errorf("rake hex = %q, want the lockfile's digest", h.Hex)
	}
	// One ruby build + four platform builds, all on the suffix-stripped purl.
	if hs := got["pkg:gem/nokogiri@1.19.1"]; len(hs) != 5 {
		t.Errorf("want 5 nokogiri platform digests on one purl, got %d: %v", len(hs), hs)
	}
	// PATH-sourced rails gems have bare CHECKSUMS lines — no digest, no entry.
	if _, ok := got["pkg:gem/activesupport@8.2.0.alpha"]; ok {
		t.Error("bare (checksum-less) PATH gem must not appear")
	}
}

func TestParseGemfileLockChecksums_NoChecksumsSection(t *testing.T) {
	// Pre-2.6 lockfiles have no CHECKSUMS section at all — an empty map, not
	// an error.
	lock := `GEM
  remote: https://rubygems.org/
  specs:
    rake (13.0.6)

DEPENDENCIES
  rake

BUNDLED WITH
   2.4.10
`
	got, err := parseGemfileLockChecksums(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseGemfileLockChecksums: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty map for pre-2.6 lockfile, got %v", got)
	}
}
