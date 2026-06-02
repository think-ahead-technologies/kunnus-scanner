// ABOUTME: Tests the composer.lock offline license and hash parsers.
// ABOUTME: composer.lock embeds a per-package license array and a dist.shasum (SHA-1) for dist archives.
package ecosystem

import (
	"reflect"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func TestParseComposerLock(t *testing.T) {
	const lock = `{
	  "packages": [
	    {"name": "psr/log", "version": "3.0.0", "license": ["MIT"]},
	    {"name": "vendor/multi", "version": "1.2.3", "license": ["MIT", "Apache-2.0"]},
	    {"name": "vendor/strlicense", "version": "2.0.0", "license": "BSD-3-Clause"},
	    {"name": "vendor/nolicense", "version": "0.1.0"}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "10.0.0", "license": ["BSD-3-Clause"]}
	  ]
	}`

	got, err := parseComposerLock(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseComposerLock: %v", err)
	}

	want := map[string][]string{
		"pkg:composer/psr/log@3.0.0":           {"MIT"},
		"pkg:composer/vendor/multi@1.2.3":      {"MIT", "Apache-2.0"},
		"pkg:composer/vendor/strlicense@2.0.0": {"BSD-3-Clause"}, // string form, not array
		"pkg:composer/phpunit/phpunit@10.0.0":  {"BSD-3-Clause"}, // packages-dev included
	}
	for purl, wantLics := range want {
		if !reflect.DeepEqual(got[purl], wantLics) {
			t.Errorf("%s: got %v, want %v", purl, got[purl], wantLics)
		}
	}
	if _, ok := got["pkg:composer/vendor/nolicense@0.1.0"]; ok {
		t.Errorf("package without a license must not appear: %v", got["pkg:composer/vendor/nolicense@0.1.0"])
	}
}

// known-good SHA-1 hex string (40 chars). Doesn't have to be a real dist
// shasum — the parser cares about shape, not provenance.
const composerShasum = "fe5ea303b0887d5caefd3d431c3e61ad47037001"

func TestParseComposerLockHashes_DistShasum(t *testing.T) {
	lock := `{
	  "packages": [
	    {"name": "psr/log", "version": "3.0.0",
	     "dist": {"type": "zip", "url": "https://example.test/log.zip", "shasum": "` + composerShasum + `"}}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "10.0.0",
	     "dist": {"type": "zip", "url": "https://example.test/phpunit.zip", "shasum": "` + composerShasum + `"}}
	  ]
	}`

	got, err := parseComposerLockHashes(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseComposerLockHashes: %v", err)
	}
	// packages-dev is covered too, mirroring the license parser.
	for _, want := range []string{"pkg:composer/psr/log@3.0.0", "pkg:composer/phpunit/phpunit@10.0.0"} {
		h, ok := firstHash(t, got, want)
		if !ok {
			t.Errorf("missing %q in %v", want, got)
			continue
		}
		if h.Algorithm != hashes.AlgSHA1 {
			t.Errorf("%q algorithm = %q, want SHA-1", want, h.Algorithm)
		}
		if h.Hex != composerShasum {
			t.Errorf("%q hex = %q, want %q", want, h.Hex, composerShasum)
		}
	}
}

func TestParseComposerLockHashes_SkipsPackagesWithoutShasum(t *testing.T) {
	// GitHub-zipball dists ship an empty shasum; path/git installs carry no
	// dist at all. Both must be silently skipped (no false-positive entries
	// with empty hashes).
	lock := `{
	  "packages": [
	    {"name": "vendor/emptyshasum", "version": "1.0.0",
	     "dist": {"type": "zip", "url": "https://api.github.com/repos/v/e/zipball/abc", "shasum": ""}},
	    {"name": "vendor/nodist", "version": "2.0.0"},
	    {"name": "vendor/hashed", "version": "3.0.0",
	     "dist": {"type": "zip", "url": "https://example.test/h.zip", "shasum": "` + composerShasum + `"}}
	  ]
	}`

	got, err := parseComposerLockHashes(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseComposerLockHashes: %v", err)
	}
	if _, ok := got["pkg:composer/vendor/hashed@3.0.0"]; !ok {
		t.Errorf("missing hashed package: %v", got)
	}
	if _, ok := got["pkg:composer/vendor/emptyshasum@1.0.0"]; ok {
		t.Error("empty shasum must be skipped")
	}
	if _, ok := got["pkg:composer/vendor/nodist@2.0.0"]; ok {
		t.Error("package without dist must be skipped")
	}
}

func TestParseComposerLockHashes_RejectsMalformedShasum(t *testing.T) {
	// shasum must be 40 hex chars (SHA-1). Anything shorter / non-hex is
	// dropped rather than emitted as a junk value.
	lock := `{
	  "packages": [
	    {"name": "vendor/badlen", "version": "1.0.0", "dist": {"shasum": "deadbeef"}},
	    {"name": "vendor/nonhex", "version": "1.0.0",
	     "dist": {"shasum": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}}
	  ]
	}`

	got, err := parseComposerLockHashes(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseComposerLockHashes: %v", err)
	}
	if _, ok := got["pkg:composer/vendor/badlen@1.0.0"]; ok {
		t.Error("short shasum must be skipped")
	}
	if _, ok := got["pkg:composer/vendor/nonhex@1.0.0"]; ok {
		t.Error("non-hex shasum must be skipped")
	}
}

func TestParseComposerLockHashes_MalformedJSONErrors(t *testing.T) {
	if _, err := parseComposerLockHashes(strings.NewReader(`{"packages": [`)); err == nil {
		t.Error("want error for malformed JSON")
	}
}
