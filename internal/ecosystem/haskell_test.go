// ABOUTME: Tests for stack.yaml.lock hash extraction.
// ABOUTME: The completed.hackage pin carries the SHA-256 of the revisioned .cabal file; pantry-tree keys are not emitted.
package ecosystem

import (
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// known-good SHA-256 hex string (64 chars). Doesn't have to be a real Hackage
// pin — the parser cares about shape, not provenance.
const stackShasum = "5badb3e5b6e8e2bb5d32392ed1748231fb02e944c2247f4041a32ae8e8b75605"

// pantryTreeShasum stands in for the pantry-internal source-tree key that the
// parser must NOT emit.
const pantryTreeShasum = "7a39c2592bcecf5e64b67d863e074a4b2eb6e2eb38ed5a3a37e25fa4ed11e6dc"

func TestParseStackYamlLock_HackagePins(t *testing.T) {
	lock := `
packages:
- completed:
    hackage: mtl-2.3.1@sha256:` + stackShasum + `,1799
    pantry-tree:
      size: 638
      sha256: ` + pantryTreeShasum + `
  original:
    hackage: mtl-2.3.1
- completed:
    hackage: utf8-string-1.0.2@sha256:` + stackShasum + `,2484
    pantry-tree:
      size: 526
      sha256: ` + pantryTreeShasum + `
  original:
    hackage: utf8-string-1.0.2
snapshots:
- completed:
    sha256: ` + pantryTreeShasum + `
    size: 650475
    url: https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/22/33.yaml
  original: lts-22.33
`
	got, err := parseStackYamlLock(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseStackYamlLock: %v", err)
	}
	// Multi-segment names split on the LAST dash, matching scalibr's purl form.
	for _, want := range []string{"pkg:haskell/mtl@2.3.1", "pkg:haskell/utf8-string@1.0.2"} {
		h, ok := firstHash(t, got, want)
		if !ok {
			t.Errorf("missing %q in %v", want, got)
			continue
		}
		if h.Algorithm != hashes.AlgSHA256 {
			t.Errorf("%q algorithm = %q, want SHA-256", want, h.Algorithm)
		}
		if h.Hex != stackShasum {
			t.Errorf("%q hex = %q, want %q", want, h.Hex, stackShasum)
		}
	}
	// The snapshot hash and pantry-tree keys must not ride in as components.
	if len(got) != 2 {
		t.Errorf("want exactly 2 entries, got %d: %v", len(got), got)
	}
}

func TestParseStackYamlLock_SkipsNonHackagePackages(t *testing.T) {
	// Git/path-sourced packages carry no hackage pin; pins without the
	// @sha256 locator (bare name-version) carry no hash. Both must be
	// silently skipped.
	lock := `
packages:
- completed:
    name: my-local-pkg
    version: 0.1.0
    git: https://github.com/foo/bar.git
    commit: abc123
- completed:
    hackage: bare-pin-1.0.0
- completed:
    hackage: hashed-0.5.0@sha256:` + stackShasum + `,613
`
	got, err := parseStackYamlLock(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseStackYamlLock: %v", err)
	}
	if _, ok := got["pkg:haskell/hashed@0.5.0"]; !ok {
		t.Errorf("missing hashed package: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("non-hackage / bare pins must be skipped, got %v", got)
	}
}

func TestParseStackYamlLock_RejectsMalformedPins(t *testing.T) {
	// The locator hash must be 64 hex chars and the pin must split into
	// name-version. Anything else is dropped rather than emitted as junk.
	lock := `
packages:
- completed:
    hackage: badlen-1.0.0@sha256:deadbeef,100
- completed:
    hackage: nonhex-1.0.0@sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,100
- completed:
    hackage: noversion@sha256:` + stackShasum + `,100
`
	got, err := parseStackYamlLock(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseStackYamlLock: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("malformed pins must all be skipped, got %v", got)
	}
}

func TestParseStackYamlLock_MalformedYAMLErrors(t *testing.T) {
	if _, err := parseStackYamlLock(strings.NewReader("packages: [\n")); err == nil {
		t.Error("want error for malformed YAML")
	}
}
