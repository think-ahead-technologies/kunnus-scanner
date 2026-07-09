// ABOUTME: Tests for the ESP-IDF dependencies.lock hash parser — SHA-256 component hashes keyed by pkg:generic purls.
// ABOUTME: The fixture mirrors a real component-manager lockfile: registry components with hashes, the idf pseudo-component without.
package ecosystem

import (
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

const espidfLockFixture = `dependencies:
  espressif/led_strip:
    component_hash: 384db8dd8f4d4d0dd5d941358588c4455bb783e6588e04fbcfdc27eab6d199a8
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 2.5.5
  espressif/mdns:
    component_hash: 32b5eb0ab00b8d17a30d2f5f5cd4bab5a1d1b8ed3f1d0d4a1e07a06f0f0e2a55
    source:
      registry_url: https://components.espressif.com/
      type: service
    version: 1.8.2
  idf:
    source:
      type: idf
    version: 5.3.1
direct_dependencies:
- espressif/led_strip
- espressif/mdns
- idf
manifest_hash: 8ed35f6b5e83e7cb1cbcc28f0b6cd9a26e59ab5aa9b83c8be0e3f4b2d5a1c377
target: esp32
version: 2.0.0
`

func TestParseESPIDFLock(t *testing.T) {
	got, err := parseESPIDFLock(strings.NewReader(espidfLockFixture))
	if err != nil {
		t.Fatalf("parseESPIDFLock: %v", err)
	}

	want := map[string]string{ // purl -> sha256 hex
		"pkg:generic/espressif/led_strip@2.5.5": "384db8dd8f4d4d0dd5d941358588c4455bb783e6588e04fbcfdc27eab6d199a8",
		"pkg:generic/espressif/mdns@1.8.2":      "32b5eb0ab00b8d17a30d2f5f5cd4bab5a1d1b8ed3f1d0d4a1e07a06f0f0e2a55",
	}
	if len(got) != len(want) {
		t.Errorf("got %d entries %v, want %d (idf has no component_hash and must not appear)", len(got), got, len(want))
	}
	for purl, hexDigest := range want {
		hs := got[purl]
		if len(hs) != 1 {
			t.Errorf("purl %q: got %d hashes, want 1", purl, len(hs))
			continue
		}
		if hs[0].Algorithm != hashes.AlgSHA256 || hs[0].Hex != hexDigest {
			t.Errorf("purl %q = %s:%s, want SHA-256:%s", purl, hs[0].Algorithm, hs[0].Hex, hexDigest)
		}
	}
}

func TestParseESPIDFLock_Malformed(t *testing.T) {
	cases := map[string]string{
		"not yaml":       "\t{{{",
		"truncated hash": "dependencies:\n  a/b:\n    component_hash: abc123\n    version: 1.0.0\n",
		"non-hex hash":   "dependencies:\n  a/b:\n    component_hash: " + strings.Repeat("zz", 32) + "\n    version: 1.0.0\n",
		"missing version": "dependencies:\n  a/b:\n    component_hash: " +
			strings.Repeat("ab", 32) + "\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseESPIDFLock(strings.NewReader(input))
			if err == nil && len(got) != 0 {
				t.Errorf("parseESPIDFLock(%q) = %v, want empty or error", input, got)
			}
		})
	}
}
