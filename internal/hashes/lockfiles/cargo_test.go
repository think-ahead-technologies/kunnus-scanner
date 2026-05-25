// ABOUTME: Tests for Cargo.lock hash extraction.
// ABOUTME: checksum is hex SHA-256 (no SRI prefix); only registry packages carry one.
package lockfiles

import (
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// known-good SHA-256 hex string (64 chars). Doesn't have to be a real crate
// hash — the parser cares about shape, not provenance.
const cargoChecksum = "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f"

func TestParseCargoLock_RegistryPackages(t *testing.T) {
	path := writeFixture(t, "Cargo.lock", `
version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "`+cargoChecksum+`"

[[package]]
name = "serde_json"
version = "1.0.117"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "`+cargoChecksum+`"
dependencies = [
 "serde",
]
`)
	got, err := parseCargoLock(path)
	if err != nil {
		t.Fatalf("parseCargoLock: %v", err)
	}
	for _, want := range []string{"pkg:cargo/serde@1.0.200", "pkg:cargo/serde_json@1.0.117"} {
		h, ok := got[want]
		if !ok {
			t.Errorf("missing %q in %v", want, got)
			continue
		}
		if h.Algorithm != hashes.AlgSHA256 {
			t.Errorf("%q algorithm = %q, want SHA-256", want, h.Algorithm)
		}
		if h.Hex != cargoChecksum {
			t.Errorf("%q hex = %q, want %q", want, h.Hex, cargoChecksum)
		}
	}
}

func TestParseCargoLock_SkipsPackagesWithoutChecksum(t *testing.T) {
	// Local-path and git packages have no checksum field. The workspace root
	// package likewise. All must be silently skipped (no false-positive
	// entries with empty hashes).
	path := writeFixture(t, "Cargo.lock", `
[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "git-dep"
version = "0.0.0"
source = "git+https://github.com/foo/bar.git#abc"

[[package]]
name = "registered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "`+cargoChecksum+`"
`)
	got, _ := parseCargoLock(path)
	if _, ok := got["pkg:cargo/registered@1.0.0"]; !ok {
		t.Errorf("missing registered package: %v", got)
	}
	if _, ok := got["pkg:cargo/my-app@0.1.0"]; ok {
		t.Errorf("root package should be skipped (no checksum)")
	}
	if _, ok := got["pkg:cargo/git-dep@0.0.0"]; ok {
		t.Errorf("git package should be skipped (no checksum)")
	}
}

func TestParseCargoLock_RejectsMalformedChecksum(t *testing.T) {
	// checksum must be 64 hex chars. Anything shorter / non-hex is dropped
	// rather than emitted as a junk value.
	path := writeFixture(t, "Cargo.lock", `
[[package]]
name = "bad-len"
version = "1.0.0"
checksum = "deadbeef"

[[package]]
name = "non-hex"
version = "1.0.0"
checksum = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
`)
	got, _ := parseCargoLock(path)
	if _, ok := got["pkg:cargo/bad-len@1.0.0"]; ok {
		t.Error("short checksum must be skipped")
	}
	if _, ok := got["pkg:cargo/non-hex@1.0.0"]; ok {
		t.Error("non-hex checksum must be skipped")
	}
}

func TestParseCargoLock_MalformedTOMLErrors(t *testing.T) {
	path := writeFixture(t, "Cargo.lock", `[[package broken`)
	if _, err := parseCargoLock(path); err == nil {
		t.Error("want error for malformed TOML")
	}
}
