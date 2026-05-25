// ABOUTME: Tests for package-lock.json hash extraction.
// ABOUTME: Verifies scoped/unscoped naming, SHA-512 decode, and skip of non-sha512 entries.
package lockfiles

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// sha512OfLodash is the integrity hash for lodash@4.17.21 as it appears on
// npm. Real production value — picked because it's stable and verifiable.
const (
	lodashIntegrity = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
	babelIntegrity  = "sha512-NF0d/qS49QXR0KdLLOh01SpQIYL40zPmFKvkrJSjQM4XW0XalwYJzKtTPa67yvbnDqfa3SF9oFvbgD+kgavkew=="
)

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestParseNPMLock_V2_Unscoped(t *testing.T) {
	path := writeFixture(t, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "root", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.21",
      "integrity": "`+lodashIntegrity+`"
    }
  }
}`)

	got, err := parseNPMLock(path)
	if err != nil {
		t.Fatalf("parseNPMLock: %v", err)
	}
	const purl = "pkg:npm/lodash@4.17.21"
	h, ok := got[purl]
	if !ok {
		t.Fatalf("missing %q in result: %v", purl, got)
	}
	if h.Algorithm != hashes.AlgSHA512 {
		t.Errorf("algorithm = %q, want SHA-512", h.Algorithm)
	}
	if len(h.Hex) != 128 {
		t.Errorf("hex digest length = %d, want 128", len(h.Hex))
	}
	if _, err := hex.DecodeString(h.Hex); err != nil {
		t.Errorf("hex digest not parseable: %v", err)
	}
}

func TestParseNPMLock_V2_Scoped(t *testing.T) {
	// Scoped packages produce pkg:npm/%40babel/core@version PURLs to match
	// scalibr's percent-encoding of the leading "@" in scope names.
	path := writeFixture(t, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@babel/core": {
      "version": "7.0.0",
      "integrity": "`+babelIntegrity+`"
    }
  }
}`)

	got, err := parseNPMLock(path)
	if err != nil {
		t.Fatalf("parseNPMLock: %v", err)
	}
	const purl = "pkg:npm/%40babel/core@7.0.0"
	if _, ok := got[purl]; !ok {
		t.Errorf("missing %q in result: %v", purl, got)
	}
}

func TestParseNPMLock_V1Compat(t *testing.T) {
	// v1 has dependencies (not packages); same integrity format.
	path := writeFixture(t, "package-lock.json", `{
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "integrity": "`+lodashIntegrity+`"
    }
  }
}`)

	got, err := parseNPMLock(path)
	if err != nil {
		t.Fatalf("parseNPMLock: %v", err)
	}
	if _, ok := got["pkg:npm/lodash@4.17.21"]; !ok {
		t.Errorf("v1 lockfile not parsed: %v", got)
	}
}

func TestParseNPMLock_SkipsNonSha512(t *testing.T) {
	// BSI demands SHA-512. SHA-1 entries (older npm) must be skipped, not
	// downgraded.
	path := writeFixture(t, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/old-thing": {
      "version": "0.1.0",
      "integrity": "sha1-abcdefghijklmnopqrstuvwxyz12"
    }
  }
}`)

	got, err := parseNPMLock(path)
	if err != nil {
		t.Fatalf("parseNPMLock: %v", err)
	}
	if _, ok := got["pkg:npm/old-thing@0.1.0"]; ok {
		t.Errorf("expected SHA-1 entry to be skipped, got %v", got)
	}
}

func TestParseNPMLock_SkipsRootAndLinkedPaths(t *testing.T) {
	// "" is the project root, "node_modules/foo/node_modules/bar" is a
	// nested dep — we want both. But entries with no integrity (e.g.
	// link: file dependencies) must be silently skipped.
	path := writeFixture(t, "package-lock.json", `{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "root", "version": "0.0.0" },
    "node_modules/foo": {
      "version": "1.0.0",
      "integrity": "`+lodashIntegrity+`"
    },
    "node_modules/local-link": {
      "version": "file:../local",
      "link": true
    }
  }
}`)
	got, _ := parseNPMLock(path)
	if _, ok := got["pkg:npm/foo@1.0.0"]; !ok {
		t.Errorf("missing real package: %v", got)
	}
	if _, ok := got["pkg:npm/local-link@file:../local"]; ok {
		t.Error("link entry should not be emitted")
	}
}

func TestParseNPMLock_MalformedFileReturnsError(t *testing.T) {
	path := writeFixture(t, "package-lock.json", `not json at all`)
	if _, err := parseNPMLock(path); err == nil {
		t.Error("want error for malformed JSON, got nil")
	}
}
