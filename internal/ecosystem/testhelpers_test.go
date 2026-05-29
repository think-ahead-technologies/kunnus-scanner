// ABOUTME: Test-only helpers shared across every parser's test file in this package.
// ABOUTME: fixtureReader feeds lockfile content to a parser; firstHash unpacks a single-hash slice for assertion ergonomics.
package ecosystem

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// fixtureReader returns content as an in-memory reader for a parser under test.
// The name documents which lockfile format the content represents; parsers read
// from an io.Reader, so nothing is written to disk.
func fixtureReader(t *testing.T, _ /* name */, content string) io.Reader {
	t.Helper()
	return strings.NewReader(content)
}

// writeAt writes content under root at the given relative path, creating any
// parent directories. Unlike writeFixture (which creates its own TempDir per
// call), this lets the walker tests place multiple files under one common root.
func writeAt(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// firstHash returns the only hash recorded for purl. Single-hash ecosystems
// (npm/cargo/nuget/conan/...) write one entry per PURL so a [0] access is
// sufficient. Multi-hash ecosystems (Python) test the full slice directly.
func firstHash(t *testing.T, m hashes.Map, purl string) (hashes.Hash, bool) {
	t.Helper()
	hs, ok := m[purl]
	if !ok || len(hs) == 0 {
		return hashes.Hash{}, false
	}
	return hs[0], true
}
