// ABOUTME: Tests for the Parser registry and the Hashes walker.
// ABOUTME: Iterates Parsers so contract violations surface as one parser is added or changed.
package lockfiles

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestParsers_FilenamesAreUnique(t *testing.T) {
	// Two parsers claiming the same filename would silently lose data
	// depending on map-build order. The registry must keep them disjoint.
	seen := make(map[string]string)
	for _, p := range Parsers {
		for _, name := range p.Filenames {
			if other, dup := seen[name]; dup {
				t.Errorf("filename %q claimed by both %q and %q", name, other, p.Name)
			}
			seen[name] = p.Name
		}
	}
}

func TestParsers_AllHaveRequiredFields(t *testing.T) {
	for i, p := range Parsers {
		if p.Name == "" {
			t.Errorf("Parsers[%d] has empty Name", i)
		}
		if len(p.Filenames) == 0 {
			t.Errorf("Parsers[%d] (%s) has no filenames", i, p.Name)
		}
		if p.Parse == nil {
			t.Errorf("Parsers[%d] (%s) has nil Parse func", i, p.Name)
		}
	}
}

func TestHashes_EmptyTreeReturnsEmptyMap(t *testing.T) {
	got := Hashes(t.TempDir(), nil)
	if len(got) != 0 {
		t.Errorf("empty tree: got %d entries, want 0", len(got))
	}
}

func TestHashes_DispatchesByFilename(t *testing.T) {
	// A minimal valid Cargo.lock under a tree with no other lockfiles
	// proves the walker → registry → parser chain wires through.
	root := t.TempDir()
	const checksum = "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f"
	writeAt(t, root, "Cargo.lock", `
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "`+checksum+`"
`)
	got := Hashes(root, nil)
	if _, ok := got["pkg:cargo/serde@1.0.0"]; !ok {
		t.Errorf("walker did not dispatch Cargo.lock through cargo parser; got %v", got)
	}
}

func TestHashes_ParseErrorLogsButContinues(t *testing.T) {
	// One broken lockfile must not block another parser's output.
	root := t.TempDir()
	writeAt(t, root, "Cargo.lock", "[[package broken toml")
	const checksum = "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f"
	writeAt(t, root, "sub/Cargo.lock", `
[[package]]
name = "ok"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "`+checksum+`"
`)
	var logBuf bytes.Buffer
	got := Hashes(root, &logBuf)
	if _, ok := got["pkg:cargo/ok@1.0.0"]; !ok {
		t.Errorf("sibling parser output lost: %v", got)
	}
	if !strings.Contains(logBuf.String(), "cargo") {
		t.Errorf("expected parse-error log mentioning cargo, got %q", logBuf.String())
	}
}
