// ABOUTME: Registry-level tests. Invariants guard against the bug class where the three lists drift.
// ABOUTME: Walker tests assert the dispatch wiring from filenames → parsers → merged hash map.
package ecosystem

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

// TestRegistry_EcosystemNamesAreUnique guards against adding an ecosystem
// twice (e.g. by copy-paste error on the all[] slice). Two ecosystems sharing
// a name would shadow each other in PluginsFor lookups.
func TestRegistry_EcosystemNamesAreUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for _, eco := range all {
		if eco.Name == "" {
			t.Errorf("ecosystem has empty Name: %+v", eco)
			continue
		}
		if _, dup := seen[eco.Name]; dup {
			t.Errorf("duplicate ecosystem name %q", eco.Name)
		}
		seen[eco.Name] = struct{}{}
	}
}

// TestRegistry_FilenamesAreUniqueAcrossEcosystems guarantees ForFile is
// deterministic: a filename never belongs to two ecosystems. Without this,
// the first-match order in ForFile would silently bias toward whichever
// ecosystem appeared earlier in all[].
func TestRegistry_FilenamesAreUniqueAcrossEcosystems(t *testing.T) {
	owner := make(map[string]string)
	for _, eco := range all {
		for _, f := range eco.Filenames {
			lower := strings.ToLower(f)
			if other, dup := owner[lower]; dup {
				t.Errorf("filename %q claimed by both %q and %q", f, other, eco.Name)
			}
			owner[lower] = eco.Name
		}
	}
}

// TestRegistry_ParserFilenamesAreDetectable is the load-bearing invariant for
// this refactor: every Parser's Filenames must appear in its owning Ecosystem's
// Filenames, otherwise detect won't trigger the ecosystem when only the
// lockfile is present and the hash will never bind to a scalibr component.
// This was the exact bug the registry collapse exists to prevent.
func TestRegistry_ParserFilenamesAreDetectable(t *testing.T) {
	for _, eco := range all {
		ecoSet := make(map[string]struct{}, len(eco.Filenames))
		for _, f := range eco.Filenames {
			ecoSet[strings.ToLower(f)] = struct{}{}
		}
		for _, p := range eco.HashParsers {
			for _, f := range p.Filenames {
				if _, ok := ecoSet[strings.ToLower(f)]; !ok {
					t.Errorf("ecosystem %q parser %q claims filename %q that detect wouldn't see (missing from Ecosystem.Filenames)", eco.Name, p.Name, f)
				}
			}
		}
	}
}

// TestRegistry_ParserFieldsAreComplete catches a Parser{} declared with the
// wrong field name or a forgotten Parse func — every parser must have all
// three fields set.
func TestRegistry_ParserFieldsAreComplete(t *testing.T) {
	for _, eco := range all {
		for _, p := range eco.HashParsers {
			if p.Name == "" {
				t.Errorf("ecosystem %q has a HashParser with empty Name", eco.Name)
			}
			if len(p.Filenames) == 0 {
				t.Errorf("ecosystem %q parser %q has no filenames", eco.Name, p.Name)
			}
			if p.Parse == nil {
				t.Errorf("ecosystem %q parser %q has nil Parse func", eco.Name, p.Name)
			}
		}
	}
}

// TestRegistry_EcosystemFieldsAreComplete guards against ScalibrPlugins
// being forgotten on an ecosystem that has filenames — every detected
// ecosystem must produce at least one scalibr plugin (else detect flags it
// and the scan emits nothing).
func TestRegistry_EcosystemFieldsAreComplete(t *testing.T) {
	for _, eco := range all {
		if len(eco.Filenames) == 0 && len(eco.FilenameSuffixes) == 0 {
			t.Errorf("ecosystem %q has no filenames and no filename suffixes", eco.Name)
		}
		if len(eco.ScalibrPlugins) == 0 {
			t.Errorf("ecosystem %q has no ScalibrPlugins; detection would flag it but scalibr would do nothing", eco.Name)
		}
	}
}

func TestForFile_KnownAndUnknown(t *testing.T) {
	tests := map[string]string{
		"Cargo.lock":         "cargo",
		"cargo.lock":         "cargo",
		"CARGO.LOCK":         "cargo",
		"go.sum":             "go",
		"package-lock.json":  "npm",
		"yarn.lock":          "npm",
		"uv.lock":            "python",
		"poetry.lock":        "python",
		"conan.lock":         "cpp",
		"conanfile.py":       "cpp",
		"renv.lock":          "r",
		"unknown.file":       "",
		"":                   "",
		"MyApp.csproj":       "dotnet", // suffix match
		"x.deps.json":        "dotnet", // suffix match
	}
	for name, want := range tests {
		if got := ForFile(name); got != want {
			t.Errorf("ForFile(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPluginsFor_UnionedAndSorted(t *testing.T) {
	got := PluginsFor([]string{"go", "cargo"})
	want := []string{"go/binary", "go/gomod", "rust/cargoauditable", "rust/cargolock"}
	if !slices.Equal(got, want) {
		t.Errorf("PluginsFor(go,cargo) = %v, want %v", got, want)
	}

	if len(PluginsFor([]string{"definitely-not-an-ecosystem"})) != 0 {
		t.Error("unknown ecosystem should yield no plugins")
	}
}

func TestHashes_EmptyTreeReturnsEmptyMap(t *testing.T) {
	got := Hashes(t.TempDir(), nil)
	if len(got) != 0 {
		t.Errorf("empty tree: got %d entries, want 0", len(got))
	}
}

func TestHashes_DispatchesByFilename(t *testing.T) {
	// A minimal valid Cargo.lock under a tree with no other lockfiles proves
	// the walker → registry → parser chain wires through end-to-end.
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
