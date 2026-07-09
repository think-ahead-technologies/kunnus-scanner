// ABOUTME: Registry-level tests. Invariants guard against the bug class where the three lists drift.
// ABOUTME: Walker tests assert the dispatch wiring from filenames → parsers → merged hash map.
package ecosystem

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestAllInstalledPlugins_IsUnionSortedAndDeduped verifies AllInstalledPlugins
// returns the deduplicated, sorted union of every ecosystem's installed-state
// plugins — the set container scanning enables.
func TestAllInstalledPlugins_IsUnionSortedAndDeduped(t *testing.T) {
	got := AllInstalledPlugins()
	if len(got) == 0 {
		t.Fatal("AllInstalledPlugins returned nothing")
	}
	if !slices.IsSorted(got) {
		t.Errorf("AllInstalledPlugins not sorted: %v", got)
	}
	seen := make(map[string]struct{})
	for _, p := range got {
		if _, dup := seen[p]; dup {
			t.Errorf("AllInstalledPlugins has duplicate %q", p)
		}
		seen[p] = struct{}{}
	}
	// It must include go's installed extractor (the Go binary) but not its
	// source-only one (go.mod), which describes declared, not installed, deps.
	if _, ok := seen["go/binary"]; !ok {
		t.Error("AllInstalledPlugins missing the installed go extractor go/binary")
	}
	if _, ok := seen["go/gomod"]; ok {
		t.Error("AllInstalledPlugins must not include the source-only go/gomod")
	}
}

// TestInstalledPluginsAreScalibrPluginsSubset enforces that every InstalledPlugins
// entry is also declared in ScalibrPlugins — the installed set is a subset of an
// ecosystem's full plugin set, never a separate list that can drift.
func TestInstalledPluginsAreScalibrPluginsSubset(t *testing.T) {
	for _, eco := range all {
		full := make(map[string]struct{}, len(eco.ScalibrPlugins))
		for _, p := range eco.ScalibrPlugins {
			full[p] = struct{}{}
		}
		for _, p := range eco.InstalledPlugins {
			if _, ok := full[p]; !ok {
				t.Errorf("ecosystem %q: InstalledPlugins %q is not in ScalibrPlugins", eco.Name, p)
			}
		}
	}
}

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
// ecosystem must produce components, either via at least one scalibr plugin or
// a kunnus-native extractor (NativeExtractor). Otherwise detect flags it and the
// scan emits nothing.
func TestRegistry_EcosystemFieldsAreComplete(t *testing.T) {
	for _, eco := range all {
		if len(eco.Filenames) == 0 && len(eco.FilenameSuffixes) == 0 {
			t.Errorf("ecosystem %q has no filenames and no filename suffixes", eco.Name)
		}
		if len(eco.ScalibrPlugins) == 0 && !eco.NativeExtractor {
			t.Errorf("ecosystem %q has no ScalibrPlugins and no NativeExtractor; detection would flag it but nothing would produce components", eco.Name)
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
		"MyApp.csproj":       "dotnet",       // suffix match
		"x.deps.json":        "dotnet",       // suffix match
		"foo-1.0-1.rockspec": "lua",          // luarocks spec file
		"my_gem.gemspec":     "ruby",         // ruby gem spec
		"cmsis.mtb":          "modustoolbox", // ModusToolbox dependency manifest (suffix match)
		"freertos.MTB":       "modustoolbox", // case-insensitive suffix
		".mtbqueryapi":       "",             // longer suffix must not match .mtb
		"vcpkg.json":         "vcpkg",        // vcpkg manifest
		"VCPKG.JSON":         "vcpkg",        // case-insensitive
		"vcpkg-lock.json":    "",             // only the manifest marks the ecosystem
		".gitmodules":        "gitsubmodule", // git submodule manifest
		".gitmodules.bak":    "",             // exact name only
		"platformio.ini":     "platformio",   // PlatformIO project config
		"PLATFORMIO.INI":     "platformio",   // case-insensitive
		"idf_component.yml":  "espidf",       // ESP-IDF component manifest
		"dependencies.lock":  "espidf",       // ESP-IDF resolved lockfile
		"west.yml":           "zephyr",       // Zephyr west manifest
		"west.yaml":          "zephyr",       // alternate spelling
	}
	for name, want := range tests {
		if got := ForFile(name); got != want {
			t.Errorf("ForFile(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestPluginsFor_UnionedAndSorted(t *testing.T) {
	got := PluginsFor([]string{"go", "cargo"})
	want := []string{"go/binary", "go/gomod", "rust/cargoauditable", "rust/cargolock", "rust/cargotoml"}
	if !slices.Equal(got, want) {
		t.Errorf("PluginsFor(go,cargo) = %v, want %v", got, want)
	}

	if len(PluginsFor([]string{"definitely-not-an-ecosystem"})) != 0 {
		t.Error("unknown ecosystem should yield no plugins")
	}
}

func TestSurvey_EmptyTree(t *testing.T) {
	ecos, digests, _ := Survey(os.DirFS(t.TempDir()))
	if len(ecos) != 0 {
		t.Errorf("empty tree: got ecosystems %v, want []", ecos)
	}
	if len(digests) != 0 {
		t.Errorf("empty tree: got %d digest entries, want 0", len(digests))
	}
}

func TestSurvey_DetectsEcosystems(t *testing.T) {
	tests := []struct {
		name  string
		files []string // file paths relative to scan root
		want  []string // expected canonical ecosystems, sorted
	}{
		{"node project", []string{"package.json", "package-lock.json"}, []string{"npm"}},
		{"bun project", []string{"package.json", "bun.lock"}, []string{"npm"}},
		{"bun-only project", []string{"bun.lock"}, []string{"npm"}},
		{"go project", []string{"go.mod", "go.sum"}, []string{"go"}},
		{"rust project", []string{"Cargo.toml", "Cargo.lock"}, []string{"cargo"}},
		{"dotnet csproj", []string{"myapp/MyApp.csproj"}, []string{"dotnet"}},
		{"dotnet packages.lock.json", []string{"packages.lock.json"}, []string{"dotnet"}},
		{"python pyproject + poetry", []string{"pyproject.toml", "poetry.lock"}, []string{"python"}},
		{"python uv-only project", []string{"uv.lock"}, []string{"python"}},
		{"cpp conan project", []string{"conanfile.py", "conan.lock"}, []string{"cpp"}},
		{"cpp conanfile.txt only", []string{"conanfile.txt"}, []string{"cpp"}},
		{"vcpkg manifest project", []string{"vcpkg.json"}, []string{"vcpkg"}},
		{"git submodule project", []string{".gitmodules"}, []string{"gitsubmodule"}},
		{"platformio project", []string{"platformio.ini"}, []string{"platformio"}},
		{"esp-idf project", []string{"main/idf_component.yml", "dependencies.lock"}, []string{"espidf"}},
		{"zephyr west workspace", []string{"west.yml"}, []string{"zephyr"}},
		{
			name: "mixed monorepo",
			files: []string{
				"backend/go.mod",
				"frontend/package.json",
				"frontend/pnpm-lock.yaml",
				"services/api/MyApi.csproj",
			},
			want: []string{"dotnet", "go", "npm"},
		},
		{
			name: "skip-dir contents ignored",
			files: []string{
				"go.mod",
				"node_modules/foo/package.json",
				".git/HEAD",
				"vendor/cargo/Cargo.toml",
			},
			want: []string{"go"},
		},
		{"case-insensitive lockfile names", []string{"Gemfile", "Gemfile.lock"}, []string{"ruby"}},
		{"ruby gem source repo via .gemspec", []string{"my_gem.gemspec"}, []string{"ruby"}},
		{"lua rockspec project", []string{"foo-1.0-1.rockspec"}, []string{"lua"}},
		{"unrelated files ignored", []string{"README.md", "src/main.go", "LICENSE"}, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, rel := range tc.files {
				writeAt(t, root, rel, "")
			}
			got, _, _ := Survey(os.DirFS(root))
			if got == nil {
				got = []string{}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Survey(%q) ecosystems = %v, want %v", root, got, tc.want)
			}
		})
	}
}

func TestSurvey_PermissionErrorOnSubdirSkipped(t *testing.T) {
	root := t.TempDir()
	writeAt(t, root, "go.mod", "")

	bad := filepath.Join(root, "locked")
	if err := os.Mkdir(bad, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o755) })

	got, _, _ := Survey(os.DirFS(root))
	if !slices.Equal(got, []string{"go"}) {
		t.Errorf("Survey with unreadable subdir: %v, want [go]", got)
	}
}

func TestSurvey_DispatchesByFilename(t *testing.T) {
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
	_, digests, _ := Survey(os.DirFS(root))
	if _, ok := digests["pkg:cargo/serde@1.0.0"]; !ok {
		t.Errorf("walker did not dispatch Cargo.lock through cargo parser; got %v", digests)
	}
}

func TestSurvey_ParseErrorLogsButContinues(t *testing.T) {
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
	logBuf, restore := captureSlog(t)
	defer restore()

	_, digests, _ := Survey(os.DirFS(root))
	if _, ok := digests["pkg:cargo/ok@1.0.0"]; !ok {
		t.Errorf("sibling parser output lost: %v", digests)
	}
	if !strings.Contains(logBuf.String(), "cargo") {
		t.Errorf("expected parse-error log mentioning cargo, got %q", logBuf.String())
	}
}

// captureSlog installs a buffer-backed slog.Default for the duration of one
// test and returns the buffer plus a restore func. Used by tests that assert
// on log output rather than return values.
func captureSlog(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return buf, func() { slog.SetDefault(prev) }
}
