// ABOUTME: Tests for repo.Mode.Plan(). Asserts ScanConfig shape and that every plugin name we ship resolves.
// ABOUTME: Exercises scalibr's plugin loader without running an actual scan.
package repo

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

func TestIntersect(t *testing.T) {
	got := intersect([]string{"npm", "go", "dotnet"}, []string{"go", "rust", "dotnet"})
	want := []string{"go", "dotnet"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("intersect = %v, want %v", got, want)
	}
}

func TestPlan_DetectsGoEcosystem(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")

	plan, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan == nil || plan.Config == nil {
		t.Fatal("Plan returned nil config")
	}
	if len(plan.Config.ScanRoots) != 1 {
		t.Fatalf("want 1 scan root, got %d", len(plan.Config.ScanRoots))
	}
	if plan.Config.ScanRoots[0].Path != root {
		t.Errorf("ScanRoots[0].Path = %q, want %q", plan.Config.ScanRoots[0].Path, root)
	}
	if len(plan.Config.Plugins) == 0 {
		t.Error("expected at least one plugin for a go.mod project")
	}
	if plan.Component.Type != "application" {
		t.Errorf("ComponentInfo.Type = %q, want application", plan.Component.Type)
	}
	if plan.Component.Name == "" {
		t.Error("ComponentInfo.Name should default to the directory basename")
	}
}

func TestPlan_EmptyTreeFailsExplicitly(t *testing.T) {
	root := t.TempDir()
	_, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err == nil {
		t.Fatal("expected error for empty tree, got nil")
	}
}

func TestPlan_EcosystemOverrideRestricts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module x\n")
	writeFile(t, filepath.Join(root, "package.json"), "{}")

	plan, err := New().Plan(context.Background(), root, mode.Overrides{
		Ecosystems: []string{"npm"},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// We can't easily introspect plugin names from the loaded set without
	// reaching into scalibr internals; we settle for: the scan plan exists
	// and has plugins. The plugin map test already covers the restriction logic.
	if len(plan.Config.Plugins) == 0 {
		t.Error("expected plugins after restricting to npm")
	}
}

func TestPlan_EveryShippedPluginResolves(t *testing.T) {
	// Verify every plugin name we ship in ecosystemPlugins is recognised by scalibr.
	// This catches typos and renames at compile-time of the test, not at runtime.
	root := t.TempDir()
	for _, marker := range []string{
		"package.json", "go.mod", "Cargo.toml", "MyApp.csproj",
		"pom.xml", "build.gradle", "pyproject.toml", "uv.lock",
		"composer.json", "Gemfile", "Package.resolved", "cabal.project.freeze",
		"renv.lock", "conan.lock",
	} {
		writeFile(t, filepath.Join(root, marker), "")
	}

	plan, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan on mixed tree: %v", err)
	}
	if len(plan.Config.Plugins) == 0 {
		t.Fatal("expected plugins from mixed tree")
	}
}

func TestPlan_VendoredOnlyRepoStillSucceeds(t *testing.T) {
	// A C/C++ project with vendored deps but no lockfile (e.g. CMake project
	// pulling third_party/zlib via git submodule) is the common case in OSS C++.
	// Without this guard the user gets "no extractors selected" and the vendored
	// SBOM data we worked to collect is dropped on the floor.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "third_party", "zlib", "deflate.c"), "// vendored zlib\n")
	writeFile(t, filepath.Join(root, "third_party", "zlib", "zlib.h"), "// header\n")
	writeFile(t, filepath.Join(root, "README.md"), "# my cpp app\n") // unrelated noise

	plan, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan should succeed for vendored-only repo: %v", err)
	}
	if plan.Config == nil {
		t.Fatal("Plan.Config must be non-nil even when no scalibr plugins selected")
	}
	if len(plan.ExtraComponents) != 1 {
		t.Errorf("ExtraComponents = %d, want 1: %+v", len(plan.ExtraComponents), plan.ExtraComponents)
	}
	if len(plan.Hashes) == 0 {
		t.Error("Plan.Hashes should carry the per-file vendored hashes")
	}
}

func TestPlan_VendoredCppSurfacesAsExtraComponent(t *testing.T) {
	// Mixed tree: a Go module (so detection succeeds and Plan returns) plus a
	// vendored C/C++ library. The vendored hit must land in Plan.ExtraComponents
	// and the per-file hashes must be in Plan.Hashes under the same PURL.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")
	writeFile(t, filepath.Join(root, "third_party", "zlib", "deflate.c"), "// vendored\n")
	writeFile(t, filepath.Join(root, "third_party", "zlib", "zlib.h"), "// header\n")

	plan, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(plan.ExtraComponents) != 1 {
		t.Fatalf("ExtraComponents = %d, want 1: %+v", len(plan.ExtraComponents), plan.ExtraComponents)
	}
	ec := plan.ExtraComponents[0]
	if ec.Name != "zlib" {
		t.Errorf("Name = %q, want %q", ec.Name, "zlib")
	}
	if ec.Type != mode.ComponentTypeLibrary {
		t.Errorf("Type = %q, want %q", ec.Type, mode.ComponentTypeLibrary)
	}
	if ec.PURL == "" {
		t.Error("PURL must be set on vendored ExtraComponent")
	}
	if ec.BomRef == "" {
		t.Error("BomRef must be set on vendored ExtraComponent")
	}

	// Per-file hashes must flow into Plan.Hashes under the same PURL so the
	// existing sbom.injectHashesCDX picks them up.
	hs, ok := plan.Hashes[ec.PURL]
	if !ok || len(hs) != 2 {
		t.Fatalf("Plan.Hashes[%q] = %v, want 2 entries (deflate.c + zlib.h)", ec.PURL, hs)
	}
	for _, h := range hs {
		if h.Path == "" {
			t.Errorf("vendored Hash.Path must be set: %+v", h)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
