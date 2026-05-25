// ABOUTME: Tests for repo.Mode.Plan(). Asserts ScanConfig shape and that every plugin name we ship resolves.
// ABOUTME: Exercises scalibr's plugin loader without running an actual scan.
package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

func TestPlan_DetectsGoEcosystem(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.21\n")

	cfg, comp, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cfg == nil {
		t.Fatal("Plan returned nil config")
	}
	if len(cfg.ScanRoots) != 1 {
		t.Fatalf("want 1 scan root, got %d", len(cfg.ScanRoots))
	}
	if cfg.ScanRoots[0].Path != root {
		t.Errorf("ScanRoots[0].Path = %q, want %q", cfg.ScanRoots[0].Path, root)
	}
	if len(cfg.Plugins) == 0 {
		t.Error("expected at least one plugin for a go.mod project")
	}
	if comp.Type != "application" {
		t.Errorf("ComponentInfo.Type = %q, want application", comp.Type)
	}
	if comp.Name == "" {
		t.Error("ComponentInfo.Name should default to the directory basename")
	}
}

func TestPlan_EmptyTreeFailsExplicitly(t *testing.T) {
	root := t.TempDir()
	_, _, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err == nil {
		t.Fatal("expected error for empty tree, got nil")
	}
}

func TestPlan_EcosystemOverrideRestricts(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module x\n")
	writeFile(t, filepath.Join(root, "package.json"), "{}")

	cfg, _, err := New().Plan(context.Background(), root, mode.Overrides{
		Ecosystems: []string{"npm"},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// We can't easily introspect plugin names from the loaded set without
	// reaching into scalibr internals; we settle for: the scan plan exists
	// and has plugins. The plugin map test already covers the restriction logic.
	if len(cfg.Plugins) == 0 {
		t.Error("expected plugins after restricting to npm")
	}
}

func TestPlan_EveryShippedPluginResolves(t *testing.T) {
	// Verify every plugin name we ship in ecosystemPlugins is recognised by scalibr.
	// This catches typos and renames at compile-time of the test, not at runtime.
	root := t.TempDir()
	for _, marker := range []string{
		"package.json", "go.mod", "Cargo.toml", "MyApp.csproj",
		"pom.xml", "build.gradle", "pyproject.toml",
		"composer.json", "Gemfile", "Package.resolved", "cabal.project.freeze",
		"renv.lock",
	} {
		writeFile(t, filepath.Join(root, marker), "")
	}

	cfg, _, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan on mixed tree: %v", err)
	}
	if len(cfg.Plugins) == 0 {
		t.Fatal("expected plugins from mixed tree")
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
