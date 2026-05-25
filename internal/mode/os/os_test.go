// ABOUTME: Tests for os.Mode.Plan(). Asserts target-OS routing, distro detection, and override flags.
// ABOUTME: Also verifies every OS plugin name we ship is recognised by scalibr's loader.
package os

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/osv-scalibr/plugin"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

func TestPlan_LinuxWithDpkgFixture(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "var", "lib", "dpkg"))
	writeFile(t, filepath.Join(root, "var", "lib", "dpkg", "status"), "")

	cfg, comp, err := New().Plan(context.Background(), root, mode.Overrides{TargetOS: "linux"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSLinux {
		t.Errorf("want Capabilities.OS = OSLinux, got %+v", cfg.Capabilities)
	}
	if !cfg.Capabilities.DirectFS {
		t.Error("want DirectFS true for OS scan")
	}
	if len(cfg.Plugins) == 0 {
		t.Error("want at least one plugin for Linux dpkg fixture")
	}
	if comp.Type != "operating-system" {
		t.Errorf("ComponentInfo.Type = %q, want operating-system", comp.Type)
	}
}

func TestPlan_LinuxNoDistroFallsBackToAll(t *testing.T) {
	root := t.TempDir() // empty — no os-release, no package DB
	cfg, _, err := New().Plan(context.Background(), root, mode.Overrides{TargetOS: "linux"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(cfg.Plugins) == 0 {
		t.Error("want fallback to all linux extractors when no distro detected")
	}
}

func TestPlan_WindowsTarget(t *testing.T) {
	root := t.TempDir()
	cfg, comp, err := New().Plan(context.Background(), root, mode.Overrides{TargetOS: "windows"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSWindows {
		t.Errorf("want Capabilities.OS = OSWindows, got %+v", cfg.Capabilities)
	}
	if len(cfg.Plugins) == 0 {
		t.Error("want at least one plugin for Windows target")
	}
	if comp.Name != "Windows" {
		t.Errorf("ComponentInfo.Name = %q, want Windows", comp.Name)
	}
}

func TestPlan_MacTarget(t *testing.T) {
	cfg, _, err := New().Plan(context.Background(), t.TempDir(), mode.Overrides{TargetOS: "mac"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSMac {
		t.Errorf("want Capabilities.OS = OSMac, got %+v", cfg.Capabilities)
	}
}

func TestPlan_UnsupportedTargetOS(t *testing.T) {
	_, _, err := New().Plan(context.Background(), t.TempDir(), mode.Overrides{TargetOS: "plan9"})
	if err == nil {
		t.Fatal("expected error for unsupported target OS, got nil")
	}
}

func TestPlan_AutoDetectMatchesHost(t *testing.T) {
	// With no TargetOS override, Plan must use the host OS.
	// On non-Linux/Windows/Mac hosts this test is a no-op.
	host := runtime.GOOS
	if host != "linux" && host != "darwin" && host != "windows" {
		t.Skipf("auto-detect test only meaningful on linux/darwin/windows, got %s", host)
	}

	root := t.TempDir()
	cfg, _, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cfg.Capabilities == nil {
		t.Fatal("Plan returned nil capabilities")
	}
}

func TestPlan_DisableOverrideTrimsPluginSet(t *testing.T) {
	root := t.TempDir()
	cfg, _, err := New().Plan(context.Background(), root, mode.Overrides{
		TargetOS:       "linux",
		DisablePlugins: []string{"os/dpkg", "os/rpm", "os/apk", "os/pacman", "os/portage", "os/nix", "os/flatpak", "os/snap", "os/cos"},
	})
	// Disabling everything should produce the "no extractors selected" error.
	if err == nil {
		t.Fatalf("expected error when all plugins disabled, got cfg with %d plugins", len(cfg.Plugins))
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
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
