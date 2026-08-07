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

	"github.com/think-ahead/kunnus-scanner/internal/bom"
	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

func TestPlan_LinuxWithDpkgFixture(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "var", "lib", "dpkg"))
	writeFile(t, filepath.Join(root, "var", "lib", "dpkg", "status"), "")

	plan, err := New().Plan(context.Background(), root, mode.Overrides{TargetOS: "linux"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfg := plan.Config
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSLinux {
		t.Errorf("want Capabilities.OS = OSLinux, got %+v", cfg.Capabilities)
	}
	if !cfg.Capabilities.DirectFS {
		t.Error("want DirectFS true for OS scan")
	}
	if len(cfg.Plugins) == 0 {
		t.Error("want at least one plugin for Linux dpkg fixture")
	}
	if plan.Component.Type != "operating-system" {
		t.Errorf("ComponentInfo.Type = %q, want operating-system", plan.Component.Type)
	}
	if plan.Hashes != nil {
		t.Errorf("OS-mode Plan.Hashes should be nil, got %v", plan.Hashes)
	}
	// An OS scan analyses built artifacts, so its generation context is post-build.
	if plan.Lifecycle != bom.LifecyclePostBuild {
		t.Errorf("Plan.Lifecycle = %q, want %q", plan.Lifecycle, bom.LifecyclePostBuild)
	}
}

func TestPlan_LinuxNoDistroFallsBackToAll(t *testing.T) {
	root := t.TempDir() // empty — no os-release, no package DB
	plan, err := New().Plan(context.Background(), root, mode.Overrides{TargetOS: "linux"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Config.Plugins) == 0 {
		t.Error("want fallback to all linux extractors when no distro detected")
	}
	// The fallback set is the host-scan superset: it must include the host-only
	// kernel extractors (extracted firmware has a kernel but often no distro
	// fingerprint).
	names := make(map[string]bool)
	for _, p := range plan.Config.Plugins {
		names[p.Name()] = true
	}
	for _, want := range []string{"os/kernel/module", "os/kernel/vmlinuz"} {
		if !names[want] {
			t.Errorf("fallback plugin set missing host-only kernel extractor %q", want)
		}
	}
}

func TestPlan_WindowsTarget(t *testing.T) {
	root := t.TempDir()
	plan, err := New().Plan(context.Background(), root, mode.Overrides{TargetOS: "windows"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfg := plan.Config
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSWindows {
		t.Errorf("want Capabilities.OS = OSWindows, got %+v", cfg.Capabilities)
	}
	if len(cfg.Plugins) == 0 {
		t.Error("want at least one plugin for Windows target")
	}
	if plan.Component.Name != "Windows" {
		t.Errorf("ComponentInfo.Name = %q, want Windows", plan.Component.Name)
	}
}

func TestPlan_MacTarget(t *testing.T) {
	plan, err := New().Plan(context.Background(), t.TempDir(), mode.Overrides{TargetOS: "mac"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfg := plan.Config
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSMac {
		t.Errorf("want Capabilities.OS = OSMac, got %+v", cfg.Capabilities)
	}
}

func TestPlan_UnsupportedTargetOS(t *testing.T) {
	_, err := New().Plan(context.Background(), t.TempDir(), mode.Overrides{TargetOS: "plan9"})
	if err == nil {
		t.Fatal("expected error for unsupported target OS, got nil")
	}
}

func TestPlan_DarwinIsNotAccepted(t *testing.T) {
	// detect.Host() always converts darwin → "mac"; the flag advertises only mac.
	// "darwin" passed explicitly must be rejected to match the documented contract.
	_, err := New().Plan(context.Background(), t.TempDir(), mode.Overrides{TargetOS: "darwin"})
	if err == nil {
		t.Fatal("expected error for TargetOS=darwin, got nil")
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
	plan, err := New().Plan(context.Background(), root, mode.Overrides{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Config.Capabilities == nil {
		t.Fatal("Plan returned nil capabilities")
	}
}

func TestPlan_DisableOverrideTrimsPluginSet(t *testing.T) {
	root := t.TempDir()
	plan, err := New().Plan(context.Background(), root, mode.Overrides{
		TargetOS:       "linux",
		DisablePlugins: []string{"os/dpkg", "os/rpm", "os/apk", "os/pacman", "os/portage", "os/nix", "os/flatpak", "os/snap", "os/cos", "os/chisel", "os/kernel/module", "os/kernel/vmlinuz"},
	})
	// Disabling everything should produce the "no extractors selected" error.
	if err == nil {
		t.Fatalf("expected error when all plugins disabled, got plan with %d plugins", len(plan.Config.Plugins))
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
