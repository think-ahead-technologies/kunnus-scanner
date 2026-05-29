// ABOUTME: Unit tests for the container planner: config shape, capability filtering, and source resolution.
// ABOUTME: White-box (package container) so it can exercise the unexported buildConfig and resolveSource.
package container

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/plugin"

	"github.com/think-ahead/kunnus-scanner/internal/mode"
)

func TestBuildConfig_UnionLinuxFiltered(t *testing.T) {
	cfg, err := buildConfig(mode.Overrides{})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Capabilities == nil || cfg.Capabilities.OS != plugin.OSLinux {
		t.Fatalf("capabilities OS = %v, want Linux", cfg.Capabilities)
	}
	if len(cfg.Plugins) == 0 {
		t.Fatal("expected a non-empty plugin set")
	}

	names := make(map[string]bool)
	for _, p := range cfg.Plugins {
		names[p.Name()] = true
	}
	// The union must span OS and language ecosystems...
	for _, want := range []string{"os/dpkg", "os/apk"} {
		if !names[want] {
			t.Errorf("expected Linux OS plugin %q in container config", want)
		}
	}
	// ...and must drop the Windows-only PE extractor under Linux capabilities.
	if names["dotnet/pe"] {
		t.Error("dotnet/pe must be filtered out for a Linux container scan")
	}
}

func TestBuildConfig_DisableOverride(t *testing.T) {
	cfg, err := buildConfig(mode.Overrides{DisablePlugins: []string{"os/dpkg"}})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	for _, p := range cfg.Plugins {
		if p.Name() == "os/dpkg" {
			t.Error("os/dpkg should be removed when disabled via overrides")
		}
	}
}

func TestResolveSource(t *testing.T) {
	f := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		ref  string
		src  Source
		want Source
	}{
		{"auto resolves existing file to tarball", f, SourceAuto, SourceTarball},
		{"auto resolves image name to remote", "alpine:3.18", SourceAuto, SourceRemote},
		{"explicit source is respected", f, SourceRemote, SourceRemote},
		{"explicit docker is respected", "alpine:3.18", SourceDocker, SourceDocker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveSource(tc.ref, tc.src); got != tc.want {
				t.Errorf("resolveSource(%q, %q) = %q, want %q", tc.ref, tc.src, got, tc.want)
			}
		})
	}
}

func TestOpen_EmptyRefErrors(t *testing.T) {
	if _, err := Open(context.Background(), "", SourceAuto, mode.Overrides{}); err == nil {
		t.Fatal("want error for empty image reference")
	}
}
