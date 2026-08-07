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

func TestBuildConfig_InstalledOnlyLinuxFiltered(t *testing.T) {
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
	// Must span Linux OS families, the installed-state language extractors, and
	// the embedded-SBOM extractors...
	for _, want := range []string{"os/dpkg", "os/apk", "javascript/packagejson", "sbom/cdx", "sbom/spdx"} {
		if !names[want] {
			t.Errorf("expected installed-state plugin %q in container config", want)
		}
	}
	// ...must NOT include lockfile/source extractors (those report declared, not
	// installed, dependencies — the container over-reporting we avoid)...
	for _, unwanted := range []string{"javascript/packagelockjson", "go/gomod", "javascript/yarnlock"} {
		if names[unwanted] {
			t.Errorf("lockfile/source extractor %q must not be in a container scan", unwanted)
		}
	}
	// ...and must drop the Windows-only PE extractor under Linux capabilities.
	if names["dotnet/pe"] {
		t.Error("dotnet/pe must be filtered out for a Linux container scan")
	}
	// ...and must not include host-only families (containers have no kernel).
	for _, unwanted := range []string{"os/kernel/module", "os/kernel/vmlinuz"} {
		if names[unwanted] {
			t.Errorf("host-only extractor %q must not be in a container scan", unwanted)
		}
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

func TestSeriesIdentity(t *testing.T) {
	cases := []struct {
		name        string
		target      string
		src         Source
		wantID      string
		wantVersion string
	}{
		{"tag reference splits into repo path and tag", "ghcr.io/acme/app:v1.2.3", SourceRemote, "ghcr.io/acme/app", "v1.2.3"},
		{"bare name normalizes and defaults to latest", "alpine", SourceRemote, "index.docker.io/library/alpine", "latest"},
		{"digest reference keeps repo path, no version", "ghcr.io/acme/app@sha256:0000000000000000000000000000000000000000000000000000000000000000", SourceRemote, "ghcr.io/acme/app", ""},
		{"docker source parses like remote", "myimage:dev", SourceDocker, "index.docker.io/library/myimage", "dev"},
		{"tarball path is no identity", "build/image.tar", SourceTarball, "", ""},
		{"unparseable reference is no identity", "UPPER CASE not a ref", SourceRemote, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, version := seriesIdentity(tc.target, tc.src)
			if id != tc.wantID || version != tc.wantVersion {
				t.Errorf("seriesIdentity(%q, %q) = (%q, %q), want (%q, %q)",
					tc.target, tc.src, id, version, tc.wantID, tc.wantVersion)
			}
		})
	}
}

func TestPlan_EmptyRefErrors(t *testing.T) {
	if _, err := New().Plan(context.Background(), "", mode.Overrides{}); err == nil {
		t.Fatal("want error for empty image reference")
	}
}
