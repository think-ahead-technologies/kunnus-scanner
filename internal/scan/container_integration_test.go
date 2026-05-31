// ABOUTME: Integration test for RunContainer over a synthetic multi-layer image built in-memory.
// ABOUTME: Real scalibr ScanContainer — asserts both extraction and per-package layer attribution.
package scan_test

import (
	"archive/tar"
	"bytes"
	"context"
	"path"
	"sort"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibr "github.com/google/osv-scalibr"
	scalibrimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/think-ahead/kunnus-scanner/internal/ecosystem"
	"github.com/think-ahead/kunnus-scanner/internal/osfamily"
	"github.com/think-ahead/kunnus-scanner/internal/scan"
)

// TestRunContainer_MultiLayer builds a two-layer image — an OS layer (alpine apk
// db) and an app layer (npm lockfile) — scans it, and asserts both packages are
// found with the correct per-layer attribution. This exercises the full
// RunContainer path including ScanContainer's layer tracing.
func TestRunContainer_MultiLayer(t *testing.T) {
	osLayer := layerFromFiles(t, map[string]string{
		"etc/os-release": "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.4\n",
		"lib/apk/db/installed": "C:Q1eVpkksZ6wkkjssudkkaXmIYCBN2A=\nP:musl\n" +
			"V:1.2.4-r2\nA:x86_64\no:musl\n",
	})
	// An installed npm dependency: a package.json under node_modules, not a
	// lockfile. Container scans use installed-state extractors only.
	appLayer := layerFromFiles(t, map[string]string{
		"app/node_modules/left-pad/package.json": `{"name":"left-pad","version":"1.3.0"}`,
	})

	img := buildImage(t, osLayer, appLayer)

	names := dedup(append(ecosystem.AllInstalledPlugins(), osfamily.AllLinuxPlugins()...))
	plugins, err := pl.FromNames(names, nil)
	if err != nil {
		t.Fatalf("FromNames: %v", err)
	}
	caps := &plugin.Capabilities{OS: plugin.OSLinux}
	cfg := &scalibr.ScanConfig{
		Plugins:      plugin.FilterByCapabilities(plugins, caps),
		Capabilities: caps,
	}

	res, err := scan.RunContainer(context.Background(), img, cfg)
	if err != nil {
		t.Fatalf("RunContainer: %v", err)
	}

	musl := findByPURL(t, res, "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.18.4&origin=musl")
	leftPad := findByPURL(t, res, "pkg:npm/left-pad@1.3.0")

	// Layer attribution: the OS package came from layer 0, the app package from
	// layer 1. This is the value ScanContainer adds over a squashed scan.
	if musl.LayerMetadata == nil || leftPad.LayerMetadata == nil {
		t.Fatalf("expected LayerMetadata on both packages; musl=%v leftPad=%v",
			musl.LayerMetadata, leftPad.LayerMetadata)
	}
	if musl.LayerMetadata.Index != 0 {
		t.Errorf("musl layer index = %d, want 0", musl.LayerMetadata.Index)
	}
	if leftPad.LayerMetadata.Index != 1 {
		t.Errorf("left-pad layer index = %d, want 1", leftPad.LayerMetadata.Index)
	}
}

// findByPURL matches on the purl path+version, ignoring qualifiers (the
// packagejson extractor appends a source=UNKNOWN qualifier we don't care about).
func findByPURL(t *testing.T, res *scan.Result, want string) *extractor.Package {
	t.Helper()
	base := func(s string) string { return strings.SplitN(s, "?", 2)[0] }
	for _, p := range res.Inventory.Packages {
		if u := p.PURL(); u != nil && base(u.String()) == base(want) {
			return p
		}
	}
	t.Fatalf("package %q not found; got:\n  %s", want, strings.Join(sortedKeys(inventoryPURLs(res)), "\n  "))
	return nil
}

// layerFromFiles builds a single image layer from a path→content map, emitting
// explicit parent-directory entries so the scalibr layer FS resolves each file.
func layerFromFiles(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	dirs := make(map[string]bool)
	for p := range files {
		for d := path.Dir(p); d != "." && d != "/"; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	dirList := make([]string, 0, len(dirs))
	for d := range dirs {
		dirList = append(dirList, d)
	}
	sort.Strings(dirList) // parents sort before children
	for _, d := range dirList {
		if err := tw.WriteHeader(&tar.Header{Name: d + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatalf("tar dir %s: %v", d, err)
		}
	}
	for p, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: p, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
			t.Fatalf("tar header %s: %v", p, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", p, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}

	layer, err := tarball.LayerFromReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("LayerFromReader: %v", err)
	}
	return layer
}

// buildImage assembles a scalibr image.Image from the given layers (earliest
// first) via an empty base.
func buildImage(t *testing.T, layers ...v1.Layer) *scalibrimage.Image {
	t.Helper()
	v1img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	img, err := scalibrimage.FromV1Image(v1img, &scalibrimage.Config{
		MaxFileBytes:    1 << 30,
		MaxSymlinkDepth: 5,
	})
	if err != nil {
		t.Fatalf("FromV1Image: %v", err)
	}
	return img
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
