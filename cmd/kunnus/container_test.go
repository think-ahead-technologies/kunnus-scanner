// ABOUTME: End-to-end test for `kunnus sbom container` over a synthetic image tarball built in-memory.
// ABOUTME: Real binary, real CycloneDX output — asserts cross-ecosystem extraction and per-layer attribution.
package main_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestCLI_SBOM_Container(t *testing.T) {
	// Build a two-layer image: an OS layer (alpine apk db) and an app layer
	// (npm lockfile), so the run exercises cross-ecosystem extraction and the
	// per-layer attribution that container scanning adds.
	osLayer := layerFromFiles(t, map[string]string{
		"etc/os-release":       "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.4\n",
		"lib/apk/db/installed": "C:Q1eVpkksZ6wkkjssudkkaXmIYCBN2A=\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n",
	})
	appLayer := layerFromFiles(t, map[string]string{
		"app/package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,` +
			`"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0"}}}`,
	})
	tarPath := writeImageTarball(t, osLayer, appLayer)

	outPath := filepath.Join(t.TempDir(), "sbom.json")
	stdout, stderr, err := runKunnus(t,
		"sbom", "container", "--source", "tarball", "--output", outPath, tarPath)
	if err != nil {
		t.Fatalf("sbom container failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Component struct {
				Type string `json:"type"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			PURL       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}

	if doc.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", doc.BOMFormat)
	}
	if doc.Metadata.Component.Type != "container" {
		t.Errorf("root component type = %q, want container", doc.Metadata.Component.Type)
	}

	// layerIndexByPURLSubstr maps each expected component to the layer index its
	// kunnus:layer:index property reports.
	want := map[string]string{
		"pkg:apk/alpine/musl@1.2.4-r2": "0", // OS layer
		"pkg:npm/left-pad@1.3.0":       "1", // app layer
	}
	for substr, wantIdx := range want {
		idx, found := layerIndexFor(doc.Components, substr)
		if !found {
			t.Errorf("component %q missing from container SBOM", substr)
			continue
		}
		if idx != wantIdx {
			t.Errorf("component %q kunnus:layer:index = %q, want %q", substr, idx, wantIdx)
		}
	}
}

// layerIndexFor returns the kunnus:layer:index property value of the first
// component whose purl contains substr.
func layerIndexFor(components []struct {
	PURL       string `json:"purl"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}, substr string) (string, bool) {
	for _, c := range components {
		if !contains(c.PURL, substr) {
			continue
		}
		for _, p := range c.Properties {
			if p.Name == "kunnus:layer:index" {
				return p.Value, true
			}
		}
		return "", true // component present but no layer property
	}
	return "", false
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

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
	sort.Strings(dirList)
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

// writeImageTarball assembles an image from the given layers (earliest first)
// and writes it to a docker-save tarball, returning its path.
func writeImageTarball(t *testing.T, layers ...v1.Layer) string {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatalf("AppendLayers: %v", err)
	}
	ref, err := name.ParseReference("kunnus-fixture:latest")
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(tarPath, ref, img); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	return tarPath
}
