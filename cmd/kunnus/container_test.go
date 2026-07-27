// ABOUTME: End-to-end test for `kunnus sbom container` over a synthetic image tarball built in-memory.
// ABOUTME: Real binary, real CycloneDX output — asserts cross-ecosystem extraction and per-layer attribution.
package main_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
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
		"etc/os-release": "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.4\n",
		// C is a real Q1 checksum (Q1 + base64 of a 20-byte SHA-1); the apk
		// checksum recovery decodes it to muslSHA1 and attaches it to the
		// component.
		"lib/apk/db/installed": "C:Q1jKMx2ZpwgZjUgK4EZTBYzhfDsQs=\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n",
	})
	// Installed dependencies as their own manifests: an npm package.json and a
	// Python dist-info METADATA. Container scans use installed-state extractors,
	// not lockfiles, and the manifest-license enricher recovers the licence each
	// manifest declares but scalibr drops.
	// A Java JAR carries its identity (pom.properties) and licence (pom.xml)
	// inside the zip; the enricher cracks it open offline.
	coollib := jarBytes(t, map[string]string{
		"META-INF/maven/com.example/coollib/pom.properties": "groupId=com.example\nartifactId=coollib\nversion=1.0\n",
		"META-INF/maven/com.example/coollib/pom.xml": `<project xmlns="http://maven.apache.org/POM/4.0.0">` +
			`<licenses><license><name>Apache License, Version 2.0</name></license></licenses></project>`,
	})
	appLayer := layerFromFiles(t, map[string]string{
		"app/node_modules/left-pad/package.json":             `{"name":"left-pad","version":"1.3.0","license":"WTFPL"}`,
		"app/site-packages/coolpkg-2.5.0.dist-info/METADATA": "Metadata-Version: 2.4\nName: coolpkg\nVersion: 2.5.0\nLicense-Expression: BSD-3-Clause\n",
		"app/lib/coollib-1.0.jar":                            coollib,
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
		Components []cdxComponent `json:"components"`
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
	// Container scans analyse a built image, so the generation context is post-build.
	if !strings.Contains(string(data), `"phase": "post-build"`) {
		t.Error("SBOM missing post-build lifecycle phase (metadata.lifecycles)")
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

	// The apk pull-checksum scalibr drops is recovered post-scan (container
	// mode's Plan.PostScanHashes) and lands as a SHA-1 hash on the apk component
	// — proving the integrity-digest path end to end through the real binary.
	const muslSHA1 = "8ca331d99a708198d480ae04653058ce17c3b10b"
	muslHashed := false
	for _, c := range doc.Components {
		if !contains(c.PURL, "pkg:apk/alpine/musl@1.2.4-r2") {
			continue
		}
		for _, h := range c.Hashes {
			if h.Alg == "SHA-1" && h.Content == muslSHA1 {
				muslHashed = true
			}
		}
	}
	if !muslHashed {
		t.Errorf("musl apk component missing recovered SHA-1 %s in container SBOM", muslSHA1)
	}

	// The manifest-license enricher recovers left-pad's licence from its
	// installed package.json — a licence scalibr's packagejson extractor reads
	// but drops. This is the offline per-installed-package manifest path.
	var licDoc struct {
		Components []struct {
			PURL     string `json:"purl"`
			Licenses []struct {
				License struct {
					ID string `json:"id"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &licDoc); err != nil {
		t.Fatalf("re-parse sbom for licences: %v", err)
	}
	// licenceFor returns the first licence id of the component whose purl contains
	// substr (scalibr may append purl qualifiers like "?source=...").
	licenceFor := func(substr string) string {
		for _, c := range licDoc.Components {
			if !contains(c.PURL, substr) {
				continue
			}
			for _, l := range c.Licenses {
				if l.License.ID != "" {
					return l.License.ID
				}
			}
		}
		return ""
	}
	if got := licenceFor("pkg:npm/left-pad@1.3.0"); got != "WTFPL" {
		t.Errorf("left-pad licence = %q, want WTFPL (recovered from package.json)", got)
	}
	if got := licenceFor("pkg:pypi/coolpkg@2.5.0"); got != "BSD-3-Clause" {
		t.Errorf("coolpkg licence = %q, want BSD-3-Clause (recovered from dist-info METADATA)", got)
	}
	if got := licenceFor("pkg:maven/com.example/coollib@1.0"); got != "Apache-2.0" {
		t.Errorf("coollib licence = %q, want Apache-2.0 (recovered from the JAR's embedded pom.xml)", got)
	}

	// The image's operating system is emitted as its own component, named by the
	// distro ID with VERSION_ID as the version (from the layer's os-release).
	var osDoc struct {
		Components []struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &osDoc); err != nil {
		t.Fatalf("re-parse sbom: %v", err)
	}
	foundOS := false
	for _, c := range osDoc.Components {
		if c.Type != "operating-system" {
			continue
		}
		foundOS = true
		if c.Name != "alpine" || c.Version != "3.18.4" {
			t.Errorf("operating-system component = %q@%q, want alpine@3.18.4", c.Name, c.Version)
		}
	}
	if !foundOS {
		t.Error("expected an operating-system component for the scanned image")
	}
}

func TestCLI_SBOM_Container_Chiselled(t *testing.T) {
	// A chiselled Ubuntu image has no dpkg status file: its package record is
	// the chisel manifest. Build a single-layer image from the real
	// chiselled-noble fixture (manifest + os-release + openssl's DEP-5
	// copyright) and assert the chisel extractor, the manifest sha256 digest
	// recovery (container mode's PostScanHashes) and the debiancopyright
	// enricher all work through the real binary.
	fixture := filepath.Join(moduleRoot(t), "testdata", "osfamilies", "chisel")
	manifest, err := os.ReadFile(filepath.Join(fixture, "var", "lib", "chisel", "manifest.wall"))
	if err != nil {
		t.Fatalf("read chisel manifest fixture: %v", err)
	}
	osRelease, err := os.ReadFile(filepath.Join(fixture, "etc", "os-release"))
	if err != nil {
		t.Fatalf("read os-release fixture: %v", err)
	}
	copyright, err := os.ReadFile(filepath.Join(fixture, "usr", "share", "doc", "openssl", "copyright"))
	if err != nil {
		t.Fatalf("read copyright fixture: %v", err)
	}
	layer := layerFromFiles(t, map[string]string{
		"etc/os-release":                  string(osRelease),
		"var/lib/chisel/manifest.wall":    string(manifest),
		"usr/share/doc/openssl/copyright": string(copyright),
	})
	tarPath := writeImageTarball(t, layer)

	outPath := filepath.Join(t.TempDir(), "sbom.json")
	stdout, stderr, err := runKunnus(t,
		"sbom", "container", "--source", "tarball", "--output", outPath, tarPath)
	if err != nil {
		t.Fatalf("sbom container failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read SBOM: %v", err)
	}
	var doc struct {
		Components []struct {
			PURL   string `json:"purl"`
			Hashes []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
			Licenses []struct {
				License struct {
					ID string `json:"id"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse SBOM: %v", err)
	}

	// Every package in the fixture manifest must surface as a deb component.
	for _, p := range []string{
		"pkg:deb/ubuntu/base-files@13ubuntu10.2?arch=amd64&distro=noble",
		"pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4?arch=amd64&distro=noble",
		"pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.5?arch=amd64&distro=noble",
		"pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?arch=amd64&distro=noble",
	} {
		found := false
		for _, c := range doc.Components {
			if c.PURL == p {
				found = true
			}
		}
		if !found {
			t.Errorf("expected purl %q missing from chiselled-container SBOM", p)
		}
	}

	// The manifest's per-package sha256 is recovered post-scan and attached to
	// the component; the DEP-5 copyright yields the licence.
	const opensslSHA256 = "00f9b292ff5636d49832e493789ec91e21cfd4e98ccc9fd23497e92a2cc9c76a"
	hashed, licensed := false, false
	for _, c := range doc.Components {
		if !contains(c.PURL, "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5") {
			continue
		}
		for _, h := range c.Hashes {
			if h.Alg == "SHA-256" && h.Content == opensslSHA256 {
				hashed = true
			}
		}
		for _, l := range c.Licenses {
			if l.License.ID == "Apache-2.0" {
				licensed = true
			}
		}
	}
	if !hashed {
		t.Errorf("openssl component missing recovered SHA-256 %s in chiselled-container SBOM", opensslSHA256)
	}
	if !licensed {
		t.Errorf("openssl component missing Apache-2.0 licence from its DEP-5 copyright file")
	}
}

func TestCLI_SBOM_Container_EmbeddedSBOM(t *testing.T) {
	// Some images ship their own SBOM (e.g. Talos at /usr/share/spdx/*.spdx.json).
	// The embedded-SBOM extractor must ingest it, so vendor-declared components
	// that leave no other on-disk trace still appear. embedded-only-lib exists
	// only in the embedded CycloneDX document, nowhere else in the image.
	layer := layerFromFiles(t, map[string]string{
		"etc/os-release": "ID=wolfi\nVERSION_ID=\"20230201\"\n",
		"usr/share/sbom/app.cdx.json": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` +
			`{"type":"library","name":"embedded-only-lib","version":"9.9.9",` +
			`"purl":"pkg:golang/example.com/embedded-only-lib@9.9.9"}]}`,
	})
	tarPath := writeImageTarball(t, layer)

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
		Components []struct {
			Name string `json:"name"`
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("sbom is not valid JSON: %v", err)
	}
	found := false
	for _, c := range doc.Components {
		if c.Name == "embedded-only-lib" {
			found = true
		}
	}
	if !found {
		t.Error("component from the image's embedded SBOM (embedded-only-lib) is missing — SBOM extractor not ingesting it")
	}
}

// cdxComponent is the slice of a CycloneDX component the container e2e test
// inspects: purl, the kunnus property bag, and the hashes injected for it.
type cdxComponent struct {
	PURL       string `json:"purl"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
	Hashes []struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	} `json:"hashes"`
}

// layerIndexFor returns the kunnus:layer:index property value of the first
// component whose purl contains substr.
func layerIndexFor(components []cdxComponent, substr string) (string, bool) {
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

// jarBytes builds an in-memory .jar (a zip) from a path→content map and returns
// its bytes as a string, suitable as file content for layerFromFiles.
func jarBytes(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("jar create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("jar write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("jar close: %v", err)
	}
	return buf.String()
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

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	})
	if err != nil {
		t.Fatalf("LayerFromOpener: %v", err)
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
