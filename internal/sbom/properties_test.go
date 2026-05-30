// ABOUTME: Tests bsi-property derivation from extractor metadata.
// ABOUTME: Four properties: filename, executable, archive, structured.
package sbom

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/opencontainers/go-digest"
)

func TestBSIProperties_FromGoBinary(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "github.com/foo/bar",
		Version:   "1.0.0",
		Locations: []string{"bin/kunnus"},
		Plugins:   []string{"go/binary"},
	}
	got := bsiProperties([]*extractor.Package{pkg})
	wantContain := map[string]string{
		"bsi:component:filename":   "bin/kunnus",
		"bsi:component:executable": "true",
		"bsi:component:archive":    "false",
		"bsi:component:structured": "false",
	}
	for k, v := range wantContain {
		if got[k] != v {
			t.Errorf("property %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestBSIProperties_FromLockfile(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "lodash",
		Version:   "4.17.21",
		Locations: []string{"frontend/package-lock.json"},
		Plugins:   []string{"javascript/packagelockjson"},
	}
	got := bsiProperties([]*extractor.Package{pkg})
	if got["bsi:component:filename"] != "frontend/package-lock.json" {
		t.Errorf("filename = %q, want frontend/package-lock.json", got["bsi:component:filename"])
	}
	if got["bsi:component:executable"] != "false" {
		t.Errorf("executable = %q, want false for lockfile-sourced", got["bsi:component:executable"])
	}
	if got["bsi:component:structured"] != "true" {
		t.Errorf("structured = %q, want true for lockfile-sourced", got["bsi:component:structured"])
	}
}

func TestBSIProperties_FromJavaArchive(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "org.example/some-jar",
		Version:   "2.0",
		Locations: []string{"libs/some-jar-2.0.jar"},
		Plugins:   []string{"java/archive"},
	}
	got := bsiProperties([]*extractor.Package{pkg})
	if got["bsi:component:archive"] != "true" {
		t.Errorf("archive = %q, want true for java/archive", got["bsi:component:archive"])
	}
}

func TestBSIProperties_FromOSPackage(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "openssl",
		Version:   "3.0.11",
		Locations: []string{"var/lib/dpkg/status"},
		Plugins:   []string{"os/dpkg"},
	}
	got := bsiProperties([]*extractor.Package{pkg})
	if got["bsi:component:structured"] != "true" {
		t.Errorf("structured = %q, want true for OS package db", got["bsi:component:structured"])
	}
	if got["bsi:component:executable"] != "false" {
		t.Errorf("executable = %q, want false for OS metadata entry", got["bsi:component:executable"])
	}
}

func TestBSIProperties_NoLocations(t *testing.T) {
	pkg := &extractor.Package{
		Name:    "x",
		Version: "1",
		Plugins: []string{"go/gomod"},
	}
	got := bsiProperties([]*extractor.Package{pkg})
	// No filename when no location is known.
	if _, ok := got["bsi:component:filename"]; ok {
		t.Errorf("filename should be omitted when Locations is empty, got %q", got["bsi:component:filename"])
	}
	// The other three properties must still be set — BSI requires them to be present.
	for _, k := range []string{"bsi:component:executable", "bsi:component:archive", "bsi:component:structured"} {
		if got[k] == "" {
			t.Errorf("property %q must always be set, got empty", k)
		}
	}
}

func TestBSIProperties_KnownExtractorTags(t *testing.T) {
	// Spot-check that the executable/archive/structured tags exist for every
	// scalibr plugin name we advertise in the mode packages. Catches drift
	// between mode/repo/plugins.go and the BSI-property classifier.
	for _, name := range knownPluginNames() {
		pkg := &extractor.Package{Plugins: []string{name}}
		got := bsiProperties([]*extractor.Package{pkg})
		for _, key := range []string{"bsi:component:executable", "bsi:component:archive", "bsi:component:structured"} {
			v := got[key]
			if v != "true" && v != "false" {
				t.Errorf("plugin %q: property %q = %q, want boolean string", name, key, v)
			}
		}
	}
}

func TestLayerProperties_NoMetadata(t *testing.T) {
	// Repo and OS scans carry no layer dimension — every package has nil
	// LayerMetadata, so the layer properties must be nil (a no-op for the applier).
	pkgs := []*extractor.Package{{Name: "x", Version: "1"}}
	if got := layerProperties(pkgs); got != nil {
		t.Errorf("layerProperties with no layer metadata = %v, want nil", got)
	}
}

func TestLayerProperties_SingleLayer(t *testing.T) {
	// A package in exactly one layer keeps the original singular-key output and
	// emits no plural set keys — the common case stays unchanged.
	pkgs := []*extractor.Package{{
		Name: "musl", Version: "1.2.4",
		LayerMetadata: &extractor.LayerMetadata{
			Index: 2, DiffID: digest.Digest("sha256:abc"), Command: "RUN apk add musl", BaseImageIndex: 1,
		},
	}}
	got := layerProperties(pkgs)
	want := map[string]string{
		"kunnus:layer:index":         "2",
		"kunnus:layer:diffid":        "sha256:abc",
		"kunnus:layer:command":       "RUN apk add musl",
		"kunnus:layer:in_base_image": "true",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("property %q = %q, want %q", k, got[k], v)
		}
	}
	for _, k := range []string{"kunnus:layer:indices", "kunnus:layer:diffids"} {
		if _, ok := got[k]; ok {
			t.Errorf("single-layer package should not emit %q, got %q", k, got[k])
		}
	}
}

func TestLayerProperties_MultiLayerAggregates(t *testing.T) {
	// Same PURL present in three layers, supplied out of index order. The
	// singular keys must describe the introducing (lowest-index) layer; the
	// plural keys must list every distinct layer, sorted.
	mk := func(idx int, diffID string) *extractor.Package {
		return &extractor.Package{
			Name: "musl", Version: "1.2.4",
			LayerMetadata: &extractor.LayerMetadata{Index: idx, DiffID: digest.Digest(diffID)},
		}
	}
	pkgs := []*extractor.Package{mk(5, "sha256:eee"), mk(1, "sha256:aaa"), mk(5, "sha256:eee")}

	got := layerProperties(pkgs)
	if got["kunnus:layer:index"] != "1" {
		t.Errorf("introducing index = %q, want 1 (lowest)", got["kunnus:layer:index"])
	}
	if got["kunnus:layer:diffid"] != "sha256:aaa" {
		t.Errorf("introducing diffid = %q, want sha256:aaa", got["kunnus:layer:diffid"])
	}
	if got["kunnus:layer:indices"] != "1,5" {
		t.Errorf("indices = %q, want 1,5 (distinct, sorted)", got["kunnus:layer:indices"])
	}
	if got["kunnus:layer:diffids"] != "sha256:aaa,sha256:eee" {
		t.Errorf("diffids = %q, want sha256:aaa,sha256:eee (distinct, index order)", got["kunnus:layer:diffids"])
	}
}

func TestBSIProperties_AggregatesAcrossPackages(t *testing.T) {
	// Same PURL found by two extractors — one archive-sourced, one structured.
	// The flags must OR across both, and the filename takes the first known
	// location.
	pkgs := []*extractor.Package{
		{Locations: []string{"libs/foo.jar"}, Plugins: []string{"java/archive"}},
		{Locations: []string{"pom.xml"}, Plugins: []string{"java/pomxml"}},
	}
	got := bsiProperties(pkgs)
	if got["bsi:component:archive"] != "true" {
		t.Errorf("archive = %q, want true (one source is an archive)", got["bsi:component:archive"])
	}
	if got["bsi:component:structured"] != "true" {
		t.Errorf("structured = %q, want true (one source is structured)", got["bsi:component:structured"])
	}
	if got["bsi:component:filename"] != "libs/foo.jar" {
		t.Errorf("filename = %q, want libs/foo.jar (first known location)", got["bsi:component:filename"])
	}
}

func knownPluginNames() []string {
	names := []string{
		"go/gomod", "go/binary",
		"javascript/packagejson", "javascript/packagelockjson", "javascript/pnpmlock", "javascript/yarnlock",
		"rust/cargoauditable", "rust/cargolock",
		"dotnet/csproj", "dotnet/depsjson", "dotnet/nugetcpm", "dotnet/packagesconfig", "dotnet/packageslockjson", "dotnet/pe",
		"java/pomxml", "java/archive", "java/gradlelockfile",
		"python/poetrylock", "python/requirements", "python/wheelegg",
		"php/composerlock", "ruby/gemfilelock",
		"swift/packageresolved", "swift/podfilelock",
		"haskell/cabal", "haskell/stacklock", "r/renvlock",
		"os/dpkg", "os/rpm", "os/apk", "os/pacman", "os/portage", "os/nix", "os/flatpak", "os/snap", "os/cos",
		"os/homebrew", "os/macports", "os/macapps",
		"os/chocolatey", "os/winget",
		"windows/ospackages", "windows/regosversion", "windows/regpatchlevel", "windows/dismpatch",
	}
	slices.Sort(names)
	return slices.Compact(names)
}
