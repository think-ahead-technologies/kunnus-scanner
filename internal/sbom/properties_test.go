// ABOUTME: Tests bsi-property derivation from extractor metadata.
// ABOUTME: Per BSI TR-03183-2 v2.1: filename / executable / archive / structured.
package sbom

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestBSIProperties_FromGoBinary(t *testing.T) {
	pkg := &extractor.Package{
		Name:      "github.com/foo/bar",
		Version:   "1.0.0",
		Locations: []string{"bin/kunnus"},
		Plugins:   []string{"go/binary"},
	}
	got := bsiProperties(pkg)
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
	got := bsiProperties(pkg)
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
	got := bsiProperties(pkg)
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
	got := bsiProperties(pkg)
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
	got := bsiProperties(pkg)
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
		got := bsiProperties(pkg)
		for _, key := range []string{"bsi:component:executable", "bsi:component:archive", "bsi:component:structured"} {
			v := got[key]
			if v != "true" && v != "false" {
				t.Errorf("plugin %q: property %q = %q, want boolean string", name, key, v)
			}
		}
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
