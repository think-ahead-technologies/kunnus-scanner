// ABOUTME: Tests for the CMake extractor: real-fixture extraction over scalibr's walk.
// ABOUTME: The fixture tree mirrors CPM convention (CMakeLists.txt + cmake/deps.cmake) plus a vendored CPM.cmake decoy that must be rejected.
package cmake

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/stats"
)

// TestExtract runs the extractor through scalibr's real filesystem walk over a
// project pinning deps in CMakeLists.txt (FetchContent) and cmake/deps.cmake
// (CPM shorthand). The vendored cmake/CPM.cmake script is a decoy: even though
// it matches the .cmake suffix, FileRequired must reject it.
func TestExtract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "CMakeLists.txt"), `cmake_minimum_required(VERSION 3.24)
project(firmware CXX)
include(cmake/deps.cmake)
FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
)
FetchContent_MakeAvailable(fmt)
`)
	writeFile(t, filepath.Join(root, "proj", "cmake", "deps.cmake"),
		"CPMAddPackage(\"gh:nlohmann/json@3.11.3\")\n")
	// Decoy: the vendored package-manager script must not be parsed even if it
	// contained a literal invocation.
	writeFile(t, filepath.Join(root, "proj", "cmake", "CPM.cmake"),
		"CPMAddPackage(\"gh:decoy/should-not-appear@9.9.9\")\n")

	inv := run(t, root)

	type pkg struct{ purlType, version string }
	want := map[string]pkg{
		"fmtlib/fmt":    {"github", "10.2.1"},
		"nlohmann/json": {"github", "3.11.3"},
	}
	got := map[string]pkg{}
	for _, p := range inv.Packages {
		if p.Name == "decoy/should-not-appear" {
			t.Errorf("vendored CPM.cmake was parsed: %+v", p)
		}
		got[p.Name] = pkg{p.PURLType, p.Version}
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages %v, want %d", len(got), got, len(want))
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("package %q = %+v, want %+v", name, got[name], w)
		}
	}
}

func run(t *testing.T, root string) inventory.Inventory {
	t.Helper()
	inv, _, err := filesystem.Run(context.Background(), &filesystem.Config{
		Extractors: []filesystem.Extractor{New()},
		ScanRoots:  scalibrfs.RealFSScanRoots(root),
		Stats:      stats.NoopCollector{},
	})
	if err != nil {
		t.Fatalf("filesystem.Run: %v", err)
	}
	return inv
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}
