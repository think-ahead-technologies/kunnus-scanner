// ABOUTME: Tests for packages.lock.json dependency-edge extraction.
// ABOUTME: Each package's dependencies map resolves against the same target framework's entries.
package ecosystem

import "testing"

func TestParseNuGetLockGraph(t *testing.T) {
	// Each package entry's "dependencies" map names packages and their minimum
	// versions; the edge target is the version the same framework block
	// *resolved*, not the requested minimum. NuGet ids are case-insensitive, so
	// a differently-cased reference still resolves. A reference the lock does
	// not pin is dropped.
	path := fixtureReader(t, "packages.lock.json", `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Serilog.Sinks.Console": {
        "type": "Direct",
        "resolved": "6.0.0",
        "dependencies": {
          "serilog": "4.0.0",
          "Missing.Package": "1.0.0"
        }
      },
      "Serilog": {
        "type": "Transitive",
        "resolved": "4.1.0"
      }
    },
    "net9.0": {
      "Serilog": {
        "type": "Direct",
        "resolved": "4.2.0"
      }
    }
  }
}`)
	got, err := parseNuGetLockGraph(path)
	if err != nil {
		t.Fatalf("parseNuGetLockGraph: %v", err)
	}
	want := graphWant{
		// Resolved 4.1.0 wins over the requested 4.0.0, and the case-insensitive
		// id match binds "serilog" to the "Serilog" entry.
		"pkg:nuget/Serilog.Sinks.Console@6.0.0": {"pkg:nuget/Serilog@4.1.0"},
	}
	assertGraph(t, got, want)
}

func TestParseNuGetLockGraph_ResolutionIsPerFramework(t *testing.T) {
	// The same package can resolve to different versions per target framework.
	// An edge must bind within its own framework block, never across.
	path := fixtureReader(t, "packages.lock.json", `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "App.Lib": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"Dep": "1.0.0"}},
      "Dep": {"type": "Transitive", "resolved": "1.5.0"}
    },
    "net9.0": {
      "App.Lib": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"Dep": "1.0.0"}},
      "Dep": {"type": "Transitive", "resolved": "2.0.0"}
    }
  }
}`)
	got, err := parseNuGetLockGraph(path)
	if err != nil {
		t.Fatalf("parseNuGetLockGraph: %v", err)
	}
	// One source purl, two framework-specific targets — both real.
	want := graphWant{
		"pkg:nuget/App.Lib@1.0.0": {"pkg:nuget/Dep@1.5.0", "pkg:nuget/Dep@2.0.0"},
	}
	assertGraph(t, got, want)
}
