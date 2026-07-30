// ABOUTME: Tests for package-lock.json dependency-edge extraction (lockfileVersion 2/3).
// ABOUTME: Covers node_modules walk-up resolution, scoped-name purl escaping, and the skipped root entry.
package ecosystem

import (
	"io"
	"reflect"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/graph"
)

func TestParseNpmLockGraph(t *testing.T) {
	// lockfileVersion 3: the "packages" map is keyed by install path. A
	// dependency resolves by node's walk-up rule — the nearest
	// <dir>/node_modules/<name> wins — so the nested "b" below binds to the
	// nested copy, not the hoisted one. The "" entry is the scanned project
	// itself, not a component, so it is never an edge source. Scoped names key
	// the %40-escaped purl form the SBOM components carry.
	path := fixtureReader(t, "package-lock.json", `{
  "name": "app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "app",
      "version": "1.0.0",
      "dependencies": {"@babel/core": "^7.0.0"}
    },
    "node_modules/@babel/core": {
      "version": "7.24.0",
      "dependencies": {"left-pad": "^1.3.0", "b": "^2.0.0"},
      "optionalDependencies": {"fsevents": "^2.3.0"}
    },
    "node_modules/@babel/core/node_modules/b": {
      "version": "2.9.9"
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "dependencies": {"b": "^1.0.0", "not-installed": "^1.0.0"}
    },
    "node_modules/b": {"version": "1.0.0"},
    "node_modules/fsevents": {"version": "2.3.3"}
  }
}`)
	got, err := parseNpmLockGraph(path)
	if err != nil {
		t.Fatalf("parseNpmLockGraph: %v", err)
	}
	// Dependency names are walked in sorted order within each map, so "b"
	// precedes "left-pad"; optionalDependencies follow dependencies.
	want := graphWant{
		"pkg:npm/%40babel/core@7.24.0": {
			"pkg:npm/b@2.9.9", // nested copy wins over the hoisted 1.0.0
			"pkg:npm/left-pad@1.3.0",
			"pkg:npm/fsevents@2.3.3",
		},
		// Hoisted resolution: left-pad has no nested node_modules, so "b"
		// resolves to the root-level copy. "not-installed" appears in no
		// packages entry and is dropped.
		"pkg:npm/left-pad@1.3.0": {"pkg:npm/b@1.0.0"},
	}
	assertGraph(t, got, want)
}

func TestParseNpmLockGraph_V1LockfileYieldsNothing(t *testing.T) {
	// lockfileVersion 1 (npm 6) has no "packages" map — only a nested
	// "dependencies" tree with "requires" ranges. It is not parsed: resolving
	// that shape needs the nesting semantics the v2+ path map states outright,
	// and npm has written v2+ since 2020. No edges beats wrong edges.
	path := fixtureReader(t, "package-lock.json", `{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "left-pad": {"version": "1.3.0", "requires": {"b": "^1.0.0"}},
    "b": {"version": "1.0.0"}
  }
}`)
	got, err := parseNpmLockGraph(path)
	if err != nil {
		t.Fatalf("parseNpmLockGraph: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("graph = %v, want empty for a v1 lockfile", got)
	}
}

func TestGraphParsersAreDeterministic(t *testing.T) {
	// Every graph parser reads at least one Go map, whose iteration order is
	// randomised per run. Parsing one input twice must still yield identical
	// edge slices: an SBOM's dependsOn lists have to be byte-identical across
	// runs of the same scan, or successive documents in a serial-number series
	// would differ for no real reason.
	cases := []struct {
		name     string
		filename string
		content  string
		parse    func(io.Reader) (graph.Map, error)
	}{
		{
			name:     "npm",
			filename: "package-lock.json",
			content: `{"lockfileVersion": 3, "packages": {
				"": {"version": "1.0.0", "dependencies": {"a": "^1.0.0"}},
				"node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1", "c": "^1", "d": "^1", "e": "^1"},
					"optionalDependencies": {"f": "^1"}},
				"node_modules/b": {"version": "1.1.0"},
				"node_modules/c": {"version": "1.2.0"},
				"node_modules/d": {"version": "1.3.0"},
				"node_modules/e": {"version": "1.4.0"},
				"node_modules/f": {"version": "1.5.0"}
			}}`,
			parse: parseNpmLockGraph,
		},
		{
			name:     "composer",
			filename: "composer.lock",
			content: `{"packages": [
				{"name": "v/a", "version": "1.0.0", "require": {"v/b": "^1", "v/c": "^1", "v/d": "^1", "v/e": "^1"}},
				{"name": "v/b", "version": "1.1.0"},
				{"name": "v/c", "version": "1.2.0"},
				{"name": "v/d", "version": "1.3.0"},
				{"name": "v/e", "version": "1.4.0"}
			]}`,
			parse: parseComposerLockGraph,
		},
		{
			name:     "nuget",
			filename: "packages.lock.json",
			content: `{"version": 1, "dependencies": {
				"net8.0": {
					"A": {"resolved": "1.0.0", "dependencies": {"B": "1.0.0", "C": "1.0.0", "D": "1.0.0"}},
					"B": {"resolved": "1.1.0"}, "C": {"resolved": "1.2.0"}, "D": {"resolved": "1.3.0"}
				},
				"net9.0": {
					"A": {"resolved": "1.0.0", "dependencies": {"B": "1.0.0"}},
					"B": {"resolved": "2.0.0"}
				}
			}}`,
			parse: parseNuGetLockGraph,
		},
		{
			name:     "renv",
			filename: "renv.lock",
			content: `{"Packages": {
				"a": {"Package": "a", "Version": "1.0.0", "Requirements": ["b", "c", "d"]},
				"b": {"Package": "b", "Version": "1.1.0"},
				"c": {"Package": "c", "Version": "1.2.0"},
				"d": {"Package": "d", "Version": "1.3.0"}
			}}`,
			parse: parseRenvLockGraph,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, err := tc.parse(fixtureReader(t, tc.filename, tc.content))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(first) == 0 {
				t.Fatal("parser produced no edges; the case proves nothing")
			}
			// Several rounds: one repeat can coincidentally match under map
			// randomisation, ten in a row will not.
			for i := 0; i < 10; i++ {
				again, err := tc.parse(fixtureReader(t, tc.filename, tc.content))
				if err != nil {
					t.Fatalf("parse round %d: %v", i, err)
				}
				if !reflect.DeepEqual(first, again) {
					t.Fatalf("round %d differs:\nfirst = %v\nagain = %v", i, first, again)
				}
			}
		})
	}
}
