// ABOUTME: Tests for renv.lock dependency-edge extraction.
// ABOUTME: Each package's Requirements array names packages; base R and unpinned names drop out.
package ecosystem

import "testing"

func TestParseRenvLockGraph(t *testing.T) {
	// renv records each package's Requirements as bare package names. They
	// resolve against the lock's own Packages map, so base/recommended R
	// packages that renv does not pin ("R", "methods" when absent) drop out
	// naturally.
	path := fixtureReader(t, "renv.lock", `{
  "R": {"Version": "4.4.1"},
  "Packages": {
    "jsonlite": {
      "Package": "jsonlite",
      "Version": "1.8.7",
      "Requirements": ["methods", "R"]
    },
    "httr": {
      "Package": "httr",
      "Version": "1.4.7",
      "Requirements": ["curl", "jsonlite", "mime"]
    },
    "curl": {"Package": "curl", "Version": "5.2.1"},
    "mime": {"Package": "mime", "Version": "0.12"}
  }
}`)
	got, err := parseRenvLockGraph(path)
	if err != nil {
		t.Fatalf("parseRenvLockGraph: %v", err)
	}
	want := graphWant{
		"pkg:cran/httr@1.4.7": {
			"pkg:cran/curl@5.2.1",
			"pkg:cran/jsonlite@1.8.7",
			"pkg:cran/mime@0.12",
		},
	}
	assertGraph(t, got, want)
}

func TestParseRenvLockGraph_UsesPackageFieldOverKey(t *testing.T) {
	// The authoritative name is the entry's own Package field (renv keys by it,
	// but the field is what the package calls itself). An entry missing a
	// version yields no purl and so no edges.
	path := fixtureReader(t, "renv.lock", `{
  "Packages": {
    "dplyr": {"Package": "dplyr", "Version": "1.1.4", "Requirements": ["rlang", "tibble"]},
    "rlang": {"Package": "rlang", "Version": "1.1.4"},
    "tibble": {"Package": "tibble"}
  }
}`)
	got, err := parseRenvLockGraph(path)
	if err != nil {
		t.Fatalf("parseRenvLockGraph: %v", err)
	}
	want := graphWant{
		"pkg:cran/dplyr@1.1.4": {"pkg:cran/rlang@1.1.4"},
	}
	assertGraph(t, got, want)
}
