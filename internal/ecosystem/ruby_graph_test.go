// ABOUTME: Tests for Gemfile.lock dependency-edge extraction.
// ABOUTME: Specs are 4-space indented, their deps 6-space; deps resolve against the specs themselves.
package ecosystem

import (
	"reflect"
	"testing"
)

func TestParseGemfileLockGraph(t *testing.T) {
	// A real-shaped Gemfile.lock: GEM and PATH sections each carry a specs
	// block whose 4-space entries are gems and 6-space entries their
	// requirements. Requirement constraints are ignored — the locked version of
	// the named gem is the resolved target. A requirement naming a gem the lock
	// does not pin (bundler itself, a platform gem) is dropped.
	path := fixtureReader(t, "Gemfile.lock", `PATH
  remote: .
  specs:
    myapp (1.0.0)
      actionpack (= 8.2.0)
      rake

GEM
  remote: https://rubygems.org/
  specs:
    actionpack (8.2.0)
      activesupport (= 8.2.0)
      rack (>= 2.2.4)
    activesupport (8.2.0)
      concurrent-ruby (~> 1.0, >= 1.0.2)
    concurrent-ruby (1.3.4)
    nokogiri (1.19.1-arm64-darwin)
      racc (~> 1.4)
    racc (1.8.1)
    rack (3.1.8)
    rake (13.3.0)

PLATFORMS
  ruby

DEPENDENCIES
  myapp!
  rake

BUNDLED WITH
   2.6.2
`)
	got, err := parseGemfileLockGraph(path)
	if err != nil {
		t.Fatalf("parseGemfileLockGraph: %v", err)
	}
	want := graphWant{
		"pkg:gem/myapp@1.0.0":         {"pkg:gem/actionpack@8.2.0", "pkg:gem/rake@13.3.0"},
		"pkg:gem/actionpack@8.2.0":    {"pkg:gem/activesupport@8.2.0", "pkg:gem/rack@3.1.8"},
		"pkg:gem/activesupport@8.2.0": {"pkg:gem/concurrent-ruby@1.3.4"},
		// The platform suffix is stripped from the spec's own version, matching
		// how scalibr's gemfilelock extractor builds the purl.
		"pkg:gem/nokogiri@1.19.1": {"pkg:gem/racc@1.8.1"},
	}
	assertGraph(t, got, want)
}

func TestParseGemfileLockGraph_NoSpecsSection(t *testing.T) {
	// A lockfile with no specs block (or an empty one) yields no edges rather
	// than an error — pre-Bundler formats and hand-trimmed files must not fail
	// the scan.
	path := fixtureReader(t, "Gemfile.lock", `DEPENDENCIES
  rake

BUNDLED WITH
   2.6.2
`)
	got, err := parseGemfileLockGraph(path)
	if err != nil {
		t.Fatalf("parseGemfileLockGraph: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("graph = %v, want empty", got)
	}
}

// graphWant is the expected edge set of a graph parser test.
type graphWant map[string][]string

// assertGraph compares a parsed graph against the expected edges, reporting
// both missing/wrong edge lists and unexpected extra sources.
func assertGraph(t *testing.T, got map[string][]string, want graphWant) {
	t.Helper()
	for from, tos := range want {
		if !reflect.DeepEqual(got[from], tos) {
			t.Errorf("edges[%q] = %v, want %v", from, got[from], tos)
		}
	}
	if len(got) != len(want) {
		t.Errorf("graph has %d sources, want %d: %v", len(got), len(want), got)
	}
}
