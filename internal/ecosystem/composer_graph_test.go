// ABOUTME: Tests for composer.lock dependency-edge extraction.
// ABOUTME: require keys resolve against the lock's own packages; platform deps (php, ext-*) drop out naturally.
package ecosystem

import (
	"reflect"
	"testing"
)

func TestParseComposerLockGraph(t *testing.T) {
	path := fixtureReader(t, "composer.lock", `{
  "packages": [
    {
      "name": "monolog/monolog",
      "version": "3.6.0",
      "require": {
        "php": ">=8.1",
        "psr/log": "^2.0 || ^3.0"
      }
    },
    {
      "name": "psr/log",
      "version": "3.0.0",
      "require": {"php": ">=8.0.0"}
    }
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "11.0.0",
      "require": {
        "ext-dom": "*",
        "psr/log": "^3.0"
      }
    }
  ]
}`)
	got, err := parseComposerLockGraph(path)
	if err != nil {
		t.Fatalf("parseComposerLockGraph: %v", err)
	}
	want := map[string][]string{
		"pkg:composer/monolog/monolog@3.6.0":  {"pkg:composer/psr/log@3.0.0"},
		"pkg:composer/phpunit/phpunit@11.0.0": {"pkg:composer/psr/log@3.0.0"},
	}
	for from, tos := range want {
		if !reflect.DeepEqual(got[from], tos) {
			t.Errorf("edges[%q] = %v, want %v", from, got[from], tos)
		}
	}
	if len(got) != len(want) {
		t.Errorf("graph has %d sources, want %d: %v", len(got), len(want), got)
	}
}
