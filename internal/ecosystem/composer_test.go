// ABOUTME: Tests the composer.lock offline license parser.
// ABOUTME: composer.lock embeds a per-package license array; PHP is not on deps.dev, so this is the only license source.
package ecosystem

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseComposerLock(t *testing.T) {
	const lock = `{
	  "packages": [
	    {"name": "psr/log", "version": "3.0.0", "license": ["MIT"]},
	    {"name": "vendor/multi", "version": "1.2.3", "license": ["MIT", "Apache-2.0"]},
	    {"name": "vendor/strlicense", "version": "2.0.0", "license": "BSD-3-Clause"},
	    {"name": "vendor/nolicense", "version": "0.1.0"}
	  ],
	  "packages-dev": [
	    {"name": "phpunit/phpunit", "version": "10.0.0", "license": ["BSD-3-Clause"]}
	  ]
	}`

	got, err := parseComposerLock(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("parseComposerLock: %v", err)
	}

	want := map[string][]string{
		"pkg:composer/psr/log@3.0.0":           {"MIT"},
		"pkg:composer/vendor/multi@1.2.3":      {"MIT", "Apache-2.0"},
		"pkg:composer/vendor/strlicense@2.0.0": {"BSD-3-Clause"}, // string form, not array
		"pkg:composer/phpunit/phpunit@10.0.0":  {"BSD-3-Clause"}, // packages-dev included
	}
	for purl, wantLics := range want {
		if !reflect.DeepEqual(got[purl], wantLics) {
			t.Errorf("%s: got %v, want %v", purl, got[purl], wantLics)
		}
	}
	if _, ok := got["pkg:composer/vendor/nolicense@0.1.0"]; ok {
		t.Errorf("package without a license must not appear: %v", got["pkg:composer/vendor/nolicense@0.1.0"])
	}
}
