// ABOUTME: Tests the source-manifest license parsers (Lua .rockspec, Ruby .gemspec).
// ABOUTME: These read a declarative assignment from the package's own source manifest, not a lockfile.
package ecosystem

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRockspecLicense(t *testing.T) {
	cases := map[string]struct {
		rockspec string
		want     []string
	}{
		"in description table": {"package = \"x\"\nversion = \"1.0-1\"\ndescription = {\n   summary = \"s\",\n   license = \"MIT\"\n}\n", []string{"MIT"}},
		"single quotes":        {"license = 'Apache-2.0'\n", []string{"Apache-2.0"}},
		"none":                 {"package = \"x\"\nversion = \"1.0-1\"\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseRockspecLicense(strings.NewReader(tc.rockspec))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseGemspecLicense(t *testing.T) {
	cases := map[string]struct {
		gemspec string
		want    []string
	}{
		"single license": {
			"Gem::Specification.new do |s|\n  s.name = \"foo\"\n  s.license = \"MIT\"\nend\n",
			[]string{"MIT"},
		},
		"licenses array": {
			"Gem::Specification.new do |s|\n  s.licenses = [\"MIT\", \"Apache-2.0\"]\nend\n",
			[]string{"MIT", "Apache-2.0"},
		},
		"different block var, single quotes": {
			"Gem::Specification.new do |spec|\n  spec.license = 'BSD-3-Clause'\nend\n",
			[]string{"BSD-3-Clause"},
		},
		"none": {"Gem::Specification.new do |s|\n  s.name = \"foo\"\nend\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseGemspecLicense(strings.NewReader(tc.gemspec))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
