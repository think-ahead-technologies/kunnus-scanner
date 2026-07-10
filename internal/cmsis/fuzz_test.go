// ABOUTME: Fuzz targets for the csolution parser and pack-spec grammar — arbitrary input must never panic.
// ABOUTME: Every returned spec must carry a vendor-namespaced non-empty name with no wildcards.
package cmsis

import (
	"strings"
	"testing"
)

// FuzzParseSolution drives parseSolution with arbitrary YAML.
func FuzzParseSolution(f *testing.F) {
	seeds := []string{
		"",
		"solution:\n  packs:\n    - pack: ARM::CMSIS@5.9.0\n",
		"solution:\n  packs:\n    - pack: X::Y\n      path: ./local\n",
		"solution:\n  packs:\n    - pack: NXP::*\n",
		"solution:\n  packs: 42\n",
		"solution: []\n",
		"\t{{{",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data string) {
		for _, s := range parseSolution(strings.NewReader(data)) {
			checkSpec(t, data, s)
		}
	})
}

// FuzzParsePackSpec drives parsePackSpec with arbitrary specs.
func FuzzParsePackSpec(f *testing.F) {
	seeds := []string{
		"", "ARM::CMSIS@5.9.0", "ARM::CMSIS-Driver@^2.8.0", "Keil::ARM_Compiler",
		"NXP::*", "::@", "a::b::c@d", "@1.0", "ARM::CMSIS@",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		if p := parsePackSpec(spec); p != nil {
			checkSpec(t, spec, *p)
		}
	})
}

// checkSpec asserts the parser contract: a vendor/pack namespaced name with
// both sides non-empty and no wildcard leaking through.
func checkSpec(t *testing.T, input string, s pkgSpec) {
	t.Helper()
	vendor, pack, ok := strings.Cut(s.name, "/")
	if !ok || vendor == "" || pack == "" {
		t.Fatalf("parser(%q) returned un-namespaced name %q", input, s.name)
	}
	if strings.Contains(s.name, "*") {
		t.Fatalf("parser(%q) leaked wildcard name %q", input, s.name)
	}
}
