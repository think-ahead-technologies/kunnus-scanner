// ABOUTME: Tests for pnpm-lock.yaml hash extraction.
// ABOUTME: Covers v6/v7/v9 lockfile syntax (the prefixed-key and key/name+version variants).
package lockfiles

import "testing"

func TestParsePNPMLock_V6Style(t *testing.T) {
	// v6 keys: "/lodash@4.17.21"
	path := writeFixture(t, "pnpm-lock.yaml", `lockfileVersion: '6.0'
packages:
  /lodash@4.17.21:
    resolution:
      integrity: `+lodashIntegrity+`
    dev: false
  '/@babel/core@7.0.0':
    resolution:
      integrity: `+babelIntegrity+`
`)

	got, err := parsePNPMLock(path)
	if err != nil {
		t.Fatalf("parsePNPMLock: %v", err)
	}
	for _, want := range []string{"pkg:npm/lodash@4.17.21", "pkg:npm/%40babel/core@7.0.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q: %v", want, got)
		}
	}
}

func TestParsePNPMLock_V9Style(t *testing.T) {
	// v9 introduced "snapshots" but the packages map still carries the
	// integrity at <name>@<version>. Test that variant.
	path := writeFixture(t, "pnpm-lock.yaml", `lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: `+lodashIntegrity+`}
`)
	got, err := parsePNPMLock(path)
	if err != nil {
		t.Fatalf("parsePNPMLock: %v", err)
	}
	if _, ok := got["pkg:npm/lodash@4.17.21"]; !ok {
		t.Errorf("v9 lockfile not parsed: %v", got)
	}
}

func TestParsePNPMLock_SkipsNonSha512(t *testing.T) {
	path := writeFixture(t, "pnpm-lock.yaml", `lockfileVersion: '6.0'
packages:
  /weak@1.0.0:
    resolution:
      integrity: sha1-aaaaaaaaaaaaaaaaaaaaaaaaaaa=
`)
	got, _ := parsePNPMLock(path)
	if _, ok := got["pkg:npm/weak@1.0.0"]; ok {
		t.Errorf("sha1 entry should be skipped, got %v", got)
	}
}

func TestParsePNPMLock_MalformedYAMLErrors(t *testing.T) {
	path := writeFixture(t, "pnpm-lock.yaml", "{: not yaml\n")
	if _, err := parsePNPMLock(path); err == nil {
		t.Error("want error for malformed yaml")
	}
}
