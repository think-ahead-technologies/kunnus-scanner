// ABOUTME: Tests for bun.lock hash extraction.
// ABOUTME: Format is JSONC ([name@ver, resolution, deps, integrity]); same SHA-512 SRI as npm.
package hashes

import "testing"

func TestParseBunLock_UnscopedAndScoped(t *testing.T) {
	// JSON5/JSONC: trailing commas after every entry — must be tolerated.
	path := writeFixture(t, "bun.lock", `{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": { "lodash": "^4.17.0", "@babel/core": "^7.0.0" },
    },
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "`+lodashIntegrity+`"],
    "@babel/core": ["@babel/core@7.0.0", "", {}, "`+babelIntegrity+`"],
  },
}`)
	got, err := parseBunLock(path)
	if err != nil {
		t.Fatalf("parseBunLock: %v", err)
	}
	for _, want := range []string{"pkg:npm/lodash@4.17.21", "pkg:npm/%40babel/core@7.0.0"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestParseBunLock_SkipsEntriesWithoutIntegrity(t *testing.T) {
	// Git/file: dependencies and workspaces have no integrity at index 3 —
	// the tuple may be shorter or carry an empty string. Both must be silently
	// skipped.
	path := writeFixture(t, "bun.lock", `{
  "packages": {
    "git-dep": ["git-dep@1.0.0", "https://github.com/x/y#abc", {}],
    "local": ["local@workspace:packages/local"],
    "real": ["real@1.0.0", "", {}, "`+lodashIntegrity+`"],
  }
}`)
	got, _ := parseBunLock(path)
	if _, ok := got["pkg:npm/real@1.0.0"]; !ok {
		t.Errorf("missing real package: %v", got)
	}
	if _, ok := got["pkg:npm/git-dep@1.0.0"]; ok {
		t.Errorf("git-dep should be skipped (no integrity)")
	}
	if _, ok := got["pkg:npm/local@workspace:packages/local"]; ok {
		t.Errorf("workspace entry should be skipped")
	}
}

func TestParseBunLock_SkipsNonSha512(t *testing.T) {
	path := writeFixture(t, "bun.lock", `{
  "packages": {
    "weak": ["weak@1.0.0", "", {}, "sha1-abcdefghijklmnopqrstuvwxyz12"]
  }
}`)
	got, _ := parseBunLock(path)
	if _, ok := got["pkg:npm/weak@1.0.0"]; ok {
		t.Errorf("sha1 entry must be skipped, got %v", got)
	}
}

func TestParseBunLock_MalformedErrors(t *testing.T) {
	path := writeFixture(t, "bun.lock", `not even close to json`)
	if _, err := parseBunLock(path); err == nil {
		t.Error("want error for malformed lockfile")
	}
}
