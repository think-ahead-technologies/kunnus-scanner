// ABOUTME: Tests for conan.lock (v0.5+) recipe-revision extraction.
// ABOUTME: Conan rrev is MD5 (32 hex) by default or SHA-1 (40 hex) under scm revision mode.
package lockfiles

import (
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// 32 hex chars — the default Conan 2 "hash" revision mode (MD5 of manifest).
// Taken from a real conan-center lockfile entry for zlib/1.2.11.
const conanRrevMD5 = "ffa77daf83a57094149707928bdce823"

// 40 hex chars — Conan 2 "scm" mode (git-commit-based SHA-1).
const conanRrevSHA1 = "9b1d0d5f5b3f2a1e4c6d7a8b9c0d1e2f3a4b5c6d"

func TestParseConanLock_RequiresMD5(t *testing.T) {
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "zlib/1.2.11#`+conanRrevMD5+`%1667396813.184"
  ],
  "build_requires": [],
  "python_requires": []
}`)
	got, err := parseConanLock(path)
	if err != nil {
		t.Fatalf("parseConanLock: %v", err)
	}
	h, ok := got["pkg:conan/zlib@1.2.11"]
	if !ok {
		t.Fatalf("missing zlib entry: %v", got)
	}
	if h.Algorithm != hashes.AlgMD5 {
		t.Errorf("algorithm = %q, want MD5", h.Algorithm)
	}
	if h.Hex != conanRrevMD5 {
		t.Errorf("hex = %q, want %q", h.Hex, conanRrevMD5)
	}
}

func TestParseConanLock_AllRequireGroups(t *testing.T) {
	// requires, build_requires, and python_requires all contribute. A regression
	// here would silently drop build/test/python deps from the SBOM hash map.
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "zlib/1.2.11#`+conanRrevMD5+`%1667396813.184"
  ],
  "build_requires": [
    "ninja/1.11.1#`+conanRrevMD5+`%1667050636.338"
  ],
  "python_requires": [
    "mytool/1.0#`+conanRrevMD5+`"
  ]
}`)
	got, _ := parseConanLock(path)
	for _, want := range []string{
		"pkg:conan/zlib@1.2.11",
		"pkg:conan/ninja@1.11.1",
		"pkg:conan/mytool@1.0",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestParseConanLock_SHA1RecipeRevision(t *testing.T) {
	// scm revision mode emits 40-char hex (git commit / SHA-1). Real-world but
	// rarer than the MD5 default; we still want to surface it.
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "openssl/3.0.0#`+conanRrevSHA1+`%1700000000.0"
  ]
}`)
	got, _ := parseConanLock(path)
	h, ok := got["pkg:conan/openssl@3.0.0"]
	if !ok {
		t.Fatalf("missing openssl: %v", got)
	}
	if h.Algorithm != hashes.AlgSHA1 {
		t.Errorf("algorithm = %q, want SHA-1", h.Algorithm)
	}
	if h.Hex != conanRrevSHA1 {
		t.Errorf("hex = %q, want %q", h.Hex, conanRrevSHA1)
	}
}

func TestParseConanLock_UserChannelAndPackageRevision(t *testing.T) {
	// Full reference: name/version@user/channel#rrev:pkgid#prev%timestamp.
	// We key on name/version only (matches scalibr's conan PURL form) and pick
	// the rrev, not the prev — rrev identifies the recipe, prev the binary.
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "fmt/10.2.1@bincrafters/stable#`+conanRrevMD5+`:abc123#deadbeefdeadbeefdeadbeefdeadbeef%1700000000.0"
  ]
}`)
	got, _ := parseConanLock(path)
	h, ok := got["pkg:conan/fmt@10.2.1"]
	if !ok {
		t.Fatalf("missing fmt: %v", got)
	}
	if h.Hex != conanRrevMD5 {
		t.Errorf("hex = %q, want recipe revision %q (not package revision)", h.Hex, conanRrevMD5)
	}
}

func TestParseConanLock_SkipsRefsWithoutRevision(t *testing.T) {
	// Some lockfiles pin only name/version with no rrev. Nothing to hash; skip.
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "norev/1.0.0"
  ]
}`)
	got, _ := parseConanLock(path)
	if _, ok := got["pkg:conan/norev@1.0.0"]; ok {
		t.Errorf("ref without rrev should produce no hash entry: %v", got)
	}
}

func TestParseConanLock_SkipsInvalidRevisionShape(t *testing.T) {
	// rrev must be 32-hex (MD5) or 40-hex (SHA-1). Anything else is either a
	// future format change or junk — drop rather than emit a malformed hash.
	const shortRrev = "deadbeef"
	const nonHexMD5 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" // 32 chars but non-hex
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "short/1.0.0#`+shortRrev+`",
    "nonhex/1.0.0#`+nonHexMD5+`"
  ]
}`)
	got, _ := parseConanLock(path)
	if _, ok := got["pkg:conan/short@1.0.0"]; ok {
		t.Error("short rrev must be skipped")
	}
	if _, ok := got["pkg:conan/nonhex@1.0.0"]; ok {
		t.Error("non-hex rrev must be skipped")
	}
}

func TestParseConanLock_SkipsConsumerConanfile(t *testing.T) {
	// A bare "version#rrev" entry (no name) is a consumer conanfile, not a
	// dependency. Matches scalibr's behavior of skipping such nodes.
	path := writeFixture(t, "conan.lock", `{
  "version": "0.5",
  "requires": [
    "1.0.0#`+conanRrevMD5+`"
  ]
}`)
	got, _ := parseConanLock(path)
	if len(got) != 0 {
		t.Errorf("consumer conanfile must be skipped, got %v", got)
	}
}

func TestParseConanLock_MalformedJSONErrors(t *testing.T) {
	path := writeFixture(t, "conan.lock", `{not json`)
	if _, err := parseConanLock(path); err == nil {
		t.Error("want error for malformed JSON")
	}
}

func TestParseConanLock_V1Empty(t *testing.T) {
	// v0.4- lockfiles use graph_lock.nodes. We don't parse them — the v2 fields
	// will simply be empty and the parser emits nothing. Verify no spurious
	// entries or errors so a stray v1 file in the tree is silent, not loud.
	path := writeFixture(t, "conan.lock", `{
  "version": "0.4",
  "graph_lock": {
    "nodes": {
      "1": { "ref": "zlib/1.2.11@#`+conanRrevMD5+`", "options": "" }
    }
  }
}`)
	got, err := parseConanLock(path)
	if err != nil {
		t.Fatalf("v0.4 lockfile should not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("v0.4 lockfile is unsupported and should yield no entries, got %v", got)
	}
}
