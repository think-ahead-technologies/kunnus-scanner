// ABOUTME: Fuzz target for the CMake declare parser — arbitrary source must never panic.
// ABOUTME: Every Decl must carry a known purl type, a non-empty name (namespaced for github), and well-formed hex hashes.
package cmakedecl

import (
	"encoding/hex"
	"strings"
	"testing"
)

// FuzzParse drives Parse with arbitrary CMake source. The invariants are the
// parser's contract: a Decl always has a non-empty name with a known PURL type
// (github names owner/repo namespaced), and every attached hash is valid
// lowercase hex of a supported algorithm.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt.git GIT_TAG 10.2.1)",
		"FetchContent_Declare(zlib URL https://zlib.net/zlib-1.3.1.tar.gz URL_HASH SHA256=" + strings.Repeat("ab", 32) + ")",
		`CPMAddPackage("gh:nlohmann/json@3.11.3")`,
		"CPMAddPackage(NAME fmt GITHUB_REPOSITORY fmtlib/fmt VERSION 10.2.1)",
		"ExternalProject_Add(curl GIT_REPOSITORY https://github.com/curl/curl.git GIT_TAG curl-8_5_0)",
		"# comment FetchContent_Declare(x GIT_REPOSITORY y)",
		"#[[ bracket FetchContent_Declare(x) ]]",
		`set(S "CPMAddPackage(gh:a/b@1)")`,
		"FetchContent_Declare(${NAME} GIT_REPOSITORY ${URL})",
		"FetchContent_Declare(unterminated GIT_REPOSITORY https://github.com/a/b",
		"fetchcontent_declare(()())",
		`CPMAddPackage("gh:")`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		for _, d := range Parse(strings.NewReader(src)) {
			if d.Name == "" {
				t.Fatalf("Parse(%q) returned decl with empty name: %+v", src, d)
			}
			switch d.PURLType {
			case "generic":
			case "github":
				if !strings.Contains(d.Name, "/") {
					t.Fatalf("Parse(%q) = github/%q without owner namespace", src, d.Name)
				}
			default:
				t.Fatalf("Parse(%q) has unknown purl type %q", src, d.PURLType)
			}
			for _, h := range d.Hashes {
				if _, err := hex.DecodeString(h.Hex); err != nil || h.Hex != strings.ToLower(h.Hex) {
					t.Fatalf("Parse(%q) returned malformed hash %+v", src, h)
				}
			}
		}
	})
}
