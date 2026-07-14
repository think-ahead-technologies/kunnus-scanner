// ABOUTME: Tests for the CMake declare parser — FetchContent/ExternalProject/CPM grammars over realistic CMake source.
// ABOUTME: Table tests cover keyword and shorthand forms, URL_HASH mining, comment/quote handling, and the ${...}-skip rule.
package cmakedecl

import (
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// declKey renders a Decl compactly for table comparison.
func declKey(d Decl) string {
	s := d.PURLType + " " + d.Name + "@" + d.Version
	for _, h := range d.Hashes {
		s += " " + string(h.Algorithm) + ":" + h.Hex
	}
	return s
}

func TestParse(t *testing.T) {
	const zlibSHA256 = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"

	cases := []struct {
		name string
		src  string
		want []string // declKey strings, order-insensitive; nil = expect none
	}{
		{
			"fetchcontent git github",
			`FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
)`,
			[]string{"github fmtlib/fmt@10.2.1"},
		},
		{
			"fetchcontent git non-github",
			"FetchContent_Declare(mylib GIT_REPOSITORY https://git.example.com/team/mylib.git GIT_TAG v2.0.0)",
			[]string{"generic mylib@v2.0.0"},
		},
		{
			"fetchcontent url with sha256",
			`FetchContent_Declare(zlib
  URL https://zlib.net/zlib-1.3.1.tar.gz
  URL_HASH SHA256=` + zlibSHA256 + `
)`,
			[]string{"generic zlib@1.3.1 SHA-256:" + zlibSHA256},
		},
		{
			"externalproject same grammar",
			"ExternalProject_Add(curl GIT_REPOSITORY https://github.com/curl/curl.git GIT_TAG curl-8_5_0)",
			[]string{"github curl/curl@curl-8_5_0"},
		},
		{
			"command names are case-insensitive",
			"fetchcontent_declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt GIT_TAG 10.2.1)",
			[]string{"github fmtlib/fmt@10.2.1"},
		},
		{
			"cpm shorthand gh with hash ref",
			`CPMAddPackage("gh:fmtlib/fmt#10.2.1")`,
			[]string{"github fmtlib/fmt@10.2.1"},
		},
		{
			"cpm shorthand gh with at version",
			`CPMAddPackage("gh:nlohmann/json@3.11.3")`,
			[]string{"github nlohmann/json@3.11.3"},
		},
		{
			"cpm shorthand gh versionless",
			`CPMAddPackage("gh:owner/repo")`,
			[]string{"github owner/repo@"},
		},
		{
			// CPM allows both suffixes: #tag pins the git ref, @version declares
			// the version. The ref is the exact pin and wins; neither may leak
			// into the repo name (seen in the wild in CPM.cmake's own examples).
			"cpm shorthand gh with tag and version",
			`CPMAddPackage("gh:chriskohlhoff/asio#asio-1-18-1@1.18.1")`,
			[]string{"github chriskohlhoff/asio@asio-1-18-1"},
		},
		{
			"cpm shorthand gitlab",
			`CPMAddPackage("gl:group/proj@1.0.0")`,
			[]string{"generic proj@1.0.0"},
		},
		{
			"cpm shorthand full url",
			`CPMAddPackage("https://github.com/cpm-cmake/CPM.cmake@0.38.7")`,
			[]string{"github cpm-cmake/CPM.cmake@0.38.7"},
		},
		{
			"cpm keyword github repository",
			`CPMAddPackage(
  NAME fmt
  GITHUB_REPOSITORY fmtlib/fmt
  GIT_TAG 10.2.1
)`,
			[]string{"github fmtlib/fmt@10.2.1"},
		},
		{
			"cpm keyword version fallback",
			"CPMAddPackage(NAME json GITHUB_REPOSITORY nlohmann/json VERSION 3.11.3)",
			[]string{"github nlohmann/json@3.11.3"},
		},
		{
			"cpm keyword git_tag beats version",
			"CPMAddPackage(NAME json GITHUB_REPOSITORY nlohmann/json VERSION 3.11 GIT_TAG v3.11.3)",
			[]string{"github nlohmann/json@v3.11.3"},
		},
		{
			"cpm keyword url",
			"CPMAddPackage(NAME zlib VERSION 1.3.1 URL https://zlib.net/zlib-1.3.1.tar.gz URL_HASH SHA256=" + zlibSHA256 + ")",
			[]string{"generic zlib@1.3.1 SHA-256:" + zlibSHA256},
		},
		{
			"cpmfindpackage keyword form",
			"CPMFindPackage(NAME fmt GITHUB_REPOSITORY fmtlib/fmt VERSION 10.2.1)",
			[]string{"github fmtlib/fmt@10.2.1"},
		},
		{
			"variable identity drops the declare",
			"FetchContent_Declare(${DEP_NAME} GIT_REPOSITORY ${DEP_URL} GIT_TAG v1.0)",
			nil,
		},
		{
			"variable tag keeps declare versionless",
			"FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt GIT_TAG ${FMT_TAG})",
			[]string{"github fmtlib/fmt@"},
		},
		{
			"comments and strings ignored",
			`# FetchContent_Declare(commented GIT_REPOSITORY https://github.com/x/commented GIT_TAG v9)
set(DOC "CPMAddPackage(gh:x/instring@1)")
FetchContent_Declare(real GIT_REPOSITORY https://github.com/x/real GIT_TAG v1)`,
			[]string{"github x/real@v1"},
		},
		{
			"source_dir only declare skipped",
			"FetchContent_Declare(local SOURCE_DIR ${CMAKE_SOURCE_DIR}/third_party/local)",
			nil,
		},
		{
			"unrelated commands ignored",
			"cmake_minimum_required(VERSION 3.20)\nproject(app CXX)\nadd_subdirectory(src)\nfind_package(Threads REQUIRED)",
			nil,
		},
		{
			"bad url_hash dropped, decl kept",
			"FetchContent_Declare(zlib URL https://zlib.net/zlib-1.3.1.tar.gz URL_HASH SHA256=nothex)",
			[]string{"generic zlib@1.3.1"},
		},
		{
			"multiple declares in one file",
			`FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt GIT_TAG 10.2.1)
CPMAddPackage("gh:nlohmann/json@3.11.3")`,
			[]string{"github fmtlib/fmt@10.2.1", "github nlohmann/json@3.11.3"},
		},
		{"empty input", "", nil},
		{"unterminated invocation", "FetchContent_Declare(fmt GIT_REPOSITORY https://github.com/fmtlib/fmt", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decls := Parse(strings.NewReader(tc.src))
			got := map[string]bool{}
			for _, d := range decls {
				got[declKey(d)] = true
			}
			if len(got) != len(tc.want) {
				t.Fatalf("Parse = %v, want %v", keys(got), tc.want)
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("missing decl %q (got %v)", w, keys(got))
				}
			}
		})
	}
}

func TestVersionFromURL(t *testing.T) {
	cases := map[string]string{
		"https://zlib.net/zlib-1.3.1.tar.gz":                                "1.3.1",
		"https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz": "3.11.3",
		"https://example.com/lib.tar.gz":                                    "",
		"https://example.com/download?id=42":                                "",
	}
	for url, want := range cases {
		if got := versionFromURL(url); got != want {
			t.Errorf("versionFromURL(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestParseURLHash(t *testing.T) {
	sha256hex := strings.Repeat("ab", 32)
	cases := []struct {
		in      string
		wantAlg hashes.Algorithm // "" = expect no hash
		wantHex string
	}{
		{"SHA256=" + sha256hex, hashes.AlgSHA256, sha256hex},
		{"sha256=" + sha256hex, hashes.AlgSHA256, sha256hex},
		{"SHA512=" + strings.Repeat("cd", 64), hashes.AlgSHA512, strings.Repeat("cd", 64)},
		{"SHA1=" + strings.Repeat("12", 20), hashes.AlgSHA1, strings.Repeat("12", 20)},
		{"MD5=" + strings.Repeat("34", 16), hashes.AlgMD5, strings.Repeat("34", 16)},
		{"SHA256=zznothex", "", ""},
		{"SHA256=" + strings.Repeat("ab", 16), "", ""}, // wrong length for sha256
		{"SHA3_256=" + sha256hex, "", ""},              // unsupported algorithm
		{"noequalsign", "", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		h, ok := parseURLHash(tc.in)
		if tc.wantAlg == "" {
			if ok {
				t.Errorf("parseURLHash(%q) = %+v, want none", tc.in, h)
			}
			continue
		}
		if !ok || h.Algorithm != tc.wantAlg || h.Hex != tc.wantHex {
			t.Errorf("parseURLHash(%q) = %+v ok=%v, want %s:%s", tc.in, h, ok, tc.wantAlg, tc.wantHex)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
