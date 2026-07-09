// ABOUTME: Tests for the CMake URL_HASH hash parser — digests keyed by the same purls internal/cmake emits.
// ABOUTME: Proves declares without a URL_HASH contribute nothing and the purl carries type, namespaced name, and version.
package ecosystem

import (
	"strings"
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

func TestParseCMakeHashes(t *testing.T) {
	zlibSHA := "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
	src := `cmake_minimum_required(VERSION 3.20)
FetchContent_Declare(zlib
  URL https://zlib.net/zlib-1.3.1.tar.gz
  URL_HASH SHA256=` + zlibSHA + `
)
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.1
)
`
	got, err := parseCMakeHashes(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parseCMakeHashes: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d entries %v, want 1 (git declares carry no URL_HASH)", len(got), got)
	}
	hs := got["pkg:generic/zlib@1.3.1"]
	if len(hs) != 1 || hs[0].Algorithm != hashes.AlgSHA256 || hs[0].Hex != zlibSHA {
		t.Errorf("pkg:generic/zlib@1.3.1 = %+v, want SHA-256:%s", hs, zlibSHA)
	}
}

func TestParseCMakeHashes_NothingToMine(t *testing.T) {
	got, err := parseCMakeHashes(strings.NewReader("project(app CXX)\nadd_subdirectory(src)\n"))
	if err != nil {
		t.Fatalf("parseCMakeHashes: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}
