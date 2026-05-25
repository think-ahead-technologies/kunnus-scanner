// ABOUTME: Tests for poetry.lock hash extraction across the two on-disk schemas.
// ABOUTME: Modern poetry stores files= inline; legacy (<1.1) used [metadata.files] keyed by package name.
package lockfiles

import (
	"testing"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// Two known-good SHA-256 digests from a real poetry.lock for "requests".
// Real values keep the test resilient against accidental hex-length bugs.
const (
	requestsWheelHash = "58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
	requestsSdistHash = "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"
)

func TestParsePoetryLock_ModernInlineFiles(t *testing.T) {
	path := writeFixture(t, "poetry.lock", `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:`+requestsWheelHash+`"},
    {file = "requests-2.31.0.tar.gz",            hash = "sha256:`+requestsSdistHash+`"},
]
`)
	got, err := parsePyPIPackagesFilesLock(path)
	if err != nil {
		t.Fatalf("parsePyPIPackagesFilesLock: %v", err)
	}
	hs, ok := got["pkg:pypi/requests@2.31.0"]
	if !ok {
		t.Fatalf("missing requests: %v", got)
	}
	if len(hs) != 2 {
		t.Errorf("got %d hashes, want 2 (wheel + sdist)", len(hs))
	}
	for _, h := range hs {
		if h.Algorithm != hashes.AlgSHA256 {
			t.Errorf("algorithm = %q, want SHA-256", h.Algorithm)
		}
		if len(h.Hex) != 64 {
			t.Errorf("hex length = %d, want 64", len(h.Hex))
		}
	}
}

func TestParsePoetryLock_LegacyMetadataFiles(t *testing.T) {
	// Pre-v1.1 poetry stored file hashes under [metadata.files] keyed by
	// package name. We still want to read them so old lockfiles in
	// long-lived repos aren't silently empty.
	path := writeFixture(t, "poetry.lock", `[[package]]
name = "emoji"
version = "2.0.0"
description = "Emoji for Python"
category = "main"

[metadata]
lock-version = "1.1"

[metadata.files]
emoji = [
    {file = "emoji-2.0.0.tar.gz", hash = "sha256:`+requestsSdistHash+`"},
]
`)
	got, _ := parsePyPIPackagesFilesLock(path)
	hs, ok := got["pkg:pypi/emoji@2.0.0"]
	if !ok || len(hs) != 1 {
		t.Fatalf("legacy [metadata.files] not collected: %v", got)
	}
}

func TestParsePoetryLock_PEP503NameNormalization(t *testing.T) {
	// Names with mixed case and underscores/dots normalise via PEP 503.
	// scalibr emits the normalised PURL; our hashMap keys must match.
	path := writeFixture(t, "poetry.lock", `[[package]]
name = "Async_Timeout"
version = "5.0.1"
files = [
    {file = "async_timeout-5.0.1-py3-none-any.whl", hash = "sha256:`+requestsWheelHash+`"},
]

[[package]]
name = "MarkupSafe"
version = "2.1.1"
files = [
    {file = "MarkupSafe-2.1.1.tar.gz", hash = "sha256:`+requestsSdistHash+`"},
]
`)
	got, _ := parsePyPIPackagesFilesLock(path)
	for _, want := range []string{
		"pkg:pypi/async-timeout@5.0.1",
		"pkg:pypi/markupsafe@2.1.1",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("normalised PURL %q missing: %v", want, got)
		}
	}
}

func TestParsePoetryLock_SkipsNonSha256(t *testing.T) {
	// Older lockfiles may carry md5 hashes alongside sha256. Skip them —
	// pip itself ignores non-sha256 --hash values in strict mode.
	path := writeFixture(t, "poetry.lock", `[[package]]
name = "legacy"
version = "1.0.0"
files = [
    {file = "legacy-1.0.0.tar.gz", hash = "md5:abcd"},
    {file = "legacy-1.0.0-py3-none-any.whl", hash = "sha256:`+requestsWheelHash+`"},
]
`)
	got, _ := parsePyPIPackagesFilesLock(path)
	hs := got["pkg:pypi/legacy@1.0.0"]
	if len(hs) != 1 {
		t.Errorf("got %d hashes, want 1 (md5 dropped): %v", len(hs), hs)
	}
}

func TestParsePoetryLock_SkipsPackagesWithoutVersion(t *testing.T) {
	// A package without a resolved version can't form a PURL — skip.
	path := writeFixture(t, "poetry.lock", `[[package]]
name = "unresolved"
files = [
    {file = "x.tar.gz", hash = "sha256:`+requestsWheelHash+`"},
]
`)
	got, _ := parsePyPIPackagesFilesLock(path)
	if len(got) != 0 {
		t.Errorf("package without version must be skipped, got %v", got)
	}
}

func TestParsePoetryLock_EmptyFilesListProducesNoEntry(t *testing.T) {
	path := writeFixture(t, "poetry.lock", `[[package]]
name = "no-files"
version = "1.0.0"
files = []
`)
	got, _ := parsePyPIPackagesFilesLock(path)
	if _, ok := got["pkg:pypi/no-files@1.0.0"]; ok {
		t.Error("empty files list must yield no hashmap entry")
	}
}

func TestParsePoetryLock_MalformedTOMLErrors(t *testing.T) {
	path := writeFixture(t, "poetry.lock", `[[package broken`)
	if _, err := parsePyPIPackagesFilesLock(path); err == nil {
		t.Error("want error for malformed TOML")
	}
}
