// ABOUTME: Tests for uv.lock hash extraction.
// ABOUTME: uv keeps sdist and wheels in separate TOML fields; both contribute hashes.
package lockfiles

import "testing"

func TestParseUvLock_SdistAndWheels(t *testing.T) {
	// Standard package: one sdist + multiple platform wheels. Each entry's
	// hash should land in the resulting slice — losing wheels would mismatch
	// every binary install on its target platform.
	path := writeFixture(t, "uv.lock", `version = 1
requires-python = ">=3.10"

[[package]]
name = "emoji"
version = "2.14.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example.invalid/emoji.tar.gz", hash = "sha256:`+requestsSdistHash+`", size = 1 }
wheels = [
    { url = "https://example.invalid/emoji.whl", hash = "sha256:`+requestsWheelHash+`", size = 2 },
]
`)
	got, err := parseUvLock(path)
	if err != nil {
		t.Fatalf("parseUvLock: %v", err)
	}
	hs := got["pkg:pypi/emoji@2.14.0"]
	if len(hs) != 2 {
		t.Errorf("got %d hashes, want 2 (sdist + 1 wheel): %v", len(hs), hs)
	}
}

func TestParseUvLock_VirtualPackageSkipped(t *testing.T) {
	// The project itself is recorded as source = { virtual = "." } with no
	// sdist/wheels. Nothing to hash; the entry must not appear.
	path := writeFixture(t, "uv.lock", `version = 1

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
`)
	got, _ := parseUvLock(path)
	if _, ok := got["pkg:pypi/my-app@0.1.0"]; ok {
		t.Errorf("virtual package must yield no hash entry, got %v", got)
	}
}

func TestParseUvLock_WheelsOnlyOrSdistOnly(t *testing.T) {
	// Some packages publish wheels only (e.g. C-extension reuses prebuilt)
	// or sdist only (pure source). Each must collect what it has.
	path := writeFixture(t, "uv.lock", `version = 1

[[package]]
name = "wheels-only"
version = "1.0.0"
wheels = [
    { url = "https://example.invalid/x.whl", hash = "sha256:`+requestsWheelHash+`" },
]

[[package]]
name = "sdist-only"
version = "2.0.0"
sdist = { url = "https://example.invalid/y.tar.gz", hash = "sha256:`+requestsSdistHash+`" }
`)
	got, _ := parseUvLock(path)
	if len(got["pkg:pypi/wheels-only@1.0.0"]) != 1 {
		t.Errorf("wheels-only missing: %v", got)
	}
	if len(got["pkg:pypi/sdist-only@2.0.0"]) != 1 {
		t.Errorf("sdist-only missing: %v", got)
	}
}

func TestParseUvLock_PEP503NameNormalization(t *testing.T) {
	path := writeFixture(t, "uv.lock", `version = 1

[[package]]
name = "MarkupSafe"
version = "2.1.1"
sdist = { url = "x", hash = "sha256:`+requestsSdistHash+`" }
`)
	got, _ := parseUvLock(path)
	if _, ok := got["pkg:pypi/markupsafe@2.1.1"]; !ok {
		t.Errorf("normalised PURL missing: %v", got)
	}
}

func TestParseUvLock_MalformedTOMLErrors(t *testing.T) {
	path := writeFixture(t, "uv.lock", `[[package broken`)
	if _, err := parseUvLock(path); err == nil {
		t.Error("want error for malformed TOML")
	}
}
