// ABOUTME: Test that pdm.lock parses through the shared [[package]]+files=[] path.
// ABOUTME: Schema is identical to modern poetry.lock; this guards against regressions in the shared parser.
package lockfiles

import "testing"

func TestParsePDMLock_PackagesFiles(t *testing.T) {
	// Real pdm.lock structure: top-level [metadata] holds content-hash,
	// each [[package]] carries an inline files array. Wire-compatible with
	// modern poetry.lock — same shared parser handles both.
	path := writeFixture(t, "pdm.lock", `[metadata]
groups = ["default"]
lock_version = "4.4.1"
content_hash = "sha256:0acb7cdc3e805d9bec1f3347b79b69d92ba257d2cd82b5ef4355010930d46deb"

[[package]]
name = "six"
version = "1.16.0"
requires_python = ">=2.7"
groups = ["default"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:`+requestsWheelHash+`"},
    {file = "six-1.16.0.tar.gz",                hash = "sha256:`+requestsSdistHash+`"},
]
`)
	got, err := parsePyPIPackagesFilesLock(path)
	if err != nil {
		t.Fatalf("parsePyPIPackagesFilesLock: %v", err)
	}
	hs := got["pkg:pypi/six@1.16.0"]
	if len(hs) != 2 {
		t.Errorf("got %d hashes, want 2 (wheel + sdist): %v", len(hs), hs)
	}
}
