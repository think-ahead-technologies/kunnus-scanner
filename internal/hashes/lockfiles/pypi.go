// ABOUTME: Shared helpers for every PyPI-family lockfile parser (poetry, pipfile, pdm, uv, requirements).
// ABOUTME: Owns PURL normalisation (PEP 503) and the sha256: SRI decoder used by all five formats.
package lockfiles

import (
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/think-ahead/kunnus-scanner/internal/hashes"
)

// pypiNameRunPattern matches runs of - _ . per PEP 503. PyPI normalises
// "Async_Timeout", "async-timeout", and "async.timeout" to the same name;
// our PURLs must match what scalibr emits or hash injection won't bind.
var pypiNameRunPattern = regexp.MustCompile(`[-_.]+`)

// pypiPURL builds a PEP 503 normalised pkg:pypi PURL. Matches the form
// scalibr's pypipurl.MakePackageURL produces, so component PURLs and our
// hashMap keys line up at injection time.
func pypiPURL(name, version string) string {
	normalized := pypiNameRunPattern.ReplaceAllString(strings.ToLower(name), "-")
	return "pkg:pypi/" + normalized + "@" + version
}

// pypiHashFromSRI parses a "sha256:<hex>" reference (the form poetry, pdm,
// pipfile, uv, and pip --hash all emit) into a hashes.Hash. Returns ok=false
// for any other algorithm or malformed hex — Python packaging is sha256-only
// in practice; weaker digests would still fail BSI's SHA-512 check anyway and
// shouldn't masquerade as a valid integrity record.
func pypiHashFromSRI(sri string) (hashes.Hash, bool) {
	const prefix = "sha256:"
	if !strings.HasPrefix(sri, prefix) {
		return hashes.Hash{}, false
	}
	digest := strings.TrimSpace(sri[len(prefix):])
	if len(digest) != 64 {
		return hashes.Hash{}, false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return hashes.Hash{}, false
	}
	return hashes.Hash{Algorithm: hashes.AlgSHA256, Hex: strings.ToLower(digest)}, true
}
