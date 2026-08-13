// ABOUTME: Tests for pylock.toml (PEP 751) hash extraction.
// ABOUTME: PEP 751 keys digests by algorithm name (hashes.sha256 = "<hex>"), not by the sha256: SRI form the other five formats use.
package ecosystem

import "testing"

func TestParsePylock_SdistAndWheels(t *testing.T) {
	// PEP 751 gives a package one optional sdist plus any number of wheels,
	// each with its own hashes table. Every digest must land in the slice —
	// dropping wheels would mismatch a binary install on its target platform.
	r := fixtureReader(t, "pylock.toml", `lock-version = "1.0"
created-by = "uv"

[[packages]]
name = "emoji"
version = "2.14.0"

[packages.sdist]
url = "https://example.invalid/emoji.tar.gz"
hashes.sha256 = "`+requestsSdistHash+`"

[[packages.wheels]]
url = "https://example.invalid/emoji.whl"
hashes.sha256 = "`+requestsWheelHash+`"
`)
	got, err := parsePylock(r)
	if err != nil {
		t.Fatalf("parsePylock: %v", err)
	}
	hs := got["pkg:pypi/emoji@2.14.0"]
	if len(hs) != 2 {
		t.Errorf("got %d hashes, want 2 (sdist + 1 wheel): %v", len(hs), hs)
	}
}

func TestParsePylock_PEP503NameNormalization(t *testing.T) {
	// The purl must match what scalibr's pylock extractor emits, or hash
	// injection never binds to the component.
	r := fixtureReader(t, "pylock.toml", `lock-version = "1.0"

[[packages]]
name = "MarkupSafe"
version = "2.1.1"

[packages.sdist]
hashes.sha256 = "`+requestsSdistHash+`"
`)
	got, _ := parsePylock(r)
	if _, ok := got["pkg:pypi/markupsafe@2.1.1"]; !ok {
		t.Errorf("normalised PURL missing: %v", got)
	}
}

func TestParsePylock_NonSHA256DigestsIgnored(t *testing.T) {
	// PEP 751 permits any hashlib algorithm. Weaker digests must not
	// masquerade as an integrity record (they would fail BSI's check anyway),
	// so only sha256 is recorded — matching every other PyPI parser.
	r := fixtureReader(t, "pylock.toml", `lock-version = "1.0"

[[packages]]
name = "weak"
version = "1.0.0"

[[packages.wheels]]
hashes.md5 = "d41d8cd98f00b204e9800998ecf8427e"
hashes.sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
`)
	got, _ := parsePylock(r)
	if hs, ok := got["pkg:pypi/weak@1.0.0"]; ok {
		t.Errorf("non-sha256 digests must yield no entry, got %v", hs)
	}
}

func TestParsePylock_DirectoryAndVCSPackagesSkipped(t *testing.T) {
	// A path or VCS dependency has no published distribution and so no
	// digest. scalibr's extractor still reports the package (a VCS entry
	// carries its commit as the version); we simply have no hash to add.
	r := fixtureReader(t, "pylock.toml", `lock-version = "1.0"

[[packages]]
name = "my-app"
version = "0.1.0"

[packages.directory]
path = "."

[[packages]]
name = "from-git"

[packages.vcs]
type = "git"
commit-id = "0123456789abcdef0123456789abcdef01234567"
`)
	got, _ := parsePylock(r)
	if len(got) != 0 {
		t.Errorf("packages without distributions must yield no hashes, got %v", got)
	}
}

func TestParsePylock_VersionlessPackageSkipped(t *testing.T) {
	// Without a version there is no purl to key the digest by, so the entry
	// is dropped rather than guessed at.
	r := fixtureReader(t, "pylock.toml", `lock-version = "1.0"

[[packages]]
name = "no-version"

[packages.sdist]
hashes.sha256 = "`+requestsSdistHash+`"
`)
	got, _ := parsePylock(r)
	if len(got) != 0 {
		t.Errorf("versionless package must yield no hashes, got %v", got)
	}
}

func TestParsePylock_MalformedTOMLErrors(t *testing.T) {
	r := fixtureReader(t, "pylock.toml", `[[packages broken`)
	if _, err := parsePylock(r); err == nil {
		t.Error("want error for malformed TOML")
	}
}
