// ABOUTME: Tests for requirements.txt hash extraction.
// ABOUTME: Only "name==version" pins with --hash=sha256: annotations contribute; everything else is ignored.
package ecosystem

import "testing"

func TestParseRequirementsTxt_SingleLineSingleHash(t *testing.T) {
	path := writeFixture(t, "requirements.txt",
		`click==8.1.7 --hash=sha256:`+requestsWheelHash+"\n")
	got, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parseRequirementsTxt: %v", err)
	}
	hs := got["pkg:pypi/click@8.1.7"]
	if len(hs) != 1 {
		t.Errorf("got %d hashes, want 1: %v", len(hs), hs)
	}
}

func TestParseRequirementsTxt_LineContinuationsAndMultipleHashes(t *testing.T) {
	// pip-compile produces backslash-continued lines with one --hash per
	// wheel/sdist. The walker must stitch them into one logical line.
	path := writeFixture(t, "requirements.txt", `black==24.10.0 \
    --hash=sha256:`+requestsWheelHash+` \
    --hash=sha256:`+requestsSdistHash+`
`)
	got, _ := parseRequirementsTxt(path)
	hs := got["pkg:pypi/black@24.10.0"]
	if len(hs) != 2 {
		t.Errorf("continuations not joined: got %d hashes, want 2: %v", len(hs), hs)
	}
}

func TestParseRequirementsTxt_MultiplePackages(t *testing.T) {
	path := writeFixture(t, "requirements.txt", `click==8.1.7 --hash=sha256:`+requestsWheelHash+`
black==24.10.0 --hash=sha256:`+requestsSdistHash+`
`)
	got, _ := parseRequirementsTxt(path)
	if len(got["pkg:pypi/click@8.1.7"]) != 1 {
		t.Errorf("click lost: %v", got)
	}
	if len(got["pkg:pypi/black@24.10.0"]) != 1 {
		t.Errorf("black lost: %v", got)
	}
}

func TestParseRequirementsTxt_SkipsCommentsAndBlanks(t *testing.T) {
	path := writeFixture(t, "requirements.txt", `# this is a comment

click==8.1.7 --hash=sha256:`+requestsWheelHash+`  # trailing comment

# another
`)
	got, _ := parseRequirementsTxt(path)
	if len(got["pkg:pypi/click@8.1.7"]) != 1 {
		t.Errorf("trailing comment stripped click off: %v", got)
	}
}

func TestParseRequirementsTxt_SkipsNonPinnedLines(t *testing.T) {
	// Without "==" the version is unresolved — no PURL can be formed. Editable
	// (-e), referenced (-r), and range specs all silently drop out.
	path := writeFixture(t, "requirements.txt", `-e git+https://github.com/x/y.git
-r other.txt
foo>=1.0 --hash=sha256:`+requestsWheelHash+`
foo @ https://example.invalid/foo.whl
bar==2.0.0 --hash=sha256:`+requestsSdistHash+`
`)
	got, _ := parseRequirementsTxt(path)
	if _, ok := got["pkg:pypi/foo@1.0"]; ok {
		t.Errorf("range spec must not produce an entry: %v", got)
	}
	if len(got["pkg:pypi/bar@2.0.0"]) != 1 {
		t.Errorf("legitimate pin lost: %v", got)
	}
}

func TestParseRequirementsTxt_PinWithoutHashesProducesNoEntry(t *testing.T) {
	// "name==version" alone is a valid pip pin but carries no integrity
	// data. Skipping keeps the hashmap consistent — only verifiable hashes
	// land in the SBOM.
	path := writeFixture(t, "requirements.txt", `nltk==3.2.2
`)
	got, _ := parseRequirementsTxt(path)
	if _, ok := got["pkg:pypi/nltk@3.2.2"]; ok {
		t.Errorf("pin without --hash must not appear: %v", got)
	}
}

func TestParseRequirementsTxt_StripsExtrasAndEnvMarkers(t *testing.T) {
	// requests[security]==2.31.0; python_version >= "3.7" --hash=sha256:...
	// The extras and marker don't change package identity — PURL is plain.
	path := writeFixture(t, "requirements.txt",
		`requests[security]==2.31.0;python_version>="3.7" --hash=sha256:`+requestsWheelHash+"\n")
	got, _ := parseRequirementsTxt(path)
	if len(got["pkg:pypi/requests@2.31.0"]) != 1 {
		t.Errorf("extras/marker handling lost the entry: %v", got)
	}
}

func TestParseRequirementsTxt_SkipsNonSha256Hashes(t *testing.T) {
	// pip accepts --hash=sha384, sha512, etc. We emit only sha256 because
	// that's universal across PyPI and matches what poetry/pdm/pipfile/uv ship.
	path := writeFixture(t, "requirements.txt", `foo==1.0.0 --hash=sha384:abc --hash=sha256:`+requestsWheelHash+`
`)
	got, _ := parseRequirementsTxt(path)
	hs := got["pkg:pypi/foo@1.0.0"]
	if len(hs) != 1 {
		t.Errorf("got %d hashes, want 1 (sha384 dropped): %v", len(hs), hs)
	}
}

func TestParseRequirementsTxt_PEP503NameNormalization(t *testing.T) {
	path := writeFixture(t, "requirements.txt",
		`Async_Timeout==5.0.1 --hash=sha256:`+requestsWheelHash+"\n")
	got, _ := parseRequirementsTxt(path)
	if _, ok := got["pkg:pypi/async-timeout@5.0.1"]; !ok {
		t.Errorf("normalised PURL missing: %v", got)
	}
}

func TestParseRequirementsTxt_MissingFileErrors(t *testing.T) {
	if _, err := parseRequirementsTxt("/no/such/requirements.txt"); err == nil {
		t.Error("want error for missing file")
	}
}
