// ABOUTME: Tests for Pipfile.lock hash extraction.
// ABOUTME: Each package's hashes[] holds one sha256: entry per distribution file (wheel/sdist).
package lockfiles

import "testing"

func TestParsePipfileLock_DefaultAndDevelop(t *testing.T) {
	// Pipenv splits runtime vs dev deps into two top-level sections. Both
	// must contribute hashes; ignoring "develop" would lose half the SBOM.
	path := writeFixture(t, "Pipfile.lock", `{
  "default": {
    "itsdangerous": {
      "hashes": [
        "sha256:`+requestsWheelHash+`",
        "sha256:`+requestsSdistHash+`"
      ],
      "version": "==2.1.2"
    }
  },
  "develop": {
    "markupsafe": {
      "hashes": [
        "sha256:`+requestsWheelHash+`"
      ],
      "version": "==2.1.1"
    }
  }
}`)
	got, err := parsePipfileLock(path)
	if err != nil {
		t.Fatalf("parsePipfileLock: %v", err)
	}
	hs := got["pkg:pypi/itsdangerous@2.1.2"]
	if len(hs) != 2 {
		t.Errorf("itsdangerous: got %d hashes, want 2", len(hs))
	}
	if len(got["pkg:pypi/markupsafe@2.1.1"]) != 1 {
		t.Errorf("markupsafe (develop) lost: %v", got)
	}
}

func TestParsePipfileLock_StripsEqualsPrefix(t *testing.T) {
	// version is recorded as "==X.Y.Z" by Pipenv. The PURL key omits the
	// operator — a missed strip would silently shift every PURL by two chars.
	path := writeFixture(t, "Pipfile.lock", `{
  "default": {
    "foo": {
      "hashes": ["sha256:`+requestsWheelHash+`"],
      "version": "==1.0.0"
    }
  }
}`)
	got, _ := parsePipfileLock(path)
	if _, ok := got["pkg:pypi/foo@1.0.0"]; !ok {
		t.Errorf("== prefix not stripped: %v", got)
	}
}

func TestParsePipfileLock_SkipsEntriesWithoutVersion(t *testing.T) {
	// Editable installs and VCS deps lack a pinned version in Pipfile.lock.
	// Without a version we can't form a PURL — skip.
	path := writeFixture(t, "Pipfile.lock", `{
  "default": {
    "from-git": {
      "git": "https://github.com/x/y.git",
      "ref": "abc"
    }
  }
}`)
	got, _ := parsePipfileLock(path)
	if len(got) != 0 {
		t.Errorf("vcs entries must be skipped, got %v", got)
	}
}

func TestParsePipfileLock_PEP503NameNormalization(t *testing.T) {
	path := writeFixture(t, "Pipfile.lock", `{
  "default": {
    "Async_Timeout": {
      "hashes": ["sha256:`+requestsWheelHash+`"],
      "version": "==5.0.1"
    }
  }
}`)
	got, _ := parsePipfileLock(path)
	if _, ok := got["pkg:pypi/async-timeout@5.0.1"]; !ok {
		t.Errorf("normalised PURL missing: %v", got)
	}
}

func TestParsePipfileLock_MalformedJSONErrors(t *testing.T) {
	path := writeFixture(t, "Pipfile.lock", `{not json`)
	if _, err := parsePipfileLock(path); err == nil {
		t.Error("want error for malformed JSON")
	}
}
