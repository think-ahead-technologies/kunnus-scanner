// ABOUTME: Tests for NuGet packages.lock.json hash extraction.
// ABOUTME: contentHash is raw base64 SHA-512 (no "sha512-" prefix unlike npm SRI).
package hashes

import "testing"

// newtonsoftHash is the contentHash for Newtonsoft.Json@13.0.3 from a real
// generated lockfile. Stable, verifiable.
const newtonsoftHash = "HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=="

func TestParseNuGetLock_DirectAndTransitive(t *testing.T) {
	path := writeFixture(t, "packages.lock.json", `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "`+newtonsoftHash+`"
      },
      "Microsoft.NETCore.Platforms": {
        "type": "Transitive",
        "resolved": "1.1.0",
        "contentHash": "`+newtonsoftHash+`"
      }
    }
  }
}`)
	got, err := parseNuGetLock(path)
	if err != nil {
		t.Fatalf("parseNuGetLock: %v", err)
	}
	for _, want := range []string{
		"pkg:nuget/Newtonsoft.Json@13.0.3",
		"pkg:nuget/Microsoft.NETCore.Platforms@1.1.0",
	} {
		h, ok := got[want]
		if !ok {
			t.Errorf("missing %q: %v", want, got)
			continue
		}
		if h.Algorithm != AlgSHA512 || len(h.Hex) != 128 {
			t.Errorf("%q: algorithm=%q hexlen=%d", want, h.Algorithm, len(h.Hex))
		}
	}
}

func TestParseNuGetLock_MultipleTargetFrameworks(t *testing.T) {
	// Cross-targeted libraries have one section per TFM. We collect from all.
	path := writeFixture(t, "packages.lock.json", `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Foo": { "type": "Direct", "resolved": "1.0.0", "contentHash": "`+newtonsoftHash+`" }
    },
    "net8.0": {
      "Bar": { "type": "Direct", "resolved": "2.0.0", "contentHash": "`+newtonsoftHash+`" }
    }
  }
}`)
	got, _ := parseNuGetLock(path)
	if _, ok := got["pkg:nuget/Foo@1.0.0"]; !ok {
		t.Error("missing Foo")
	}
	if _, ok := got["pkg:nuget/Bar@2.0.0"]; !ok {
		t.Error("missing Bar")
	}
}

func TestParseNuGetLock_SkipsEmptyHashes(t *testing.T) {
	path := writeFixture(t, "packages.lock.json", `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Empty": { "type": "Direct", "resolved": "1.0.0", "contentHash": "" }
    }
  }
}`)
	got, _ := parseNuGetLock(path)
	if _, ok := got["pkg:nuget/Empty@1.0.0"]; ok {
		t.Errorf("empty contentHash should be skipped, got %v", got)
	}
}

func TestParseNuGetLock_MalformedErrors(t *testing.T) {
	path := writeFixture(t, "packages.lock.json", `{not json`)
	if _, err := parseNuGetLock(path); err == nil {
		t.Error("want error for malformed JSON")
	}
}
