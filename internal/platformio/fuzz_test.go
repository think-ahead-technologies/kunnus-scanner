// ABOUTME: Fuzz targets for the platformio.ini scanner and lib_deps entry parser — arbitrary input must never panic.
// ABOUTME: parseEntry must only return specs with a known purl type and a non-empty name; parseINI entries must be non-blank.
package platformio

import (
	"strings"
	"testing"
)

// FuzzParseINI drives parseINI with arbitrary config bytes. Returned entries
// must be non-blank and never comment lines — anything else means the section
// scanner leaked structure into the entry list.
func FuzzParseINI(f *testing.F) {
	seeds := []string{
		"",
		"[env:a]\nlib_deps = X@1.0\n",
		"[env:a]\nlib_deps =\n    X@1.0\n    Y\nbuild_flags = -Os\n",
		"[env:a]\nlib_deps =\n; comment\n    X\n",
		"lib_deps",
		"lib_deps =",
		"[lib_deps]\n= x\n",
		"\tindented first line\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		entries, _ := parseINI(strings.NewReader(data))
		for _, e := range entries {
			if strings.TrimSpace(e) == "" {
				t.Fatalf("parseINI(%q) returned blank entry", data)
			}
			if strings.HasPrefix(e, ";") || strings.HasPrefix(e, "#") {
				t.Fatalf("parseINI(%q) returned comment entry %q", data, e)
			}
		}
	})
}

// FuzzParseEntry drives parseEntry with arbitrary lib_deps entries. A non-nil
// spec must carry a known PURL type and a non-empty name, and a github name
// must be owner/repo namespaced.
func FuzzParseEntry(f *testing.F) {
	seeds := []string{
		"",
		"PubSubClient@2.8",
		"bblanchon/ArduinoJson @ ~5.6,!=5.4",
		"https://github.com/me-no-dev/AsyncTCP.git#v1.1.1",
		"git+https://github.com/owner/repo#main",
		"file://../local-lib",
		"${common.lib_deps}",
		"@1.0",
		":////#",
		"https://example.com/mylib.zip",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, entry string) {
		p := parseEntry(entry)
		if p == nil {
			return
		}
		if p.name == "" {
			t.Fatalf("parseEntry(%q) returned spec with empty name: %+v", entry, *p)
		}
		switch p.purlType {
		case "generic":
		case "github":
			if !strings.Contains(p.name, "/") {
				t.Fatalf("parseEntry(%q) = github/%q without owner namespace", entry, p.name)
			}
		default:
			t.Fatalf("parseEntry(%q) has unknown purl type %q", entry, p.purlType)
		}
	})
}
