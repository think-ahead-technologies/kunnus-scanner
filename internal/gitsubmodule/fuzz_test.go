// ABOUTME: Fuzz targets for the .gitmodules parser and remote-URL classifier — arbitrary input must never panic.
// ABOUTME: parseGitmodules must only return stanzas with path+url; classifyURL must only return a github/generic type with a non-empty name.
package gitsubmodule

import (
	"strings"
	"testing"
)

// FuzzParseGitmodules drives parseGitmodules with arbitrary manifest bytes. The
// invariant is the parser's own contract: every returned stanza carries a
// non-empty path and url. Malformed git-config syntax must return nil, not
// panic.
func FuzzParseGitmodules(f *testing.F) {
	seeds := []string{
		"",
		"[submodule \"fmt\"]\n\tpath = libs/fmt\n\turl = https://github.com/fmtlib/fmt.git\n",
		"[submodule \"x\"]\n\tpath = a\n",
		"[submodule \"x\"]\n\turl = https://example.com/a.git\n",
		"[core]\n\tbare = false\n",
		"[submodule",
		"path = a\nurl = b\n",
		"[submodule \"a\"][submodule \"b\"]",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		for _, s := range parseGitmodules(strings.NewReader(data)) {
			if s.path == "" || s.url == "" {
				t.Fatalf("parseGitmodules(%q) returned incomplete stanza: %+v", data, s)
			}
		}
	})
}

// FuzzClassifyURL drives classifyURL with arbitrary remote URLs. A non-empty
// name must come with a known PURL type, and a github name must be the
// namespaced owner/repo form (an un-namespaced github name would render a
// malformed purl).
func FuzzClassifyURL(f *testing.F) {
	seeds := []string{
		"",
		"https://github.com/fmtlib/fmt.git",
		"git@github.com:FreeRTOS/FreeRTOS-Kernel.git",
		"ssh://git@github.com/owner/repo.git",
		"https://gitlab.example.com/group/sdk.git",
		"../shared/libfoo.git",
		"///",
		"git@github.com:",
		"https://github.com/onlyowner",
		"::::",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		purlType, name := classifyURL(raw)
		if name == "" {
			return
		}
		switch purlType {
		case "generic":
		case "github":
			if !strings.Contains(name, "/") {
				t.Fatalf("classifyURL(%q) = github/%q without owner namespace", raw, name)
			}
		default:
			t.Fatalf("classifyURL(%q) = %q/%q, unknown purl type", raw, purlType, name)
		}
	})
}
