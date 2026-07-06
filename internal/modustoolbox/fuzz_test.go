// ABOUTME: Fuzz target for the .mtb manifest line parser — feeds arbitrary lines and checks the non-nil contract.
// ABOUTME: parseLine must never panic and, when it returns a ref, both name and version must be populated.
package modustoolbox

import "testing"

// FuzzParseLine drives parseLine with arbitrary manifest lines. The invariant is
// the parser's own contract: a non-nil ref always carries a non-empty owner/repo
// name and a non-empty git ref (a partially-filled ref would produce a malformed
// PURL). Blank, non-github, and truncated lines must return nil, not panic.
func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"",
		"   ",
		"https://github.com/Infineon/cmsis#release-v6.1.0#$$ASSET_REPO$$/cmsis/release-v6.1.0",
		"https://github.com/lwip-tcpip/lwip.git#STABLE-2_1_2_RELEASE#loc",
		"https://github.com/owner/repo/tree/main#v1.0#loc",
		"https://github.com/Infineon/device-db#release-v4.37.0#$$GLOBAL$$/device-db",
		"https://github.com/#ref#loc",
		"https://gitlab.com/owner/repo#ref#loc",
		"not a url # ref # loc",
		"https://github.com/owner/repo",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		ref := parseLine(line)
		if ref == nil {
			return
		}
		if ref.name == "" {
			t.Fatalf("parseLine(%q) returned non-nil ref with empty name: %+v", line, *ref)
		}
		if ref.version == "" {
			t.Fatalf("parseLine(%q) returned non-nil ref with empty version: %+v", line, *ref)
		}
	})
}
