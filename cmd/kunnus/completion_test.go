// ABOUTME: End-to-end tests for shell completion against the real kunnus binary.
// ABOUTME: Covers the installable scripts and the sentinel protocol those scripts invoke.
package main_test

import (
	"slices"
	"strings"
	"testing"
)

// completionSentinel is the flag every generated script appends to ask the
// binary for candidates. Completing it end-to-end means running the binary
// exactly as the shell function does.
const completionSentinel = "--generate-shell-completion"

func TestCLI_Completion_Scripts(t *testing.T) {
	// The bash, zsh and fish scripts are rendered with the command name baked
	// in. The powershell one instead derives it from the filename it is saved
	// as, so it carries no "kunnus" of its own — hence the install docs telling
	// powershell users to name the file kunnus.ps1.
	shells := map[string]bool{"bash": true, "zsh": true, "fish": true, "pwsh": false}

	for shell, namesCommand := range shells {
		t.Run(shell, func(t *testing.T) {
			stdout, _, err := runKunnus(t, "completion", shell)
			if err != nil {
				t.Fatalf("completion %s: %v", shell, err)
			}
			if !strings.Contains(stdout, completionSentinel) {
				t.Errorf("completion %s: script never calls the binary for candidates\n%s", shell, stdout)
			}
			if namesCommand && !strings.Contains(stdout, "kunnus") {
				t.Errorf("completion %s: script is not bound to the kunnus command\n%s", shell, stdout)
			}
		})
	}
}

func TestCLI_Completion_Candidates(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		want  []string
	}{
		{
			name: "root offers its subcommands",
			want: []string{"sbom", "upload"},
		},
		{
			name:  "sbom offers every subcommand spelling",
			words: []string{"sbom"},
			want:  []string{"repo", "os", "container", "image"},
		},
		{
			name:  "root flags",
			words: []string{"--verb"},
			want:  []string{"--verbosity"},
		},
		{
			name:  "leaf flags",
			words: []string{"sbom", "container", "--"},
			want:  []string{"--source", "--output"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := completionTokens(t, tc.words...)
			for _, want := range tc.want {
				if !slices.Contains(got, want) {
					t.Errorf("completion %q = %v, missing %q", tc.words, got, want)
				}
			}
		})
	}
}

// TestCLI_Completion_LeafFallsBackToFiles pins the behaviour the scripts rely
// on: they complete file paths only when the binary offers no candidates at
// all. `sbom repo` takes a directory, so it must stay silent.
func TestCLI_Completion_LeafFallsBackToFiles(t *testing.T) {
	for _, words := range [][]string{{"sbom", "repo"}, {"sbom", "image"}, {"upload"}} {
		if got := completionTokens(t, words...); len(got) != 0 {
			t.Errorf("completion %q = %v, want no candidates so the shell completes paths", words, got)
		}
	}
}

func TestCLI_Completion_OmitsHelpCommand(t *testing.T) {
	for _, words := range [][]string{nil, {"sbom"}, {"sbom", "repo"}} {
		if got := completionTokens(t, words...); slices.Contains(got, "help") {
			t.Errorf("completion %q = %v, offers the built-in help command", words, got)
		}
	}
}

// completionTokens runs the binary the way a completion script does and
// returns the bare tokens from its `token:description` lines.
func completionTokens(t *testing.T, words ...string) []string {
	t.Helper()
	stdout, _, err := runKunnus(t, append(slices.Clone(words), completionSentinel)...)
	if err != nil {
		t.Fatalf("completion %q: %v", words, err)
	}
	var tokens []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line == "" {
			continue
		}
		tokens = append(tokens, strings.SplitN(line, ":", 2)[0])
	}
	return tokens
}
