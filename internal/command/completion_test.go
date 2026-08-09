// ABOUTME: Tests the shell-completion candidates each command offers.
// ABOUTME: Drives the real command tree through cli with the completion sentinel.
package command

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
)

// complete runs the real command tree the way a generated completion script
// does: the words typed so far, then the sentinel flag cli watches for.
func complete(t *testing.T, words ...string) []string {
	t.Helper()

	var out bytes.Buffer
	app := newApp("", "")
	app.Writer = &out
	app.ErrWriter = &out

	args := append([]string{"kunnus"}, words...)
	args = append(args, "--generate-shell-completion")
	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("completion for %q: unexpected error %v", words, err)
	}

	var tokens []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		// Lines are "token:description"; only the token is completed.
		tokens = append(tokens, strings.SplitN(line, ":", 2)[0])
	}
	return tokens
}

func TestCompleteSubcommands(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		want  []string
	}{
		{
			name: "root offers its subcommands",
			want: []string{"sbom", "upload"},
		},
		// `container` and `image` both dispatch, so both must complete.
		{
			name:  "sbom offers every subcommand spelling",
			words: []string{"sbom"},
			want:  []string{"repo", "os", "container", "image"},
		},
		// A leaf takes a path, not a subcommand. Offering nothing lets the
		// shell fall back to its own file completion.
		{
			name:  "leaf offers nothing",
			words: []string{"sbom", "repo"},
			want:  nil,
		},
		{
			name:  "alias resolves to the same leaf",
			words: []string{"sbom", "image"},
			want:  nil,
		},
		{
			name:  "upload offers nothing",
			words: []string{"upload"},
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := complete(t, tc.words...)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("complete(%q) = %v, want %v", tc.words, got, tc.want)
			}
		})
	}
}

func TestCompleteOmitsHelpCommand(t *testing.T) {
	for _, words := range [][]string{nil, {"sbom"}, {"sbom", "repo"}} {
		for _, token := range complete(t, words...) {
			if token == "help" || token == "h" {
				t.Errorf("complete(%q): offers the built-in help command", words)
			}
		}
	}
}

func TestCompleteFlags(t *testing.T) {
	// A dashed word asks for flags, not subcommands. The shells filter the
	// list by what has been typed, so every flag of the current command is
	// offered regardless of the partial word.
	tests := []struct {
		name  string
		words []string
		want  string
	}{
		{name: "root", words: []string{"--verb"}, want: "--verbosity"},
		{name: "leaf", words: []string{"sbom", "repo", "--out"}, want: "--output"},
		{name: "leaf reached by alias", words: []string{"sbom", "image", "--"}, want: "--source"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := complete(t, tc.words...)
			if len(got) == 0 {
				t.Fatalf("complete(%q): no flag candidates", tc.words)
			}
			for _, token := range got {
				if !strings.HasPrefix(token, "-") {
					t.Errorf("complete(%q): %q is not a flag", tc.words, token)
				}
			}
			if !slices.Contains(got, tc.want) {
				t.Errorf("complete(%q) = %v, want %q among the candidates", tc.words, got, tc.want)
			}
		})
	}
}
