// ABOUTME: Tests that an unknown subcommand names itself and lists the valid ones.
// ABOUTME: Guards against urfave/cli's default "No help topic for 'x'" leaking back in.
package command

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestUnknownSubcommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		wantWord []string
	}{
		{
			name:     "sbom with an image reference instead of a subcommand",
			args:     []string{"kunnus", "sbom", "ghcr.io/think-ahead-technologies/kunnus-scanner:v1.0.0"},
			wantErr:  true,
			wantWord: []string{"ghcr.io/think-ahead-technologies/kunnus-scanner:v1.0.0", "kunnus sbom", "repo", "os", "container", "image"},
		},
		{
			name:     "unknown command at the root",
			args:     []string{"kunnus", "bogus"},
			wantErr:  true,
			wantWord: []string{"bogus", "kunnus", "sbom", "upload"},
		},
		// The help command is machinery, not a scan flavour — listing it would
		// invite `kunnus sbom help` as if it were a fourth mode.
		{
			name:     "suggestion omits the built-in help command",
			args:     []string{"kunnus", "sbom", "bogus"},
			wantErr:  true,
			wantWord: []string{"container"},
		},
		// Regression guards: dispatch must still work, including via alias.
		{name: "alias still dispatches", args: []string{"kunnus", "sbom", "image", "--help"}},
		{name: "bare parent shows help", args: []string{"kunnus", "sbom"}},
		{name: "bare root shows help", args: []string{"kunnus"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			app := newApp("", "")
			app.Writer = &out
			app.ErrWriter = &out

			err := app.Run(context.Background(), tc.args)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Run(%q): unexpected error %v", tc.args, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Run(%q): want error, got none (output %q)", tc.args, out.String())
			}
			if strings.Contains(err.Error(), "No help topic") {
				t.Errorf("Run(%q): got urfave/cli's default message: %v", tc.args, err)
			}
			for _, word := range tc.wantWord {
				if !strings.Contains(err.Error(), word) {
					t.Errorf("Run(%q) error %q: missing %q", tc.args, err, word)
				}
			}
			if strings.Contains(err.Error(), "help") {
				t.Errorf("Run(%q) error %q: lists the built-in help command", tc.args, err)
			}
		})
	}
}
