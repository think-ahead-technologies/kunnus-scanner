package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	// Not parallel: run() calls slog.SetDefault, which is a global.
	tests := []struct {
		name     string
		args     []string
		wantExit int
		wantOut  string
	}{
		{
			name:     "no args shows help",
			args:     []string{"kunnus"},
			wantExit: 0,
			wantOut:  "COMMANDS:",
		},
		{
			name:     "--help exits 0",
			args:     []string{"kunnus", "--help"},
			wantExit: 0,
			wantOut:  "COMMANDS:",
		},
		{
			name:     "--version exits 0",
			args:     []string{"kunnus", "--version"},
			wantExit: 0,
			wantOut:  "kunnus version:",
		},
		{
			name:     "unknown command exits 2",
			args:     []string{"kunnus", "nonexistent"},
			wantExit: 2,
		},
		{
			name:     "sbom --help exits 0",
			args:     []string{"kunnus", "sbom", "--help"},
			wantExit: 0,
			wantOut:  "Examples:",
		},
		{
			name:     "upload --help exits 0",
			args:     []string{"kunnus", "upload", "--help"},
			wantExit: 0,
			wantOut:  "Examples:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			got := run(tc.args, &stdout, &stderr, nil)

			if got != tc.wantExit {
				t.Errorf("exit code: got %d, want %d\nstdout: %s\nstderr: %s",
					got, tc.wantExit, stdout.String(), stderr.String())
			}

			if tc.wantOut != "" && !strings.Contains(stdout.String(), tc.wantOut) {
				t.Errorf("stdout: expected %q in output, got: %q", tc.wantOut, stdout.String())
			}
		})
	}
}
