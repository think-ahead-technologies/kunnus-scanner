// ABOUTME: Tests for flag-value parsing helpers shared by the sbom subcommands.
// ABOUTME: Covers parseAuthor's "Name <email>" grammar and its error cases.
package command

import "testing"

func TestParseAuthor(t *testing.T) {
	tests := []struct {
		in        string
		wantName  string
		wantEmail string
		wantErr   bool
	}{
		{in: "", wantName: "", wantEmail: ""},
		{in: "ACME GmbH", wantName: "ACME GmbH"},
		{in: "ACME GmbH <psirt@acme.example>", wantName: "ACME GmbH", wantEmail: "psirt@acme.example"},
		{in: "  ACME GmbH   <psirt@acme.example> ", wantName: "ACME GmbH", wantEmail: "psirt@acme.example"},
		// An email with no name is not a CISA-conformant author name.
		{in: "<psirt@acme.example>", wantErr: true},
		// Unclosed bracket is a typo worth failing loudly on.
		{in: "ACME <psirt@acme.example", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseAuthor(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseAuthor(%q): want error, got %+v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseAuthor(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got.Name != tc.wantName || got.Email != tc.wantEmail {
			t.Errorf("parseAuthor(%q) = %+v, want {Name:%q Email:%q}", tc.in, got, tc.wantName, tc.wantEmail)
		}
	}
}
