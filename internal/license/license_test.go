// ABOUTME: Tests license normalization into SPDX identifiers / expressions and LicenseRef fallbacks.
// ABOUTME: Drives the BSI §6.1 cascade: SPDX id -> SPDX expression -> LicenseRef-<entity>-...
package license

import "testing"

func TestNormalize_SPDXIdentifier(t *testing.T) {
	cases := map[string]string{
		"MIT":              "MIT",
		"Apache-2.0":       "Apache-2.0",
		"GPL-2.0-or-later": "GPL-2.0-or-later",
		// Canonicalized casing — the value the SPDX list defines wins.
		"mit":        "MIT",
		"apache-2.0": "Apache-2.0",
	}
	for in, want := range cases {
		got, ok := Normalize(in)
		if !ok {
			t.Errorf("Normalize(%q): ok=false, want true", in)
			continue
		}
		if got.Kind != KindID {
			t.Errorf("Normalize(%q).Kind = %v, want KindID", in, got.Kind)
		}
		if got.Value != want {
			t.Errorf("Normalize(%q).Value = %q, want %q", in, got.Value, want)
		}
	}
}

func TestNormalize_NonSPDXAlias(t *testing.T) {
	// Common rpm/apk License tags that are not valid SPDX identifiers but map
	// unambiguously to one. These MUST resolve to SPDX, not a LicenseRef.
	cases := map[string]string{
		"GPLv2+":    "GPL-2.0-or-later",
		"GPLv2":     "GPL-2.0-only",
		"GPLv3+":    "GPL-3.0-or-later",
		"LGPLv2.1+": "LGPL-2.1-or-later",
		"ASL 2.0":   "Apache-2.0",
	}
	for in, want := range cases {
		got, ok := Normalize(in)
		if !ok || got.Kind != KindID || got.Value != want {
			t.Errorf("Normalize(%q) = (%+v, %v), want {Value:%q Kind:KindID}, true", in, got, ok, want)
		}
	}
}

func TestNormalize_Expression(t *testing.T) {
	for _, in := range []string{"MIT OR Apache-2.0", "(MIT AND BSD-3-Clause)", "GPL-2.0-only WITH Classpath-exception-2.0"} {
		got, ok := Normalize(in)
		if !ok {
			t.Errorf("Normalize(%q): ok=false, want true", in)
			continue
		}
		if got.Kind != KindExpression {
			t.Errorf("Normalize(%q).Kind = %v, want KindExpression", in, got.Kind)
		}
		if got.Value != in {
			t.Errorf("Normalize(%q).Value = %q, want the expression preserved", in, got.Value)
		}
	}
}

func TestNormalize_NoAssertion(t *testing.T) {
	// "UNKNOWN" is what deps.dev returns when it has no licence on file; treat it
	// like NONE/NOASSERTION rather than minting a LicenseRef-kunnus-UNKNOWN.
	for _, in := range []string{"", "  ", "NONE", "NOASSERTION", "noassertion", "none", "UNKNOWN", "unknown"} {
		if got, ok := Normalize(in); ok {
			t.Errorf("Normalize(%q) = (%+v, true), want ok=false", in, got)
		}
	}
}

func TestNormalize_CustomFallback(t *testing.T) {
	// Anything that is neither valid SPDX nor a known alias becomes a
	// LicenseRef-<entity>-... custom identifier, sanitized to the SPDX idstring
	// grammar ([a-zA-Z0-9.-]).
	got, ok := Normalize("Some Proprietary Thing!")
	if !ok {
		t.Fatal("Normalize of a custom license: ok=false, want true")
	}
	if got.Kind != KindCustomRef {
		t.Errorf("Kind = %v, want KindCustomRef", got.Kind)
	}
	want := "LicenseRef-kunnus-Some-Proprietary-Thing"
	if got.Value != want {
		t.Errorf("Value = %q, want %q", got.Value, want)
	}
}

func TestNormalize_UnbalancedParens(t *testing.T) {
	// go-spdx panics (nil-pointer deref) on a dangling open parenthesis, so a
	// package declaring such a malformed licence would take down the scan. These
	// are not valid SPDX expressions, so they belong in the LicenseRef fallback.
	// (Regression for the crash found by FuzzNormalize on "(".)
	for _, in := range []string{"(", ")", "((", "(MIT", "MIT)", "(MIT OR Apache-2.0"} {
		got, ok := Normalize(in)
		if !ok {
			t.Errorf("Normalize(%q): ok=false, want true", in)
			continue
		}
		if got.Kind != KindCustomRef {
			t.Errorf("Normalize(%q).Kind = %v, want KindCustomRef", in, got.Kind)
		}
	}
}
