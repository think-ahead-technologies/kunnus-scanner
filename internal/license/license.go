// ABOUTME: Normalizes raw license strings into BSI §6.1-conformant SPDX identifiers, expressions, or LicenseRef fallbacks.
// ABOUTME: Pure string-in / classification-out — no SBOM-format or scanner imports, so it stays reusable and testable.
package license

import (
	"strings"

	"github.com/github/go-spdx/v2/spdxexp"
)

// Kind classifies a normalized license by how it should be expressed in an SBOM.
type Kind int

const (
	// KindID is a single SPDX license identifier (e.g. "MIT").
	KindID Kind = iota
	// KindExpression is a compound SPDX license expression with operators
	// (e.g. "MIT OR Apache-2.0", "GPL-2.0-only WITH Classpath-exception-2.0").
	KindExpression
	// KindCustomRef is a synthesized "LicenseRef-..." identifier for a license
	// that matches no SPDX id and no known alias (BSI §6.1 final fallback).
	KindCustomRef
)

// Normalized is a license ready to be written to an SBOM.
type Normalized struct {
	// Value is the SPDX identifier, SPDX expression, or LicenseRef-... string.
	Value string
	// Kind says how Value should be encoded (id vs expression vs custom ref).
	Kind Kind
}

// refNamespace is the LicenseRef "inventorising entity" per BSI §6.1 — the
// segment that namespaces identifiers we synthesize.
const refNamespace = "kunnus"

// aliases maps common non-SPDX license tags (chiefly rpm/apk License fields) to
// their canonical SPDX identifier. Only unambiguous mappings belong here;
// anything genuinely ambiguous (e.g. a bare "BSD") is left to fall through to a
// LicenseRef so we never assert a license we cannot pin down. Keyed lowercase.
var aliases = map[string]string{
	"gplv2":      "GPL-2.0-only",
	"gplv2+":     "GPL-2.0-or-later",
	"gplv3":      "GPL-3.0-only",
	"gplv3+":     "GPL-3.0-or-later",
	"lgplv2":     "LGPL-2.0-only",
	"lgplv2+":    "LGPL-2.0-or-later",
	"lgplv2.1":   "LGPL-2.1-only",
	"lgplv2.1+":  "LGPL-2.1-or-later",
	"lgplv3":     "LGPL-3.0-only",
	"lgplv3+":    "LGPL-3.0-or-later",
	"asl 2.0":    "Apache-2.0",
	"apache 2.0": "Apache-2.0",
	"mplv2.0":    "MPL-2.0",
	"mplv1.1":    "MPL-1.1",
}

// Normalize converts a raw license string into its BSI §6.1 form. It returns
// ok=false for strings that carry no license assertion ("", "NONE",
// "NOASSERTION"), which callers must omit rather than emit as an empty license.
//
// Resolution order: known alias → valid SPDX (identifier or expression, with
// SPDX-canonical casing for a single identifier) → LicenseRef-<entity>-...
func Normalize(raw string) (Normalized, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Normalized{}, false
	}
	switch strings.ToLower(s) {
	case "none", "noassertion":
		return Normalized{}, false
	}

	if mapped, ok := aliases[strings.ToLower(s)]; ok {
		return Normalized{Value: mapped, Kind: KindID}, true
	}

	if normalized, invalid := spdxexp.ValidateAndNormalizeLicensesWithOptions(
		[]string{s}, spdxexp.ValidateLicensesOptions{},
	); len(invalid) == 0 && len(normalized) > 0 {
		// A compound expression (operators / parentheses) is preserved verbatim
		// so AND/OR/WITH semantics survive; a single identifier uses the
		// SPDX-canonical spelling the validator returned.
		if isExpression(s) {
			return Normalized{Value: s, Kind: KindExpression}, true
		}
		return Normalized{Value: normalized[0], Kind: KindID}, true
	}

	return Normalized{Value: licenseRef(s), Kind: KindCustomRef}, true
}

// isExpression reports whether s uses SPDX expression syntax (operators or
// grouping) rather than being a single identifier.
func isExpression(s string) bool {
	if strings.ContainsAny(s, "()") {
		return true
	}
	upper := strings.ToUpper(s)
	for _, op := range []string{" OR ", " AND ", " WITH "} {
		if strings.Contains(upper, op) {
			return true
		}
	}
	return false
}

// licenseRef builds a LicenseRef-<entity>-<slug> identifier, sanitizing s to the
// SPDX idstring grammar ([a-zA-Z0-9.-]). Runs of disallowed characters collapse
// to a single hyphen so the result stays readable and stable.
func licenseRef(s string) string {
	var b strings.Builder
	b.WriteString("LicenseRef-")
	b.WriteString(refNamespace)
	b.WriteByte('-')
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}
