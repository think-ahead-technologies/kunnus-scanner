// ABOUTME: Stage: synthesises CPE 2.3 strings from PURLs for components scalibr left without one.
// ABOUTME: Bridges the gap between our PURL-first SBOMs and legacy CPE-only vuln matchers.
package sbom

import (
	"net/url"
	"regexp"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// injectCPEsCDX fills in Component.CPE for any component that has a PURL but
// no CPE yet. Scalibr only emits CPEs for packages that came from a parsed
// SBOM input; for everything else we synthesise one.
func injectCPEsCDX(bom *cyclonedx.BOM) {
	forEachComponent(bom, func(c *cyclonedx.Component) {
		if c.CPE != "" || c.PackageURL == "" {
			return
		}
		if cpe := cpeFromPURL(c.PackageURL); cpe != "" {
			c.CPE = cpe
		}
	})
}

// cpeFromPURL returns a CPE 2.3 string derived from a PURL, or "" if the PURL
// is malformed or empty. The mapping is heuristic and per-ecosystem — it aims
// to match conventional NVD CPE forms, not to be canonically correct. Tools
// that want CPE accuracy beyond this should consult the NVD CPE dictionary
// directly.
//
// PURL syntax we accept: pkg:<type>/<namespace>/.../<name>@<version>[?qualifiers]
func cpeFromPURL(rawPURL string) string {
	t, namespace, name, version, ok := parsePURL(rawPURL)
	if !ok {
		return ""
	}

	part := "a"
	var vendor, product string

	switch t {
	case "golang":
		vendor, product = goVendorProduct(namespace, name)
		// NVD convention drops the Go "v" prefix from semver versions.
		version = strings.TrimPrefix(version, "v")
	case "npm":
		if namespace != "" {
			vendor = strings.TrimPrefix(namespace, "@")
			product = name
		} else {
			vendor, product = name, name
		}
	case "pypi", "cargo", "gem", "nuget":
		vendor, product = name, name
	case "maven":
		// Maven groupIds are dotted (e.g. "org.springframework"); the last
		// dot-separated segment is the conventional vendor on the NVD.
		vendor = lastDotSegment(namespace)
		product = name
	case "composer":
		vendor = namespace
		product = name
	case "deb", "rpm", "apk", "alpm":
		part = "o"
		vendor = namespace
		product = name
	default:
		vendor, product = name, name
	}

	if product == "" {
		return ""
	}

	v := version
	if v == "" {
		v = "*"
	}
	out := formatCPE23(part, vendor, product, v)
	// Defensive: if a future ecosystem mapping ever produces a malformed
	// CPE, drop it rather than emit garbage into the SBOM.
	if !isValidCPE23(out) {
		return ""
	}
	return out
}

// isValidCPE23 reports whether s matches the CPE 2.3 formatted-string grammar
// defined in NIST IR 7695 section 6.2. The check is structural plus a
// per-field character allow-list — sufficient to catch malformed output we
// might generate, not a substitute for the official MITRE reference parser.
func isValidCPE23(s string) bool {
	if !strings.HasPrefix(s, "cpe:2.3:") {
		return false
	}

	// 13 colon-separated fields total: "cpe", "2.3", part, plus 10 component
	// fields. Splitting naively works because we never emit unescaped colons
	// (cpeField substitutes them), and properly escaped colons in input
	// (\:) survive Split because we don't have any in our codepath.
	parts := splitCPEFields(s)
	if len(parts) != 13 {
		return false
	}
	if parts[0] != "cpe" || parts[1] != "2.3" {
		return false
	}
	switch parts[2] {
	case "a", "o", "h", "*", "-":
	default:
		return false
	}
	for _, f := range parts[3:] {
		if !cpe23FieldRe.MatchString(f) {
			return false
		}
	}
	return true
}

// splitCPEFields splits a CPE 2.3 formatted string on unescaped ":" boundaries.
// A "\:" sequence is treated as a literal colon inside a field, not a separator.
func splitCPEFields(s string) []string {
	var out []string
	var cur strings.Builder
	escape := false
	for _, r := range s {
		switch {
		case escape:
			cur.WriteRune('\\')
			cur.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case r == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if escape {
		// trailing backslash — leave as-is for the regex to reject
		cur.WriteRune('\\')
	}
	out = append(out, cur.String())
	return out
}

// cpe23FieldRe accepts any single CPE 2.3 component value:
//   - "*" (ANY) or "-" (NA) alone, or
//   - a body composed of unreserved chars (letters, digits, ., -, _, ~, %),
//     standalone wildcards (* or ?), or escape sequences (\ + special char).
//
// Whitespace and control characters are rejected.
var cpe23FieldRe = regexp.MustCompile(
	`^(?:[*-]|(?:\\[!-/:-@\[-` + "`" + `{-~]|[A-Za-z0-9._\-~%*?])+)$`,
)

// goVendorProduct picks vendor and product from a Go module path.
//
// Rules:
//   - "stdlib" is a sentinel for the Go standard library: vendor=golang, product=go
//   - For hosts like "github.com" or "gitlab.com", the next segment is the vendor
//     and the final segment is the product (e.g. github.com/google/uuid → google/uuid)
//   - Otherwise the namespace's last segment is the vendor and the package name is
//     the product (e.g. deps.dev/util/maven → util/maven)
//   - Bare modules with no namespace use the module name as both vendor and product
func goVendorProduct(namespace, name string) (string, string) {
	if namespace == "" && name == "stdlib" {
		return "golang", "go"
	}
	if namespace == "" {
		return name, name
	}
	segs := strings.Split(namespace, "/")
	// For github/gitlab/bitbucket-style hosts, the first segment is the host.
	if len(segs) >= 2 && isCodeHost(segs[0]) {
		return segs[1], name
	}
	return lastPathSegment(namespace), name
}

func isCodeHost(host string) bool {
	switch host {
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht":
		return true
	}
	return false
}

func lastPathSegment(p string) string {
	if p == "" {
		return ""
	}
	segs := strings.Split(p, "/")
	return segs[len(segs)-1]
}

func lastDotSegment(p string) string {
	if p == "" {
		return ""
	}
	segs := strings.Split(p, ".")
	return segs[len(segs)-1]
}

// formatCPE23 assembles a CPE 2.3 formatted string. The field separator `:`
// and escape char `\` are substituted with the wildcard `*` (see cpeField);
// every other character the grammar forbids unquoted is backslash-escaped.
func formatCPE23(part, vendor, product, version string) string {
	return "cpe:2.3:" + part + ":" + cpeField(vendor) + ":" + cpeField(product) + ":" + cpeField(version) + ":*:*:*:*:*:*:*"
}

func cpeField(s string) string {
	if s == "" {
		return "*"
	}
	// Lowercase per CPE convention, then backslash-escape every character the
	// CPE 2.3 formatted-string grammar forbids unquoted. That covers the field
	// separator ':' (a Debian epoch "1:2.41-5" -> "1\:2.41-5"), the escape char
	// '\', and '+' (pervasive in deb/rpm versions, "1.34+dfsg" -> "1.34\+dfsg").
	// Escaping rather than substituting with '*' keeps the literal value and is
	// the form CPE consumers actually accept — an embedded '*' is rejected as a
	// malformed wildcard.
	return escapeCPESpecials(strings.ToLower(s))
}

// escapeCPESpecials backslash-escapes every character that is not allowed
// unquoted in a CPE 2.3 formatted-string component. The unreserved set mirrors
// isValidCPE23's per-field grammar; '*' and '?' pass through as wildcards.
func escapeCPESpecials(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !cpeUnreserved(r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func cpeUnreserved(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '.', '_', '-', '~', '%', '*', '?':
		return true
	}
	return false
}

// parsePURL is a minimal PURL parser sufficient for our CPE-generation needs.
// We do not validate every PURL spec quirk — we extract type, namespace, name,
// and version. Qualifiers and subpaths are discarded.
func parsePURL(raw string) (purlType, namespace, name, version string, ok bool) {
	if !strings.HasPrefix(raw, "pkg:") {
		return "", "", "", "", false
	}
	rest := strings.TrimPrefix(raw, "pkg:")

	// Drop qualifiers and subpaths.
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}

	// Split version from the rest at the last "@" (since versions can't contain "@").
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		version = decode(rest[at+1:])
		rest = rest[:at]
	}

	// rest is now <type>/<namespace>/.../<name>
	segs := strings.Split(rest, "/")
	if len(segs) == 0 || segs[0] == "" {
		return "", "", "", "", false
	}
	purlType = strings.ToLower(segs[0])
	if len(segs) == 1 {
		return "", "", "", "", false
	}

	pathSegs := segs[1:]
	name = decode(pathSegs[len(pathSegs)-1])
	if len(pathSegs) > 1 {
		namespace = decode(strings.Join(pathSegs[:len(pathSegs)-1], "/"))
	}

	// A namespaced name that arrived as a single percent-encoded segment
	// (scalibr renders "@scope/name" for npm and "vendor/package" for composer
	// with the separator escaped as %2F) decodes to a name containing "/".
	// Split it back so callers get the conventional namespace + name.
	if namespace == "" {
		if i := strings.IndexByte(name, '/'); i >= 0 {
			namespace, name = name[:i], name[i+1:]
		}
	}
	return purlType, namespace, name, version, name != ""
}

// decode percent-decodes a single PURL segment. Errors are swallowed since
// PURL spec only allows a small set of percent-encoded characters; on failure
// we fall back to the raw value.
func decode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if dec, err := url.QueryUnescape(s); err == nil {
		return dec
	}
	return s
}
