// ABOUTME: Stage: rewrites emitted PURLs into the conventional, portable form before the SBOM is written.
// ABOUTME: Decodes scalibr's over-escaped separators — the namespace %2F (npm @scope, composer vendor) and the Debian epoch %3A — to "/" and ":".
package sbom

import (
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// normalizePURLsCDX rewrites every component's PackageURL into the conventional
// purl form. Scalibr over-escapes two separators: a namespaced package's
// "@scope/name" / "vendor/package" arrives as a single name segment with the
// slash escaped (pkg:npm/%40isaacs%2Fcliui) instead of a distinct "/"-joined
// segment (pkg:npm/%40isaacs/cliui), and a Debian epoch arrives as
// "1%3A2.41-5" instead of the spec's "1:2.41-5". Downstream tools that key on
// the bare purl string treat the escaped and unescaped forms as different
// packages, so we emit the conventional one.
//
// This runs LAST in the encode pipeline: every purl-keyed step (dedup,
// enrichment, hash injection, dep graph) has already matched on scalibr's
// original strings, so rewriting here is a pure output transform with no risk of
// breaking those joins. Only PackageURL is touched; the opaque bom-ref is left
// as-is.
func normalizePURLsCDX(bom *cyclonedx.BOM) {
	forEachComponent(bom, func(c *cyclonedx.Component) {
		if c.PackageURL != "" {
			c.PackageURL = normalizePURL(c.PackageURL)
		}
	})
}

// normalizePURL rewrites a scalibr-emitted purl into the conventional form,
// decoding two over-escaped separators while leaving qualifiers and subpath
// untouched:
//
//   - in the path ("pkg:type/namespace/name"), %2F → "/" so a namespaced
//     package's namespace is a distinct segment (npm @scope, composer vendor);
//   - in the version (after "@"), %3A → ":" so a Debian epoch reads "1:2.41-5",
//     matching the purl-spec deb example rather than "1%3A2.41-5".
//
// Qualifiers (after "?") and subpath (after "#") keep their encoding, since a
// %2F or %3A there is meaningful data, not a separator.
func normalizePURL(purl string) string {
	// Peel off qualifiers/subpath first so we never rewrite their contents.
	tail := ""
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		tail, purl = purl[i:], purl[:i]
	}
	// Split the remaining "pkg:type/path@version" at the version separator.
	path, version := purl, ""
	if i := strings.IndexByte(purl, '@'); i >= 0 {
		path, version = purl[:i], purl[i:] // version retains its leading "@"
	}
	path = strings.ReplaceAll(path, "%2F", "/")
	path = strings.ReplaceAll(path, "%2f", "/")
	version = strings.ReplaceAll(version, "%3A", ":")
	version = strings.ReplaceAll(version, "%3a", ":")
	return path + version + tail
}
