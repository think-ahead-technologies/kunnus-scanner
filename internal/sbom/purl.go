// ABOUTME: Stage: rewrites emitted PURLs into the conventional, portable form before the SBOM is written.
// ABOUTME: Scalibr escapes the namespace separator as %2F for namespaced packages (npm @scope, composer vendor); we decode it back to "/".
package sbom

import (
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// normalizePURLsCDX rewrites every component's PackageURL into the conventional
// purl form. Scalibr renders a namespaced package's "@scope/name" or
// "vendor/package" as a single name segment with the separator escaped as %2F
// (e.g. pkg:npm/%40isaacs%2Fcliui); the purl spec models the namespace as a
// distinct, "/"-joined path segment (pkg:npm/%40isaacs/cliui). Downstream tools
// that key on the bare purl string treat the two forms as different packages,
// so we emit the conventional one.
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

// normalizePURL decodes the percent-encoded namespace separator (%2F) within a
// purl's path — the "pkg:type/namespace/name" portion before the version,
// qualifiers, or subpath. The version (after "@"), qualifiers (after "?"), and
// subpath (after "#") are left untouched, since a %2F there is meaningful data
// rather than an escaped namespace separator.
func normalizePURL(purl string) string {
	end := len(purl)
	if i := strings.IndexAny(purl, "@?#"); i >= 0 {
		end = i
	}
	path := purl[:end]
	path = strings.ReplaceAll(path, "%2F", "/")
	path = strings.ReplaceAll(path, "%2f", "/")
	return path + purl[end:]
}
