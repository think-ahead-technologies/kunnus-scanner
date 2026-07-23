// ABOUTME: Stage: synthesises CPE 2.3 strings from PURLs (or kernel-image metadata) for components scalibr left without one.
// ABOUTME: Bridges the gap between our PURL-first SBOMs and legacy CPE-only vuln matchers.
package sbom

import (
	"net/url"
	"regexp"
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	vmlinuzmeta "github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz/metadata"
	"github.com/google/osv-scalibr/inventory"

	"github.com/think-ahead/kunnus-scanner/internal/binclass"
)

// injectCPEsCDX fills in Component.CPE for any component that has a PURL but
// no CPE yet. Components surfaced by the binary classifier carry curated CPE
// templates (ported from syft's catalog) in their package metadata; those are
// authoritative, so the detected version is rendered into them first. For
// everything else — scalibr only emits CPEs for packages that came from a
// parsed SBOM input — we synthesise one from the PURL.
//
// Kernel image components (scalibr's os/kernel/vmlinuz) are the one purl-less
// case that still has a CPE identity: NVD keys kernel CVEs on
// cpe:2.3:o:linux:linux_kernel:<upstream release>. They are recognised by
// their vmlinuz metadata in the inventory (joined back to the component by
// name+version, the same identity the converter copied). Kernel modules
// (os/kernel/module) get nothing: an in-tree module has no NVD identity of
// its own — its CVEs are filed against the kernel.
func injectCPEsCDX(bom *cyclonedx.BOM, inv inventory.Inventory) {
	kernels := kernelImageVersions(inv)
	byPURL := indexInventoryByPURL(inv)
	forEachComponent(bom, func(c *cyclonedx.Component) {
		if c.CPE != "" {
			return
		}
		if c.PackageURL == "" {
			if kernels[c.Name+"@"+c.Version] {
				if cpe := kernelCPE(c.Version); cpe != "" {
					c.CPE = cpe
				}
			}
			return
		}
		if applyClassifierCPEs(c, byPURL[c.PackageURL]) {
			return
		}
		if cpe := cpeFromPURL(c.PackageURL); cpe != "" {
			c.CPE = cpe
		}
	})
}

// kernelImageVersions indexes the packages the vmlinuz extractor produced by
// "name@version", the identity available on a purl-less CDX component.
func kernelImageVersions(inv inventory.Inventory) map[string]bool {
	set := make(map[string]bool)
	for _, p := range inv.Packages {
		if p == nil {
			continue
		}
		if _, ok := p.Metadata.(*vmlinuzmeta.Metadata); ok {
			set[p.Name+"@"+p.Version] = true
		}
	}
	return set
}

// kernelUpstreamRe matches the leading dotted-numeric release of a kernel
// version string ("6.8.0" in "6.8.0-49-generic").
var kernelUpstreamRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*`)

// kernelCPE returns the NVD dictionary form for a kernel image version. NVD
// keys kernel CVEs on the upstream release, so a distro-suffixed version is
// truncated to its leading numeric release (the full version stays on the
// component). No numeric release means no CPE — a wildcard-version kernel CPE
// would match every kernel CVE ever filed.
func kernelCPE(version string) string {
	upstream := kernelUpstreamRe.FindString(version)
	if upstream == "" {
		return ""
	}
	out := formatCPE23("o", "linux", "linux_kernel", upstream)
	if !isValidCPE23(out) {
		return ""
	}
	return out
}

// applyClassifierCPEs renders the binary classifier's CPE templates for the
// first matching package that carries any, setting the first rendered CPE on
// the component and recording the rest as kunnus:cpe alias properties (CDX has
// a single cpe field, but the catalog deliberately lists NVD vendor aliases —
// e.g. redislabs and redis). Returns false — caller falls back to the PURL
// heuristic — when no package carries templates or every template is
// malformed.
func applyClassifierCPEs(c *cyclonedx.Component, pkgs []*extractor.Package) bool {
	for _, p := range pkgs {
		md, ok := p.Metadata.(*binclass.Metadata)
		if !ok || len(md.CPEs) == 0 {
			continue
		}
		var rendered []string
		for _, tmpl := range md.CPEs {
			if cpe := renderCPETemplate(tmpl, p.Version); cpe != "" {
				rendered = append(rendered, cpe)
			}
		}
		if len(rendered) == 0 {
			return false
		}
		c.CPE = rendered[0]
		appendCPEAliasProperties(c, rendered[1:])
		return true
	}
	return false
}

// appendCPEAliasProperties records each CPE as a repeated kunnus:cpe property.
// applyBSIProps is not reused here: it takes a map, and alias properties share
// one name. A no-op when cpes is empty.
func appendCPEAliasProperties(c *cyclonedx.Component, cpes []string) {
	if len(cpes) == 0 {
		return
	}
	additions := make([]cyclonedx.Property, 0, len(cpes))
	for _, cpe := range cpes {
		additions = append(additions, cyclonedx.Property{Name: cpePropAlias, Value: cpe})
	}
	if c.Properties == nil {
		c.Properties = &additions
		return
	}
	combined := append(*c.Properties, additions...)
	c.Properties = &combined
}

// renderCPETemplate renders a detected version into a catalog CPE 2.3
// template. A template is a full formatted string whose version slot (field 5)
// is the "*" placeholder; the version is escaped and lowercased like every
// other field we emit, and an empty version keeps the wildcard. Anything that
// is not a well-formed template — wrong field count, a concrete version slot
// that is not ours to clobber, or a render that fails the CPE 2.3 grammar —
// yields "" so the caller can fall back to the PURL heuristic.
func renderCPETemplate(tmpl, version string) string {
	fields := splitCPEFields(tmpl)
	if len(fields) != 13 || fields[5] != "*" {
		return ""
	}
	if version != "" {
		fields[5] = cpeField(version)
	}
	out := strings.Join(fields, ":")
	if !isValidCPE23(out) {
		return ""
	}
	return out
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
