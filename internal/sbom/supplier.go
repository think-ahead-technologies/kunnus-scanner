// ABOUTME: Heuristic supplier-identity derivation from PURLs.
// ABOUTME: BSI conformance wants every component to carry a supplier email or URL; we synthesise one.
package sbom

import "strings"

// supplierEntry holds one supplier's display name and canonical URL.
type supplierEntry struct {
	Name string
	URL  string
}

// purlSuppliers maps a PURL type to the function that derives a supplier
// from that type's (namespace, name) pair. Adding an ecosystem is a one-line
// map entry; the dispatcher (supplierFromPURL) doesn't change.
var purlSuppliers = map[string]func(namespace, name string) (string, string){
	"golang": goSupplier,
	"npm":    npmSupplier,
	"pypi":   func(_, name string) (string, string) { return name, "https://pypi.org/project/" + name + "/" },
	"maven": func(ns, name string) (string, string) {
		return ns, "https://central.sonatype.com/artifact/" + ns + "/" + name
	},
	"nuget":    func(_, name string) (string, string) { return name, "https://www.nuget.org/packages/" + name },
	"cargo":    func(_, name string) (string, string) { return name, "https://crates.io/crates/" + name },
	"composer": func(ns, name string) (string, string) { return ns, "https://packagist.org/packages/" + ns + "/" + name },
	"gem":      func(_, name string) (string, string) { return name, "https://rubygems.org/gems/" + name },
	"deb":      func(ns, _ string) (string, string) { return distroSupplier(ns) },
	"rpm":      func(ns, _ string) (string, string) { return distroSupplier(ns) },
	"apk":      func(ns, _ string) (string, string) { return distroSupplier(ns) },
}

// supplierFromPURL returns a (name, url) pair identifying the conventional
// supplier of the package described by the PURL. Returns ("", "") when no
// confident derivation is possible — callers must omit Supplier in that case
// rather than emit a misleading identity.
func supplierFromPURL(rawPURL string) (string, string) {
	t, namespace, name, _, ok := parsePURL(rawPURL)
	if !ok {
		return "", ""
	}
	fn, ok := purlSuppliers[t]
	if !ok {
		return "", ""
	}
	return fn(namespace, name)
}

func npmSupplier(namespace, name string) (string, string) {
	if strings.HasPrefix(namespace, "@") {
		scope := strings.TrimPrefix(namespace, "@")
		return namespace, "https://www.npmjs.com/org/" + scope
	}
	return name, "https://www.npmjs.com/package/" + name
}

func goSupplier(namespace, name string) (string, string) {
	if namespace == "" {
		// scalibr reports the Go standard library as either "stdlib" or "go"
		// depending on the extractor; both refer to the same upstream.
		if name == "stdlib" || name == "go" {
			return "The Go Authors", "https://go.dev"
		}
		// Domain-rooted modules (go.opencensus.io, cloud.google.com/go, etc.)
		// have no namespace path — the name itself is the host.
		if strings.Contains(name, ".") {
			host := strings.Split(name, "/")[0]
			return host, "https://" + host
		}
		return "", ""
	}
	segs := strings.Split(namespace, "/")
	if len(segs) >= 2 && isCodeHost(segs[0]) {
		return segs[1], "https://" + segs[0] + "/" + segs[1]
	}
	return segs[0], "https://" + segs[0]
}

// distroSuppliers maps an OS distro identifier (and its known aliases) to a
// canonical supplier identity. Aliases are explicit data — searching for
// "Red Hat" surfaces every key that maps to it.
var distroSuppliers = map[string]supplierEntry{
	"ubuntu":    {"Canonical", "https://ubuntu.com"},
	"debian":    {"Debian", "https://www.debian.org"},
	"fedora":    {"Fedora Project", "https://fedoraproject.org"},
	"centos":    {"CentOS Project", "https://www.centos.org"},
	"rhel":      {"Red Hat", "https://www.redhat.com"},
	"redhat":    {"Red Hat", "https://www.redhat.com"},
	"rocky":     {"Rocky Enterprise Software Foundation", "https://rockylinux.org"},
	"alma":      {"AlmaLinux OS Foundation", "https://almalinux.org"},
	"almalinux": {"AlmaLinux OS Foundation", "https://almalinux.org"},
	"suse":      {"SUSE", "https://www.suse.com"},
	"sles":      {"SUSE", "https://www.suse.com"},
	"opensuse":  {"SUSE", "https://www.suse.com"},
	"alpine":    {"Alpine Linux", "https://alpinelinux.org"},
	"arch":      {"Arch Linux", "https://archlinux.org"},
	"gentoo":    {"Gentoo Foundation", "https://www.gentoo.org"},
	"amzn":      {"Amazon", "https://aws.amazon.com/linux"},
	"amazon":    {"Amazon", "https://aws.amazon.com/linux"},
}

// distroSupplier returns the canonical supplier for an OS distro identifier,
// matching case-insensitively. Unknown distros return ("", "") rather than
// guess; BSI prefers no claim to a wrong claim.
func distroSupplier(distro string) (string, string) {
	s, ok := distroSuppliers[strings.ToLower(distro)]
	if !ok {
		return "", ""
	}
	return s.Name, s.URL
}
