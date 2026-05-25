// ABOUTME: Heuristic supplier-identity derivation from PURLs.
// ABOUTME: BSI TR-03183-2 wants every component to carry a supplier email or URL; we synthesise one.
package sbom

import "strings"

// supplierFromPURL returns a (name, url) pair identifying the conventional
// supplier of the package described by the PURL. Returns ("", "") when no
// confident derivation is possible — callers must omit Supplier in that case
// rather than emit a misleading identity.
func supplierFromPURL(rawPURL string) (string, string) {
	t, namespace, name, _, ok := parsePURL(rawPURL)
	if !ok {
		return "", ""
	}

	switch t {
	case "golang":
		return goSupplier(namespace, name)
	case "npm":
		if strings.HasPrefix(namespace, "@") {
			scope := strings.TrimPrefix(namespace, "@")
			return namespace, "https://www.npmjs.com/org/" + scope
		}
		return name, "https://www.npmjs.com/package/" + name
	case "pypi":
		return name, "https://pypi.org/project/" + name + "/"
	case "maven":
		return namespace, "https://central.sonatype.com/artifact/" + namespace + "/" + name
	case "nuget":
		return name, "https://www.nuget.org/packages/" + name
	case "cargo":
		return name, "https://crates.io/crates/" + name
	case "composer":
		return namespace, "https://packagist.org/packages/" + namespace + "/" + name
	case "gem":
		return name, "https://rubygems.org/gems/" + name
	case "deb":
		return distroSupplier(namespace)
	case "rpm":
		return distroSupplier(namespace)
	case "apk":
		return distroSupplier(namespace)
	}
	return "", ""
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

// distroSupplier maps an OS distro identifier to a canonical supplier identity.
// Unknown distros return ("", "") rather than guess; BSI prefers no claim to a
// wrong claim.
func distroSupplier(distro string) (string, string) {
	switch strings.ToLower(distro) {
	case "ubuntu":
		return "Canonical", "https://ubuntu.com"
	case "debian":
		return "Debian", "https://www.debian.org"
	case "fedora":
		return "Fedora Project", "https://fedoraproject.org"
	case "centos":
		return "CentOS Project", "https://www.centos.org"
	case "rhel", "redhat":
		return "Red Hat", "https://www.redhat.com"
	case "rocky":
		return "Rocky Enterprise Software Foundation", "https://rockylinux.org"
	case "alma", "almalinux":
		return "AlmaLinux OS Foundation", "https://almalinux.org"
	case "suse", "sles", "opensuse":
		return "SUSE", "https://www.suse.com"
	case "alpine":
		return "Alpine Linux", "https://alpinelinux.org"
	case "arch":
		return "Arch Linux", "https://archlinux.org"
	case "gentoo":
		return "Gentoo Foundation", "https://www.gentoo.org"
	case "amzn", "amazon":
		return "Amazon", "https://aws.amazon.com/linux"
	}
	return "", ""
}
