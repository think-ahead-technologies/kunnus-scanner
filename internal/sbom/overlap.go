// ABOUTME: Stage: drops binary-classifier (pkg:generic) components already covered by an OS package-manager entry.
// ABOUTME: The binary classifier keys on filename+bytes, so a packaged binary (bash, gzip) would otherwise appear twice.
package sbom

import (
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
)

// osPackagePURLTypes are the package-manager PURL types whose entry is
// authoritative for a binary on disk. When one already describes a package, a
// pkg:generic component for the same software (surfaced by the binary classifier
// from the raw executable) is redundant.
var osPackagePURLTypes = map[string]bool{"deb": true, "apk": true, "rpm": true}

// suppressOSManagedBinaries removes every pkg:generic component whose name and
// version are already covered by a deb/apk/rpm component. The binary classifier
// identifies software from a bare executable and emits pkg:generic packages; for
// a binary an OS package manager also tracks (e.g. /bin/bash owned by the bash
// .deb) this double-counts the artifact. The OS package is authoritative — it
// carries the distro version, supplier and licence — so the generic twin is
// dropped.
//
// "Covered" means same component name and a version the OS package's version
// begins with, up to a packaging separator: the classifier reads the upstream
// version from the binary ("5.2.37") while the OS package carries the distro
// revision ("5.2.37-2+b9"). Matching the upstream version as a separator-bounded
// prefix bridges the two without suppressing an unrelated neighbour (binary
// "1.13" must not be covered by package "1.130").
func suppressOSManagedBinaries(bom *cyclonedx.BOM) {
	if bom == nil || bom.Components == nil {
		return
	}
	comps := *bom.Components

	osVersions := make(map[string][]string)
	for i := range comps {
		if osPackagePURLTypes[purlType(comps[i].PackageURL)] {
			osVersions[comps[i].Name] = append(osVersions[comps[i].Name], comps[i].Version)
		}
	}

	out := make([]cyclonedx.Component, 0, len(comps))
	for i := range comps {
		c := comps[i]
		if purlType(c.PackageURL) == "generic" && coveredByOSPackage(c.Version, osVersions[c.Name]) {
			continue
		}
		out = append(out, c)
	}
	*bom.Components = out
}

// coveredByOSPackage reports whether any OS-package version covers binVer.
func coveredByOSPackage(binVer string, osVersions []string) bool {
	for _, v := range osVersions {
		if versionCovers(v, binVer) {
			return true
		}
	}
	return false
}

// versionCovers reports whether an OS-package version covers a binary version:
// identical, or the OS version is the binary version followed by a Debian/RPM
// packaging separator (so "5.2.37-2+b9" covers "5.2.37" but "1.130" does not
// cover "1.13").
func versionCovers(osVer, binVer string) bool {
	if binVer == "" {
		return false
	}
	if osVer == binVer {
		return true
	}
	rest, ok := strings.CutPrefix(osVer, binVer)
	if !ok || rest == "" {
		return false
	}
	switch rest[0] {
	case '-', '+', '~', ':', '_':
		return true
	}
	return false
}

// purlType returns the type segment of a PURL ("pkg:TYPE/...") or "" if absent.
func purlType(purl string) string {
	s, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return ""
}
