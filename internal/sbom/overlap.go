// ABOUTME: Stage: drops binary-classifier (pkg:generic) components already covered by an OS package-manager entry.
// ABOUTME: The binary classifier keys on filename+bytes, so a packaged binary (bash, gzip) would otherwise appear twice.
package sbom

import (
	"strings"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"

	"github.com/think-ahead/kunnus-scanner/internal/ownership"
)

// osPackagePURLTypes are the package-manager PURL types whose entry is
// authoritative for a binary on disk. When one already describes a package, a
// pkg:generic component for the same software (surfaced by the binary classifier
// from the raw executable) is redundant.
var osPackagePURLTypes = map[string]bool{"deb": true, "apk": true, "rpm": true}

// suppressOSManagedBinaries removes every pkg:generic component that an OS
// package manager already accounts for. The binary classifier identifies
// software from a bare executable and emits pkg:generic packages; for a binary
// an OS package manager also tracks (e.g. /bin/bash owned by the bash .deb) this
// double-counts the artifact. The OS package is authoritative — it carries the
// distro version, supplier and licence — so the generic twin is dropped.
//
// A generic component is dropped when either signal fires:
//
//   - File ownership (precise): one of the component's evidence locations is a
//     file recorded as owned in the dpkg/apk database. This keys on path, so it
//     works even when the owning package's name differs from the binary's — the
//     /usr/bin/xz binary owned by the xz-utils package, postgres owned by
//     postgresql-18 — which the name signal alone cannot bridge.
//   - Name + version (fallback): a deb/apk/rpm component shares this component's
//     name and a version that covers it, for the cases where ownership data is
//     unavailable or the located path was not recorded (e.g. a merged-usr
//     /bin↔/usr/bin path mismatch). "Covers" means the OS version equals the
//     binary's upstream version or extends it past a packaging separator, so
//     "5.2.37-2+b9" covers "5.2.37" but "1.130" does not cover "1.13".
func suppressOSManagedBinaries(bom *cyclonedx.BOM, owned ownership.Set) {
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
		if purlType(c.PackageURL) == "generic" &&
			(componentOwned(c, owned) || coveredByOSPackage(c.Version, osVersions[c.Name])) {
			continue
		}
		out = append(out, c)
	}
	*bom.Components = out
}

// componentOwned reports whether any of the component's evidence locations is a
// file owned by an OS package.
func componentOwned(c cyclonedx.Component, owned ownership.Set) bool {
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		return false
	}
	for _, occ := range *c.Evidence.Occurrences {
		if owned.Owns(occ.Location) {
			return true
		}
	}
	return false
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
