// ABOUTME: Version constant for the kunnus binary.
// ABOUTME: Kept in a tiny package so it can be imported anywhere without cycles.
package version

import "runtime/debug"

// Version is the semver release tag of the binary.
// goreleaser overrides this via -ldflags at release time.
var Version = "0.0.0-dev"

// Scalibr returns the version of the osv-scalibr module linked into this
// binary, read from Go build info — always the truth about what actually ran,
// with no constant to keep in sync. Empty when the dependency info is absent
// (go-test binaries embed no dependency modules; `go build` binaries do).
func Scalibr() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return scalibrFrom(info)
}

// scalibrFrom extracts the osv-scalibr module version from build info,
// honouring a replace directive (the replacement is what actually ran).
func scalibrFrom(info *debug.BuildInfo) string {
	for _, dep := range info.Deps {
		if dep.Path != "github.com/google/osv-scalibr" {
			continue
		}
		if dep.Replace != nil {
			return dep.Replace.Version
		}
		return dep.Version
	}
	return ""
}
