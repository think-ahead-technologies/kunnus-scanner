// ABOUTME: Version constant for the kunnus binary.
// ABOUTME: Kept in a tiny package so it can be imported anywhere without cycles.
package version

// Version is the semver release tag of the binary.
// goreleaser overrides this via -ldflags at release time.
var Version = "0.0.0-dev"
