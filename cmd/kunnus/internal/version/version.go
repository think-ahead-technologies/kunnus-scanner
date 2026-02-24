// ABOUTME: Stores the version of the kunnus CLI binary.
// ABOUTME: Separates kunnus versioning from the underlying osv-scanner version.
package version

// KunnusVersion is the current release version of the kunnus CLI.
// Set at build time via -X ldflags by goreleaser.
var KunnusVersion = "0.1.0"
