// ABOUTME: Package modustoolbox extracts Infineon ModusToolbox embedded-firmware dependencies from .mtb manifests.
// ABOUTME: Records what is parsed, what is deliberately ignored, and how the extractor is wired into kunnus.

// Package modustoolbox is a kunnus-native scalibr filesystem.Extractor for
// Infineon/Cypress ModusToolbox projects. A ModusToolbox project declares each
// dependency in a one-line ".mtb" manifest:
//
//	https://github.com/<owner>/<repo>[.git]#<git-ref>#<storage-location>
//
// The owner/repo become a pkg:github package and the git ref becomes its
// version (kept verbatim — refs are tags like "release-v6.1.0",
// "STABLE-2_1_2_RELEASE" or "v2.86.1", not semver). The third field is
// ModusToolbox storage bookkeeping and is ignored.
//
// # Wiring
//
// ModusToolbox has no scalibr extractor, so — like internal/binclass — this is
// not a name in scalibr's registry. internal/ecosystem carries a "modustoolbox"
// entry that detects the .mtb suffix (and flags NativeExtractor), and mode/repo
// appends New() to its plugin list when the ecosystem is detected. It is wired
// into repo scans only: .mtb manifests describe a source tree's declared
// dependencies, not installed state, so os/container modes do not enable it.
//
// # Deliberately not parsed
//
//   - assetlocks.json: carries asset-name + locked-commit but no repository URL,
//     so it cannot form a pkg:github coordinate. It is redundant with the .mtb
//     files (same names, same refs) and is left to the existing JSON lockfile
//     machinery if a hash source is ever added.
//   - Non-GitHub manifests: ModusToolbox can in principle point at other hosts;
//     only github.com is mapped today. Others are dropped rather than guessed.
//   - Hashes and licences: a .mtb pins a git ref (a tag), not a commit SHA or a
//     checksum, and carries no licence data. Resolving either would require
//     network access, which the scanner's offline design forbids.
package modustoolbox
