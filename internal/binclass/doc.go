// ABOUTME: Package binclass identifies non-packaged binaries by fingerprinting version strings in their bytes.
// ABOUTME: It is the kunnus counterpart to syft's binary cataloger — the one path that surfaces software (e.g. memcached) compiled into an image outside any package manager.

// Package binclass is a scalibr filesystem.Extractor that catches software which
// ships as a bare executable, with no apk/dpkg/rpm record and no embedded
// dependency manifest for scalibr's gobinary/cargoauditable/dotnetpe extractors
// to read. It works by matching a file's path against a classifier glob and
// scanning the file's bytes for a version pattern, emitting a pkg:generic (or
// pkg:golang / pkg:github) package on a hit.
//
// # Provenance
//
// The classifier catalog (catalog.go) is ported from anchore/syft's binary
// cataloger (syft/pkg/cataloger/binary, Apache-2.0). The version-extraction
// regexes and CPE templates are carried over as data.
//
// # Deliberately simplified relative to syft
//
// syft's matcher is a small combinator library; this prototype ports only the
// direct file-contents evidence, which covers the large majority of entries.
// Not ported:
//
//   - Cross-file evidence: shared-library lookups (python, ruby), sibling
//     VERSION files (go), and filename-template version hints (libpython). The
//     python-binary/-lib classifiers, which have no direct content regex, are
//     therefore omitted; go and ruby keep their content regex and drop the
//     cross-file fallback.
//   - The Java JDK/JRE branching set (classifiers_java.go), which needs syft's
//     BranchingEvidenceMatcher, path predicates, and templated CPEs, and uses
//     .NET-style named groups that Go's RE2 engine rejects. kunnus already
//     identifies JARs via scalibr's javaarchive extractor.
//
// CPE templates are retained on each classifier but not yet emitted into the
// SBOM; wiring them through the encode pipeline's CPE stage is the remaining
// step to reach parity with syft's output for these packages.
package binclass
