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
//   - Shared-library lookups (the python and ruby binaries' fallback of parsing
//     ELF imports and resolving the linked .so) and sibling VERSION files (go).
//     go and ruby keep their direct content regex; python is covered another way
//     (below), so the resolver-based lookup is not ported.
//   - The Java JDK/JRE branching set (classifiers_java.go), which needs syft's
//     BranchingEvidenceMatcher, path predicates, and templated CPEs, and uses
//     .NET-style named groups that Go's RE2 engine rejects. kunnus already
//     identifies JARs via scalibr's javaarchive extractor.
//
// Python IS covered, via the filename-template matcher (catalog.go's nameTemplate
// / mcTmpl): the libpython glob matches the shared library directly and the
// python glob the interpreter, with the major.minor read from the filename and
// the full version from the NUL-delimited bytes — so syft's shared-library
// fallback (which starts from the binary and resolves its imports) is unnecessary
// for the common --enable-shared and static builds.
//
// CPE templates are retained on each classifier and ride to the encoder on
// Metadata; the encode pipeline's CPE stage (sbom.injectCPEsCDX) renders the
// detected version into them, preferring the curated CPE over its PURL
// heuristic — matching syft's output for these packages.
package binclass
