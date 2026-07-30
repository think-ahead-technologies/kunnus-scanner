// ABOUTME: Map of the whole licence subsystem — where every licence comes from and how it reaches the SBOM.
// ABOUTME: Read this first; the code that does the work is spread across several packages by design, explained here.
//
// Package license normalizes and classifies licence strings (see license.go and
// classify.go). It is a dependency-free leaf: it knows nothing about CycloneDX,
// scalibr, modes, or the CLI. This doc, however, covers the *whole* licence
// subsystem — the parts that live outside this package too — because the work is
// deliberately spread out and that spread is the thing worth explaining.
//
// # The five sources
//
// A component's licence can come from any of five places:
//
//  1. apk / rpm package databases — scalibr's own extractors surface these for
//     free; they arrive already in the inventory as pkg.Licenses.
//  2. deps.dev — the opt-in online enricher (mode.AddOnlineLicenses). Off by
//     default; the only source that touches the network.
//  3. per-package manifests of *installed* packages — node_modules/<p>/package.json,
//     a wheel's METADATA, a JAR's pom.xml, a .rockspec, a .gemspec. scalibr reads
//     these files to find the package but drops the licence field; the
//     manifestlicense enricher reads it back.
//  4. Debian/Ubuntu copyright files — /usr/share/doc/<p>/copyright. dpkg's status
//     DB has no licence field (unlike apk/rpm), so the debiancopyright enricher
//     recovers it.
//  5. composer.lock — a PHP lockfile that embeds a per-package licence array.
//     PHP is not on deps.dev, so kunnus mines the lockfile offline.
//
// # The two paths
//
// Those five sources reach the SBOM through exactly two mechanisms, and which
// mechanism a source uses is decided by one question: is the licence known
// one-package-at-a-time after the scan, or many-packages-at-once during the walk?
//
//	             cardinality        when known        works in
//	enricher  →  one source : one   post-scan         repo, os, container
//	            package            (needs the pkg's
//	                               Locations first)
//	map       →  one file : many    walk-time          repo only
//	            packages           (mode planning)
//
// Enricher path (sources 1–4): scalibr enrichers that mutate pkg.Licenses in the
// inventory. mode.AddOfflineLicenseEnrichers always adds manifestlicense and
// debiancopyright; mode.AddOnlineLicenses adds deps.dev on request. Enrichers run
// per package, so they need the package (and its on-disk location) to already
// exist — hence post-scan. Crucially, this is the ONLY path that works for
// container scans: mode/container never calls ecosystem.Survey, it just runs
// scalibr, so an enricher is the only way to add a licence there.
//
// Map path (source 5): ecosystem.Survey walks the repo once during planning and
// returns a license.Map (purl → raw strings) alongside the hashes.Map it mines in
// the same pass — see ecosystem.LicenseParser. The map rides through mode.Plan
// (Plan.Licenses) into sbom.Encode. This fits lockfiles, where one file lists many
// packages and is parsed once; doing that as a per-package enricher would need a
// parse-once cache for the shared file. It is repo-only because only repo mode
// walks the tree. license.Map mirrors hashes.Map (and graph.Map, which carries
// dependency edges) on purpose: all three mine the same lockfiles in the same
// Survey pass.
//
// # The merge
//
// sbom.injectLicensesCDX is where the two paths converge. For each component it
// takes the inventory licences (paths 1–4) plus the map licences (path 5, keyed
// by conventional purl), runs every value through license.Normalize, and writes
// the deduplicated SPDX result. license.Classify is the probabilistic fallback
// for free-text licence prose; today only debiancopyright uses it, and only when
// the structured DEP-5 fields yield nothing.
//
// # Where parsing lives, and why it is not symmetric
//
// The two offline enrichers are shaped oppositely on purpose:
//
//   - manifestlicense delegates parsing to ecosystem.ManifestLicenseParser. It
//     handles five manifest formats, and each parser is keyed by the scalibr
//     extractor that produced the package (packagejson, wheelegg, …). Extractors
//     belong to ecosystems, so the parser lives next to that ecosystem's other
//     knowledge — one ecosystem, one place. A registry of five earns its keep.
//
//   - debiancopyright parses inline. It handles one format (DEP-5), so a registry
//     would be over-engineering, and there is no ecosystem to delegate to: deb
//     packages are OS-level, and osfamily owns plugin selection, not format
//     parsing. Self-contained is the only sensible shape.
//
// The rule underneath both is the same: parsing lives with the domain that owns
// the format, and a registry is factored out only when there is more than one
// format to register. Same principle, different N — not two conventions.
package license
