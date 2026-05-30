# Licence coverage

kunnus attaches an SPDX licence to every component it can, from the package data
itself. This document records where each licence comes from and how complete the
coverage is per ecosystem.

## How it works

Every raw licence string — from any source below — is normalized in
`internal/license` to one of:

- a canonical **SPDX identifier** (`MIT`, `Apache-2.0`, `GPL-2.0-or-later`),
- an **SPDX expression** (`MIT OR Apache-2.0`), or
- a **`LicenseRef-kunnus-<slug>`** fallback when it matches no SPDX id.

Values that carry no assertion (`""`, `NONE`, `NOASSERTION`, deps.dev's
`UNKNOWN`) are dropped rather than emitted. Normalized licences are written to
`components[].licenses[]` with acknowledgement `concluded` (the BSI §5.2.2
distribution-licence field), deduplicated per component.

## Sources

Licences come from five sources, in order of how directly they describe the
component. All but the last are **offline**; the scan stays fully offline unless
`--online-licenses` is passed.

1. **OS package extractors** — apk and rpm carry the licence in their package
   database; scalibr surfaces it directly.
2. **Debian/Ubuntu copyright files** — dpkg's status DB has no licence, so an
   enricher reads each package's machine-readable `usr/share/doc/<name>/copyright`
   (DEP-5) and maps the Debian short names to SPDX.
3. **Lockfiles** — formats that embed a per-package licence (today: `composer.lock`).
4. **Installed-package manifests** — each package's own manifest, re-read offline
   by an enricher: npm `package.json`, Python `METADATA`/`PKG-INFO`, Java JAR
   (`pom.xml` `<licenses>` / OSGi `Bundle-License`), Lua `.rockspec`, Ruby
   `.gemspec`.
5. **deps.dev (online, opt-in)** — `--online-licenses` looks up licences for the
   ecosystems deps.dev supports. Off by default; see the endpoint note in
   `internal/mode/license.go`.

## Coverage by ecosystem

"Offline" is what a scan produces with no network; "deps.dev" is what
`--online-licenses` adds.

| Ecosystem | Offline source | deps.dev | Notes |
|---|---|---|---|
| Alpine (apk) | apk extractor | — | full |
| RHEL/SUSE/Fedora (rpm) | rpm extractor | — | full |
| Debian/Ubuntu (deb) | copyright (DEP-5) | — | ~76%; free-text/symlinked copyright not parsed |
| npm | installed `package.json` | ✓ | offline covers installed/container scans |
| Python (pypi) | wheel `METADATA` | ✓ | offline covers installed/container scans |
| Java (maven) | JAR `pom.xml` / `Bundle-License` | ✓ | offline = installed JARs; parent-pom-inherited licences not in the JAR |
| Ruby (gem) | `.gemspec` | ✓ | `Gemfile.lock` carries no licence |
| PHP (composer) | `composer.lock` | — | not on deps.dev — offline is the only path |
| Lua | `.rockspec` | — | not on deps.dev |
| Go | — | ✓ | no offline licence in go.mod/go.sum |
| Rust (cargo) | — | ✓ | `Cargo.lock` carries no per-dep licence |
| .NET (nuget) | — | ✓ | lockfiles/csproj carry no per-dep licence |
| Haskell | — | — | `cabal.project.freeze` carries no licence |
| R | — | — | only a lockfile extractor; no `DESCRIPTION` extractor |
| Swift | — | — | `Package.resolved` carries no licence; not on deps.dev |
| C/C++ (conan, vendored) | — | — | no licence in the scanned inputs |

## Real-world validation

Offline scans of public images (no `--online-licenses`):

| Image | Coverage |
|---|---|
| `node:20-alpine` | npm 193/193, apk 18/18 |
| `ruby:3.3` | gem 86/86, deb 346/455 |
| `python:3.12-alpine` | pip 1/1, apk 37/38 |
| `tomcat:10.1-jre21` | maven 26/29 (Apache-2.0) |

Benchmarked against syft/trivy (see `.github/workflows/sbom-compare.yml`),
offline coverage is at parity for language ecosystems and apk; Debian trails
because syft/trivy run a full-text licence **classifier** over free-text
copyright files, whereas kunnus parses only the structured DEP-5 form.

## Known limitations

- **Debian free-text / symlinked copyright** — packages whose copyright is prose
  (no DEP-5 `License:`) or a symlink to a free-text file are not licensed
  offline. Matching syft here would require a probabilistic licence-text
  classifier, a deliberate non-goal: kunnus does exact parsing only.
- **Java parent-pom inheritance** — a JAR whose licence is declared only in a
  parent pom not shipped inside the archive cannot be recovered offline.
- **Dynamic manifests** — a `.gemspec`/`.rockspec` that computes its licence in
  code rather than declaring it literally yields nothing (best-effort regex).

For ecosystems with no offline source (Go, Rust, .NET, …), `--online-licenses`
fills the gap via deps.dev.

## Adding a source

Each source is one small, isolated addition — that is the point of the design:

- a **lockfile** licence: a `LicenseParser` entry on the `Ecosystem` (see
  `internal/ecosystem/composer.go`);
- an **installed-manifest** licence: a parser registered by extractor name in
  `internal/ecosystem/manifest.go`;
- an **OS copyright** scheme: an enricher like `internal/debiancopyright`.
