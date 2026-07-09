# CLAUDE.md — kunnus-scanner project notes

## Project context

This is the v2 rewrite. The v1 fork (`../kunnus-scanner/`) is osv-scanner with a
`cmd/kunnus/` subcommand bolted on; ~300 files of inherited surface for ~2000 LoC
of actual kunnus logic, plus flaky tests for features we never ship.

v2 depends on **osv-scalibr** directly. We bring our own CLI shell and SBOM
encoder; the scanner library does the extraction work.

## Architectural rules — enforced in code review

1. **Host introspection lives in `internal/detect/`. Target introspection lives
   next to its plugin mapping.** `detect/` answers *where am I running?* and
   stays scalibr-free. Detecting what's at the scan root belongs in the
   registry package that owns the corresponding scalibr plugin names —
   `internal/ecosystem/` for language ecosystems, `internal/osfamily/` for
   Linux distros — so that detection metadata and plugin selection cannot
   drift apart.
2. `internal/scan/` is the **only** package that calls a scalibr scan —
   `scalibr.New().Scan()` (filesystem) and `.ScanContainer()` (container image).
   Every other package operates on `scan.Result` instead.
3. `internal/command/` is the **only** package that imports `urfave/cli/v3`.
   Modes don't know they're being invoked from a CLI.
4. Each `internal/mode/<x>/` package builds a `*scalibr.ScanConfig` from a path
   plus `mode.Overrides`. Its only I/O is calls into `detect`, `ecosystem`, or
   `osfamily` — no raw filesystem reads of its own.
5. **Every scan flavour is a `mode.Mode`; the runner dispatches on the plan.**
   `internal/mode/container/` implements `mode.Mode` like repo and os — its
   `Plan` just takes an image reference instead of a filesystem path, opens the
   image (pulling it for a remote reference), and builds the union of every
   ecosystem and Linux OS-family plugin filtered to Linux capabilities. It
   signals a container scan by setting `Plan.Image`; the shared `runScan` calls
   `scan.RunContainer` when `Plan.Image` is non-nil and `scan.Run` otherwise, so
   all three subcommands are the same `runScan(ctx, cmd, mode, target, ov)`
   one-liner and `internal/scan` stays free of mode types (the dispatch lives in
   `command`, which may know both). Plugin selection skips detection: the union
   is enabled and scalibr's per-extractor `FileRequired` decides what the image
   matches.
   Digests that are only knowable after the scan ride on `Plan.PostScanHashes`,
   a hook the runner invokes with the resulting inventory and merges into
   `Plan.Hashes` — for modes (like container) whose digests key off the scanned
   packages rather than being harvestable during planning.

## Cohesion summary

| Package | Knows about | Does NOT know about |
|---|---|---|
| `command` | flags, modes, scan, sbom, upload | scalibr internals |
| `mode` | detect, ecosystem, osfamily, scalibr plugin names + capabilities | encoding, uploading, CLI flags |
| `mode/container` | image sources (registry/tarball/docker), the installed-state extractors + OS families, scalibr image opening | encoding, uploading, CLI flags |
| `detect` | runtime.GOOS — host introspection only | scalibr, modes, scan-root inspection |
| `ecosystem` | language markers, lockfile hash + licence parsers, scalibr plugin names (as strings), the `NativeExtractor` flag for ecosystems with no scalibr plugin | scalibr APIs, modes, CLI |
| `osfamily` | distro fingerprints + scalibr plugin imports for each family | modes, CLI, ecosystems |
| `binclass` | filename globs + version-string regexes for non-packaged ELF binaries (ported from syft, Apache-2.0) | modes, CLI, encoding, OS package managers |
| `modustoolbox` | `.mtb` manifest parsing (Infineon/Cypress embedded firmware) → `pkg:github` components | modes, CLI, encoding, ecosystem registry |
| `vcpkg` | `vcpkg.json` manifest parsing (dependencies + overrides + `version>=` floors) → `pkg:generic` components | modes, CLI, encoding, ecosystem registry |
| `gitsubmodule` | `.gitmodules` stanza parsing + `.git/index` gitlink SHAs → `pkg:github`/`pkg:generic` components | modes, CLI, encoding, ecosystem registry |
| `platformio` | `platformio.ini` `lib_deps` parsing (registry specs + VCS URLs) → `pkg:generic`/`pkg:github` components | modes, CLI, encoding, ecosystem registry |
| `espidf` | `dependencies.lock` + `idf_component.yml` parsing (lock preferred) → `pkg:generic`/`pkg:github` components | modes, CLI, encoding, ecosystem registry |
| `ownership` | dpkg/apk/rpm database file-list parsing → set of OS-owned paths | scalibr, modes, CLI, binclass |
| `scan` | scalibr (`Scan` + `ScanContainer`, with per-package layer tracing) | modes, CLI, encoding |
| `sbom` | scalibr inventory + converter, container layer attribution, binary/OS overlap suppression (by ownership + name) | modes, CLI, scanning |
| `license` | license identification → SPDX: normalize a declared string, or classify licence text (BSI §6.1) | CycloneDX, scalibr, modes, CLI |
| `upload` | http, file IO | everything else |

## Licence pipeline

Licence handling is spread across several packages on purpose; the map of the
whole flow lives in `internal/license/doc.go` (read that first). The short
version:

- **Five sources** feed a component's licence: apk/rpm (scalibr, free),
  deps.dev (opt-in online enricher), per-package manifests of installed packages
  (npm/python/java/lua/ruby), Debian/Ubuntu copyright files, and composer.lock.
- **Two paths** carry them, chosen by cardinality + timing: *enrichers* mutate
  `pkg.Licenses` post-scan, one package at a time (and are the **only** path that
  works for container scans, which never call `ecosystem.Survey`); the *map path*
  (`license.Map`) mines a lockfile once during the planning walk and rides
  through `mode.Plan` into `sbom.Encode` (repo-mode only). `license.Map` mirrors
  `hashes.Map` because both are mined in the same Survey pass.
- **One merge:** `sbom.injectLicensesCDX` unions both paths and normalizes every
  value through `license.Normalize`.
- **Parsing asymmetry is intentional:** `manifestlicense` delegates to
  `ecosystem` (five formats, each keyed by its scalibr extractor); `debiancopyright`
  parses inline (one format, no ecosystem home). Same rule — parsing lives with
  the domain that owns the format, registry only when N > 1.

## Binary classifier (non-packaged software)

`internal/binclass/` surfaces software compiled into an image as a bare
executable — no apk/dpkg/rpm record, and no embedded manifest for scalibr's
`gobinary`/`cargoauditable`/`dotnetpe` extractors to read (e.g. a hand-built
memcached daemon). It is a scalibr `filesystem.Extractor`: a filename glob
selects candidate files, an ELF-magic check rejects non-binaries, and a version
regex scanned over the file's bytes yields a `pkg:generic` (or
`pkg:golang`/`pkg:github`) package. A second matcher mode (`nameTemplate`) reads
a major.minor hint from the filename and renders it into the content regex —
this is how python is caught (the `libpython*.so*` and `python*` globs, version
read from the NUL-delimited bytes). The catalog (`catalog.go`) is ported from
anchore/syft's binary cataloger (Apache-2.0); `doc.go` records what was left out
— syft's resolver-based shared-library lookup and its Java JDK/JRE branching set.
CPE templates are carried on each classifier as data but not yet emitted.

It is a kunnus extractor, not a scalibr-registry plugin, so `mode/os` and
`mode/container` append `binclass.New()` directly to their plugin lists (it is
**not** added to `mode/repo`: source trees rarely carry compiled server
binaries). The ELF gate makes it a no-op on the Windows/Mac OS targets.

**Overlap suppression** (`sbom.suppressOSManagedBinaries`, an encode stage run
right after dedup, before enrichment/CPEs/dep-graph). The classifier keys on
filename + bytes, so a binary an OS package manager also tracks (`/bin/bash`
owned by the bash `.deb`) would otherwise appear twice — once as `pkg:deb/...`
and once as `pkg:generic/...`. The stage drops the `pkg:generic` twin when
either signal fires:

- **File ownership (primary).** `internal/ownership/` reads the dpkg
  (`var/lib/dpkg/info/*.list`), apk (`lib/apk/db/installed`) and rpm
  (`var/lib/rpm/rpmdb.sqlite` etc., via go-rpmdb) databases at the scan root into
  a set of owned paths, carried on `Plan.OwnedFiles` (built by `mode/os` and
  `mode/container`, which have the root/image FS) and passed into `sbom.Encode`.
  A generic component is dropped when one of its evidence locations is an owned
  file. Because this keys on **path, not name**, it bridges the common case where
  the owning package's name differs from the binary's — `/usr/bin/xz` owned by
  `xz-utils`, `…/bin/postgres` owned by `postgresql-18`, `/usr/bin/curl` owned by
  `curl-minimal`. (The rpm reader materialises the binary DB to a temp file,
  since go-rpmdb's sqlite/BerkeleyDB drivers open by path, not via `fs.FS`.)
- **Name + version (fallback).** A deb/apk/rpm component shares the generic
  component's name and a version that *covers* it — equal, or the binary's
  upstream version followed by a packaging separator, so `5.2.37-2+b9` covers
  `5.2.37` but `1.130` does not cover `1.13`. This backstops the cases ownership
  misses (no DB readable, or a merged-usr `/bin`↔`/usr/bin` path mismatch).

Only `pkg:generic` is ever suppressed (the `pkg:golang`/`pkg:github` catalog
entries are left alone), and the authoritative OS package (with its distro
version, supplier and licence) is the one kept. A genuinely non-packaged binary
— memcached or redis compiled from source — is owned by nothing and matches no
package name, so it survives.

## ModusToolbox ecosystem (native extractor, no scalibr plugin)

Infineon ModusToolbox firmware (PSE84 / Cortex-M projects) declares each
dependency in a one-line `*.mtb` manifest:
`https://github.com/<owner>/<repo>[.git]#<git-ref>#<storage-location>`. The
owner/repo become a `pkg:github` component and the git ref its version, kept
verbatim (refs are tags like `release-v6.1.0`, `STABLE-2_1_2_RELEASE`,
`v2.86.1` — not semver). The third field is ModusToolbox bookkeeping; ignored.
`assetlocks.json` is not parsed: it carries no repository URL, so it cannot form
a PURL, and it is redundant with the `.mtb` files.

scalibr has no ModusToolbox extractor, so `internal/modustoolbox/` is a
kunnus-native `filesystem.Extractor` (the binclass pattern). It is wired in
**only for repo scans** — `.mtb` files describe a source tree's declared
dependencies, not installed state — via a new mechanism that keeps detection and
plugin selection from drifting (architecture rule #1):

- `internal/ecosystem/` carries a `modustoolbox` entry that detects the `.mtb`
  suffix and sets the new **`NativeExtractor`** flag instead of `ScalibrPlugins`
  (the completeness invariant accepts either). The entry names no extractor
  instance, so `ecosystem` stays free of scalibr APIs.
- `mode/repo` maps the detected `"modustoolbox"` ecosystem to
  `modustoolbox.New()` and appends it to the plan's plugins (and counts it in the
  "something to ship" guard), exactly as `mode/os` appends `binclass.New()`.

No hashes or licences: a `.mtb` pins a git tag, not a commit SHA or checksum, and
carries no licence data; resolving either needs network access the scanner
forbids. The cross-project duplication (the same lib pinned by three
sub-projects) collapses in the sbom dedup stage.

## Embedded C/C++ ecosystems (native extractors, no scalibr plugins)

CRA pushes SBOM coverage into embedded firmware, so kunnus carries native
extractors (the modustoolbox pattern: `NativeExtractor` registry entry +
`internal/<name>/` extractor + a branch in `mode/repo`'s
`nativeExtractorsFor`) for ecosystems scalibr does not cover. Conan needs
nothing here — the `cpp` ecosystem already runs scalibr's `cpp/conanlock`.

- **vcpkg** (`internal/vcpkg/`): parses manifest-mode `vcpkg.json`. Each
  `dependencies[]` entry (bare string or object) becomes a `pkg:generic`
  component. Version resolution is the best offline data, in order: an
  `overrides[]` pin, else the dep's own `version>=` floor (with the `#N`
  port-version suffix stripped — that's vcpkg packaging metadata), else
  versionless. `builtin-baseline` is deliberately ignored: resolving the
  baseline commit to concrete port versions requires the vcpkg registry, i.e.
  network access the scanner forbids. Feature-conditional dependencies
  (`features.<x>.dependencies`) are not walked — whether a feature is enabled
  is unknowable from the manifest alone.

- **git submodules** (`internal/gitsubmodule/`): parses `.gitmodules` stanzas
  (via go-git's config decoder) for each submodule's path and remote URL —
  github.com remotes (https/ssh/scp-like) become `pkg:github/<owner>/<repo>`,
  everything else `pkg:generic/<last-path-segment>`. The pinned commit is not
  in the manifest: it is the gitlink entry in the superproject's `.git/index`,
  which the extractor decodes (go-git's index format reader) through the scan
  FS — no submodule checkout and no `git` subprocess needed. An exported tree
  without `.git` yields versionless components. scalibr's `misc/gitrepo` does
  walk submodules too, but was rejected deliberately: it triggers on `.git`
  directories (which `fswalk` skips on every kunnus walk) and needs
  `DirectFS`/`ExtractFromDirs` capabilities repo mode doesn't grant, it emits
  the scanned repo itself as a package, its GitHub names drop the owner
  namespace (`pkg:github/fmt`, not `pkg:github/fmtlib/fmt`), and it yields
  nothing on an exported tree with no `.git`.

- **PlatformIO** (`internal/platformio/`): parses `lib_deps` options across
  every section of `platformio.ini` (single-line and indented-continuation
  forms). Registry specs (`name`, `owner/name`, optionally `@ <version>` with
  spaces allowed) become `pkg:generic` with the version or range kept verbatim
  (the modustoolbox rule: a declared range is the truth; resolving it needs
  PlatformIO's registry, i.e. network). Source URLs with `#<ref>` become
  `pkg:github` for github.com, `pkg:generic` otherwise; `file://`/`symlink://`
  paths and `${...}` interpolations are dropped (interpolation would need
  configparser semantics for marginal gain). Duplicate declarations across
  `[env:*]` sections collapse in the SBOM dedup stage.

- **ESP-IDF** (`internal/espidf/`): two component-manager files, lock
  preferred. `dependencies.lock` pins exact versions for the whole project
  (direct + transitive, including the `idf` framework pseudo-component) →
  `pkg:generic/<namespace>/<name>@<version>`; when a manifest
  (`idf_component.yml`) sits under a locked project (checked by walking up to
  the scan root), it is skipped entirely — emitting its ranges alongside the
  lock's pins would duplicate every component under two purls. Manifest-only
  projects fall back to declared constraints verbatim (`*` → versionless, bare
  names get the `espressif/` registry namespace, `path:` components dropped,
  `git:` sources classified by host). The lock's SHA-256 `component_hash`
  rides the standard `HashParsers` → `hashes.Map` path (the entry lives in
  `internal/ecosystem/espidf.go`), keyed by the same purls the extractor
  emits.

## Things we deliberately did NOT build

- Plugin registry / factory pattern — two modes don't justify it.
- Config file support — flags only. Add YAML later if customers ask.
- DI container — package-level functions are fine.
- Vulnerability matching — out of scope; that's the platform's job.

## Known limitations

- **Java groupId from bare JARs.** A JAR without `META-INF/maven/.../pom.properties`
  (common for OSGi/shaded bundles) carries no authoritative Maven groupId.
  scalibr's `javaarchive` then falls back to the `Bundle-SymbolicName` or
  filename, which is often a single segment (e.g. `bcpg` for `bcpg-jdk18on`
  instead of `org.bouncycastle`). Since OSV's Maven ecosystem keys on
  `groupId:artifactId`, the wrong groupId silently drops vuln matches. This is
  upstream extractor data we don't own — tracked at
  https://github.com/google/osv-scalibr/issues/840 (expand the artifactId→groupId
  map toward Syft parity). We deliberately do NOT ship our own groupId database
  or a Maven Central lookup: the former is a maintenance liability, the latter
  contradicts the no-network design. JARs that do embed `pom.properties` get the
  correct groupId.

- **Binary classifier is a simplified syft port.** `internal/binclass/` carries
  syft's direct file-contents regexes plus a filename-template matcher (which
  covers python); not ported are syft's resolver-based shared-library lookup and
  the Java JDK/JRE branching set. CPE templates ship in the catalog but are not
  yet emitted into the
  SBOM. Overlap suppression is path-based via `internal/ownership/` (with a
  name+version fallback) across dpkg, apk and rpm, so it correctly collapses
  packages whose name differs from the binary's (`xz-utils`, `postgresql-18`,
  `curl-minimal`).

## Testing

TDD throughout. **No mocks** — real fixtures and real I/O at every boundary.
Coverage is layered, with the slow/broad tests built on the same fixtures as
the fast/narrow ones:

- **Unit + registry invariants.** `ecosystem` and `osfamily` each carry drift
  guards: parser filenames must be detectable, names unique, etc. `binclass`
  carries its own catalog drift guard (every classifier has a glob, a `version`
  capture group, and a well-formed PURL/CPE) and proves extraction + the ELF
  gate against a real slice of the `memcached:latest` binary, and the
  filename-template matcher against a real slice of `python:latest`'s
  `libpython3.14.so`. `ownership` parses
  real dpkg `.list` and apk `installed` fixtures and tolerates a corrupt rpm DB
  (a valid rpmdb is a binary sqlite/bdb blob, so the rpm parse path is verified
  e2e against a real rpm image, not an in-tree fixture — see the rpm note below);
  the `sbom` overlap stage is tested for both the path-ownership and name+version
  drop signals. Hash parsers,
  `detect`, `sbom` stages (cpe/supplier/dedup/depgraph/properties/overlap/encode),
  and `upload` (via `httptest`) are tested in isolation.
- **Shared fixture corpus at the module root.** `testdata/ecosystems/<name>/`
  and `testdata/osfamilies/<name>/` each hold a real manifest/lockfile (or
  package DB + `etc/os-release`) plus a `want.txt` listing the exact `purl` and
  `cpe` the scanner must emit. Both the scan-seam tier and the binary e2e tier
  read this one corpus.
- **Scan-seam integration** (`internal/scan/*_integration_test.go`). For each
  registered ecosystem / Linux OS family, plan via `mode/repo` or `mode/os`,
  run real scalibr, and assert the exact purls appear in the inventory. The
  loops over `ecosystem.All()` / `osfamily.LinuxFamilies()` are anti-drift
  guards: a new registry entry without a fixture (or a documented reason in
  `osFamiliesWithoutFixture`) turns the suite red. Container scanning is proven
  here against a synthetic multi-layer image built in-memory with
  `go-containerregistry`, asserting per-layer attribution.
- **Binary e2e** (`cmd/kunnus/*_test.go`). Build the real binary once, then
  drive subcommands with real flags: a kitchen-sink `sbom repo` over every
  ecosystem at once, `sbom os --target-os linux` per family, and `sbom
  container` over a synthetic image tarball — each asserting purls **and** cpes
  in the CycloneDX output (plus layer properties for containers).

Not in-tree fixturable, by design: rpm-based OS families (binary sqlite/bdb
DB), `cos` (image-specific), and the registry-pull / local-docker container
sources (need a network registry or a docker daemon). These are documented
skips, not coverage gaps.
