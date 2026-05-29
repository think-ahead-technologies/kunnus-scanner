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
5. **Container scanning is a sibling, not a path-based mode.**
   `internal/mode/container/` opens an image (registry name, OCI/docker-save
   tarball, or local docker daemon) and builds the union of every ecosystem and
   Linux OS-family plugin, filtered to Linux capabilities. It deliberately does
   *not* implement `mode.Mode` — its input is an image reference, not a
   filesystem path — and the command runs `scan.RunContainer` rather than
   `scan.Run`. Plugin selection skips detection: the union is enabled and
   scalibr's per-extractor `FileRequired` decides what the image matches.

## Cohesion summary

| Package | Knows about | Does NOT know about |
|---|---|---|
| `command` | flags, modes, scan, sbom, upload | scalibr internals |
| `mode` | detect, ecosystem, osfamily, scalibr plugin names + capabilities | encoding, uploading, CLI flags |
| `mode/container` | image sources (registry/tarball/docker), the installed-state extractors + OS families, scalibr image opening | encoding, uploading, CLI flags |
| `detect` | runtime.GOOS — host introspection only | scalibr, modes, scan-root inspection |
| `ecosystem` | language markers, lockfile hash parsers, scalibr plugin names (as strings) | scalibr APIs, modes, CLI |
| `osfamily` | distro fingerprints + scalibr plugin imports for each family | modes, CLI, ecosystems |
| `scan` | scalibr (`Scan` + `ScanContainer`, with per-package layer tracing) | modes, CLI, encoding |
| `sbom` | scalibr inventory + converter, container layer attribution | modes, CLI, scanning |
| `upload` | http, file IO | everything else |

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

## Testing

TDD throughout. **No mocks** — real fixtures and real I/O at every boundary.
Coverage is layered, with the slow/broad tests built on the same fixtures as
the fast/narrow ones:

- **Unit + registry invariants.** `ecosystem` and `osfamily` each carry drift
  guards: parser filenames must be detectable, names unique, etc. Hash parsers,
  `detect`, `sbom` stages (cpe/supplier/dedup/depgraph/properties/encode), and
  `upload` (via `httptest`) are tested in isolation.
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
