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
| `mode/container` | image sources (registry/tarball/docker), ecosystem+osfamily plugin unions, scalibr image opening | encoding, uploading, CLI flags |
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

## TDD plan (next session)

The skeleton has stubs only. Implementation work is gated on tests in this order:

1. `detect/ecosystem_test.go` — fixture-based, fastest feedback
2. `detect/distro_test.go` — fixture `/etc/os-release` trees
3. `mode/repo/plugins_test.go` — pure mapping tests
4. `mode/os/plugins_test.go` — pure mapping tests
5. `mode/repo` and `mode/os` `Plan` tests — assert on `ScanConfig` shape
6. `scan` integration test — real scalibr call on a fixture tree
7. `sbom` golden-file tests — encode a fixed inventory, snap the output
8. `upload` httptest.Server tests
9. End-to-end CLI tests in `cmd/kunnus/main_test.go`

No mocks. Real fixtures, real I/O at boundaries.
