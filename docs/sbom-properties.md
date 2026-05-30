# SBOM properties reference

kunnus emits CycloneDX 1.6 JSON. Beyond the standard CycloneDX fields, every
component carries a set of **properties** (`component.properties[]`, an array of
`{name, value}` pairs) that downstream tooling — the Kunnus platform and the BSI
TR-03183-2 conformance evaluator — relies on. This file is the authoritative
list of those property keys, their values, and which scan modes produce them.

Two namespaces are used:

- **`bsi:*`** — required by the BSI TR-03183-2 conformance check. Present on
  every component in every scan.
- **`kunnus:*`** — kunnus-specific enrichment. Present only for the scan modes
  noted below.

All property values are strings, including booleans (encoded as the text
`"true"` / `"false"`), because both CycloneDX and the sbomqs evaluator treat
property values as text.

## `bsi:component:*` — BSI component classification

Present on **every component**, for **all scan modes** (repo, os, container) and
on the SBOM's root component.

| Key | Value | Meaning |
|---|---|---|
| `bsi:component:filename` | a path string | The location the component was found at. Omitted when no location is known. Only one path appears here; the **complete** set of locations lives in `component.evidence.occurrences[]`. |
| `bsi:component:executable` | `true` / `false` | The component was extracted from a built binary (e.g. a Go binary, a .NET PE, the Linux kernel image). |
| `bsi:component:archive` | `true` / `false` | The component was extracted from a packed archive (e.g. a JAR, a NuGet `.nupkg`, a macOS `.app` bundle). |
| `bsi:component:structured` | `true` / `false` | The component was extracted from a structured manifest or database (e.g. a lockfile, a dpkg/rpm database, the Windows registry, a `.csproj`). |

Notes:

- The three boolean flags are **not mutually exclusive** — a component can be
  both `archive` and `structured`, for example.
- When several extractors (or several install locations / image layers) report
  the same component, the flags are **OR'd** across all of them: if any source
  is an archive, `archive` is `true`.

## `kunnus:layer:*` — container layer attribution

Present **only for container scans** (`kunnus sbom container`), where scalibr
traces which image layer each package came from. Absent for repo and OS scans,
which have no layer dimension.

The singular keys describe the **introducing layer** — the lowest-index layer
the package appears in. When a package occupies more than one layer, the plural
keys list the full set so no layer attribution is lost.

| Key | Value | Meaning |
|---|---|---|
| `kunnus:layer:index` | an integer string | Index of the introducing (lowest) layer. |
| `kunnus:layer:diffid` | a digest (`sha256:…`) | DiffID of the introducing layer. Omitted when unknown. |
| `kunnus:layer:command` | a string | The build command (Dockerfile instruction) that produced the introducing layer. Omitted when unknown. |
| `kunnus:layer:in_base_image` | `true` / `false` | Whether the introducing layer belongs to a detected base image. |
| `kunnus:layer:indices` | comma-joined integers (e.g. `0,3`) | Every distinct layer index the package occupies, ascending. Emitted **only** when the package spans more than one layer. |
| `kunnus:layer:diffids` | comma-joined digests | The DiffID of each layer the package occupies, in ascending index order. Emitted **only** when the package spans more than one layer. |

Notes:

- A package present in a single layer emits only the singular keys; the absence
  of `kunnus:layer:indices` means "one layer — see `kunnus:layer:index`".
- The per-layer **command** is deliberately not aggregated into a plural key: a
  build command can contain commas (breaking the comma-joined form) and is
  recoverable from the image config via the layer's DiffID.

## `kunnus:vendored:*` — vendored C/C++ source attribution

Present **only for repo scans** (`kunnus sbom repo`), on the synthetic
`pkg:generic/…` components kunnus creates for vendored C/C++ library directories
(`third_party/`, `libs/`, …). One property is emitted per source file.

| Key | Value | Meaning |
|---|---|---|
| `kunnus:vendored:file` | `<path>:<algorithm>:<hex>` | One per fingerprinted source file in the vendored library. Records the per-file digest the platform uses to recover which file each `component.hashes[]` entry belongs to. `algorithm` is e.g. `MD5`; `path` is relative to the library directory, posix-separated. |

## BSI TR-03183-2 conformance baseline

CI gates on the BSI v2 conformance score of generated SBOMs via
[sbomqs](https://github.com/interlynk-io/sbomqs) (the `compliance` job / `make
compliance`). It scores two surfaces with `sbomqs compliance --bsi-v2`, each
with its own required-elements floor:

- **repo** — `sbom repo testdata/ecosystems`, baseline required ≈ 5.25 / 10.
- **os** — `sbom os --target-os linux testdata/osfamilies/alpine`, baseline
  required ≈ 7.4 / 10.

The two differ mainly on **licences** and per-package hashes. Licences are
sourced from package data (OS extractors, Debian copyright files, lockfiles,
installed manifests, and optionally deps.dev) and normalized to SPDX in
`internal/license` — see [licenses.md](licenses.md) for the full per-ecosystem
coverage. The OS surface scores higher mainly because its hashes and licences
are more consistently available.

Remaining required-field gaps, in priority order:

- **Deployable hash** — present only where a lockfile supplies one; spec permits
  omission when unavailable.

Component creator is now derived for every ecosystem in the corpus (see
`supplier.go`); sbomqs accepts our CycloneDX `supplier` for this field. Vendored
C/C++ (`pkg:generic`) deliberately carries no creator — a local vendored copy
has no upstream supplier to assert.

Optional fields we deliberately do not emit (signature, source-code URI,
deployable-form URI) lower the optional score but not conformance.

When a gap closes, raise the matching threshold in
`.github/workflows/compliance-action/action.yml` to lock in the gain.

## Where component locations live

Because the property table above only carries a single `bsi:component:filename`,
it is worth restating: the **authoritative, complete** list of where a component
was found is `component.evidence.occurrences[]`, one entry per location. When
kunnus deduplicates components that share a PURL, it merges (unions) their
occurrences, so multiple install paths for the same package version are all
preserved there.
