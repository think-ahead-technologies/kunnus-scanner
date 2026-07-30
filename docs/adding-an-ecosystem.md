# Adding an ecosystem

Every language ecosystem kunnus understands lives in one registry:
`internal/ecosystem/`. Detection, plugin selection, hash mining, and licence
mining all derive from a single `Ecosystem` entry, and invariant tests keep
them from drifting apart. This guide walks through adding one — first the
common scalibr-backed case, then the native-extractor case for formats scalibr
doesn't cover.

Work test-first: the drift guards are designed so that a half-wired ecosystem
turns the suite red, and the fixture you write in step 2 doubles as the
integration and e2e test input.

## Case 1: scalibr already has an extractor

### 1. Add the registry entry

Create `internal/ecosystem/<name>.go` with a `var` of type `Ecosystem`
(see `internal/ecosystem/cargo.go` for a complete example):

- **`Name`** — the stable identifier; shows up in `--ecosystem` and detection
  output.
- **`Filenames`** / **`FilenameSuffixes`** — the marker files that flag the
  ecosystem during the repo walk (matched case-insensitively).
- **`ScalibrPlugins`** — the scalibr extractor names to enable, imported as
  `<pkg>.Name` constants so typos can't compile.
- **`InstalledPlugins`** — the subset that reports *installed* state (compiled
  binaries, unpacked archives) rather than declared dependencies. Container
  scans run only these. Leave empty if scalibr has only source extractors for
  the ecosystem; an invariant test enforces `InstalledPlugins ⊆
  ScalibrPlugins`.
- **`HashParsers`** (optional) — if the lockfile embeds content digests, a
  parser that returns a `hashes.Map` keyed by purl (BSI TR-03183-2 wants
  component hashes). Parser filenames must appear in `Filenames` — another
  invariant test.
- **`LicenseParsers`** (optional) — same shape, for lockfiles that embed
  per-package licences scalibr doesn't surface (see `composer.go`).
- **`GraphParsers`** (optional) — same shape again, returning a `graph.Map`
  (purl → dependsOn purls) for lockfiles that pin the resolved dependency
  graph (see `cargo.go`, `composer.go`). Only emit an edge whose *target* the
  lockfile itself pins — never invent a purl for an unresolvable requirement.

Register the entry in the `All()` slice in `ecosystem.go`.

### 2. Add the fixture

Create `testdata/ecosystems/<name>/` containing:

- a **real** manifest/lockfile — taken from an actual project, not
  hand-minimised to the point of being synthetic; and
- a `want.txt` listing the exact `purl` (and `cpe`, where applicable) lines
  the scanner must emit for it.

No mocks, ever — this corpus is what the unit tests, the scan-seam
integration tests, and the binary e2e tests all read.

### 3. Run the drift guards

```shell
make test
```

Three layers pick the new entry up automatically:

- `internal/ecosystem` invariant tests (unique name, detectable parser
  filenames, plugin subset rules);
- `internal/scan/*_integration_test.go` loops over `ecosystem.All()`, plans
  via `mode/repo`, runs real scalibr, and asserts your `want.txt` purls appear
  — a registry entry without a fixture fails here;
- `cmd/kunnus/*_test.go` scans the whole corpus with the real binary and
  asserts purls **and** cpes in the CycloneDX output.

If all three are green, you're done — no wiring beyond the registry entry is
needed for a scalibr-backed ecosystem.

## Case 2: scalibr has no extractor (native extractor)

For formats scalibr doesn't cover (vcpkg, ModusToolbox, Zephyr, …) kunnus
carries its own `filesystem.Extractor`. The pattern keeps detection and
plugin selection in one place while the `ecosystem` package stays free of
scalibr APIs (architecture rule #1 in AGENTS.md):

1. **Registry entry with `NativeExtractor: true`** instead of
   `ScalibrPlugins` (see `internal/ecosystem/vcpkg.go`). The completeness
   invariant accepts either — an ecosystem can never be detected yet produce
   nothing. The entry names no extractor instance.
2. **The extractor package**: `internal/<name>/`, implementing scalibr's
   `filesystem.Extractor` interface (`FileRequired` selects candidate files,
   `Extract` parses them into packages). Follow an existing one —
   `internal/vcpkg/` or `internal/zephyr/` are good templates. Document the
   purl scheme and any deliberately-ignored fields in the package's doc
   comment.
3. **Wire it in `mode/repo`**: add a branch to `nativeExtractorsFor()` in
   `internal/mode/repo/repo.go` mapping the detected ecosystem name to
   `<name>.New()`. The mode owns the name→instance mapping so the registry
   stays scalibr-free.
4. **Fixture + `want.txt`** exactly as in case 1 — the same three test layers
   cover native extractors.

Design rules that apply to every native extractor:

- **No network.** A declared version range or git tag is recorded verbatim;
  resolving it against a registry is out of scope by design.
- **No interpretation.** If identity fields contain unresolvable variables
  (`${...}` interpolation, CMake variables), drop the component rather than
  guess — false positives cost more than gaps.
- **Purl types**: `pkg:github/<owner>/<repo>` when the source is a github.com
  URL, the ecosystem's registered purl type when one exists (`pkg:vcpkg`),
  `pkg:generic` otherwise.
- Duplicate declarations across sub-projects are fine — they collapse in the
  SBOM dedup stage.

## Checklist

- [ ] `internal/ecosystem/<name>.go` entry, registered in `All()`
- [ ] Real fixture in `testdata/ecosystems/<name>/` with `want.txt`
- [ ] (native only) `internal/<name>/` extractor + `nativeExtractorsFor` branch
- [ ] (if the lockfile has digests) `HashParsers` entry
- [ ] (if the lockfile has licences) `LicenseParsers` entry, and a row in
      `docs/licenses.md`
- [ ] (if the lockfile pins the resolved graph) `GraphParsers` entry
- [ ] README "Supported ecosystems" section updated
- [ ] `make all` green
