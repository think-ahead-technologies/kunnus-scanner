# Contributing to kunnus-scanner

Thanks for helping manufacturers get their SBOMs right. This document covers
the mechanics; the architectural ground rules live in [AGENTS.md](AGENTS.md)
and are enforced in code review — read them before touching `internal/`.

## Development setup

You need Go (the version pinned in [`go.mod`](go.mod)) and `make`.

```shell
git clone https://github.com/think-ahead-technologies/kunnus-scanner
cd kunnus-scanner
make build         # produces ./bin/kunnus
make test          # go test -race -count=1 ./...
make lint          # golangci-lint run ./...
make fmt           # gofmt -s -w .
make all           # fmt + vet + lint + test + build — run before pushing
```

`make cover` produces a coverage profile that includes the binary e2e tests
(they merge counters via `GOCOVERDIR`); `make compliance` builds the binary
and scans the fixture corpus end to end; `make fuzz` runs the parser fuzz
targets (`FUZZTIME=30s` per target by default).

## How we work

- **TDD, no mocks.** Write the failing test first, then the code. Every
  boundary is tested against real fixtures and real I/O — real lockfiles,
  real package databases, real container images built in-memory. If you find
  yourself writing a mock, stop and find the real fixture instead.
- **Small, focused changes.** One concern per PR. Refactors ride separately
  from behaviour changes.
- **Respect the cohesion contract.** `internal/scan` is the only package that
  runs scalibr; `internal/command` is the only one that imports `urfave/cli`;
  `internal/detect` stays scalibr-free. The full package-by-package table is
  in AGENTS.md.
- **Every code file starts with two `ABOUTME:` comment lines** describing
  what the file does.
- **Conventional commits**, imperative mood, present tense:
  `feat: add zephyr west.yml extractor`, `fix: tolerate corrupt rpm database`.

## Tests you are expected to add

The test suite is layered, and drift guards make missing coverage a hard
failure rather than a review nitpick:

1. **Unit tests** next to the code, against real fixture files.
2. **Fixture corpus**: `testdata/ecosystems/<name>/` (or
   `testdata/osfamilies/<name>/`) with a real manifest/lockfile and a
   `want.txt` listing the exact purls and cpes the scanner must emit.
3. **Scan-seam integration** (`internal/scan/*_integration_test.go`) and the
   **binary e2e** (`cmd/kunnus/*_test.go`) both iterate over the registries —
   a new registry entry without a fixture turns the suite red automatically.

Adding a new ecosystem? The step-by-step walkthrough is in
[docs/adding-an-ecosystem.md](docs/adding-an-ecosystem.md).

## Pull requests

- Run `make all` locally; CI runs the same checks.
- Describe *why*, not just *what* — especially for parser edge cases, link
  the spec or real-world file that motivated them.
- New behaviour needs docs: user-visible changes touch the README or
  `docs/`, new SBOM properties touch `docs/sbom-properties.md`, new licence
  sources touch `docs/licenses.md`.

## Reporting issues

Bugs and feature requests go through
[GitHub issues](https://github.com/think-ahead-technologies/kunnus-scanner/issues).
For anything with security impact, use the private reporting channel in
[SECURITY.md](SECURITY.md) instead.
