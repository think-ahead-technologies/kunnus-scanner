# kunnus-scanner

A slim SBOM-generation CLI built directly on [osv-scalibr](https://github.com/google/osv-scalibr).
Replaces the previous osv-scanner fork for the kunnus platform.

## What it does

- **`kunnus sbom repo [path]`** — scan a source-code tree, auto-detect ecosystems (npm, Go, Cargo, NuGet, Maven, Python, …), emit SPDX 2.3 or CycloneDX 1.5.
- **`kunnus sbom os [path]`** — scan an OS or firmware filesystem (auto-detects Linux distro family or Windows registry).
- **`kunnus upload <file>`** — push an SBOM to `app.kunnus.tech`.

Override flags (`--target-os`, `--ecosystem`, `--enable`, `--disable`) let you bypass auto-detection.

## Architecture

```
cmd/kunnus/        # binary entry point
internal/
  command/         # urfave/cli subcommand wiring
  mode/            # repo + os scan-flavour implementations
  detect/          # pure host/filesystem introspection (no scalibr imports)
  scan/            # thin scalibr.Scan() wrapper
  sbom/            # inventory -> SPDX / CycloneDX encoder
  upload/          # multipart POST to the platform
  version/
```

Cohesion contract: the `detect` package has zero scalibr imports;
the `scan` package is the only one that runs scalibr; the `command`
package is the only one that touches `urfave/cli`.

## Build

```
make build         # produces ./bin/kunnus
make test          # go test ./...
make lint          # golangci-lint run ./...
make fmt           # gofmt -s -w .
```
