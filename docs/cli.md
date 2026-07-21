# CLI reference

```
kunnus [--verbosity <level>] <command> [flags] [args]
```

Operational output (logs, warnings) always goes to **stderr**; stdout carries
the SBOM payload (or the server response for `upload`), so every command is
pipe-safe. Shell completion is built in (`kunnus completion --help`).

## Global flags

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--verbosity` | `KUNNUS_VERBOSITY` | `warn` | Log level: `debug` \| `info` \| `warn` \| `error` |
| `--version` | | | Print version, commit, and build date |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean scan — every plugin ran without failure |
| 1 | Error, **or** a degraded scan: the SBOM was still written, but one or more plugins failed (the error message lists them; re-run with `--verbosity info` for per-plugin detail) |

## Shared `sbom` flags

Accepted by all three `sbom` subcommands:

| Flag | Default | Description |
|---|---|---|
| `--output`, `-o` | stdout | Write the SBOM to a file |
| `--enable` | | Add a scalibr plugin by name (repeatable) |
| `--disable` | | Remove a scalibr plugin by name (repeatable) |
| `--online-licenses` | off | Look up component licences via deps.dev — the only scan feature that uses the network |

Output format is always CycloneDX 1.6 (BSI TR-03183-2 conformant).

## `kunnus sbom repo [path]`

Generate an SBOM for a source-code repository. `path` defaults to `.`.

| Flag | Default | Description |
|---|---|---|
| `--ecosystem` | auto-detect | Restrict to specific ecosystems (repeatable; e.g. `npm`, `dotnet`, `python`) |

```shell
kunnus sbom repo                                   # scan the current directory
kunnus sbom repo ~/src/firmware -o firmware.cdx.json
kunnus sbom repo --ecosystem npm --ecosystem python
```

## `kunnus sbom os [path]`

Generate an SBOM for an OS or firmware filesystem. `path` defaults to the
filesystem root (`/` on Unix, `C:\` on Windows).

| Flag | Default | Description |
|---|---|---|
| `--target-os` | host OS | Override host auto-detection: `linux` \| `windows` \| `mac` — needed when scanning a foreign rootfs (e.g. a Linux firmware image mounted on a Mac) |

```shell
kunnus sbom os -o machine.cdx.json
kunnus sbom os /mnt/firmware --target-os linux -o firmware.cdx.json
```

## `kunnus sbom container <image-ref | tarball-path>`

Generate an SBOM for a container image, with per-layer attribution. Alias:
`kunnus sbom image`.

| Flag | Default | Description |
|---|---|---|
| `--source` | `auto` | Where to get the image: `auto` \| `remote` (registry pull) \| `tarball` (docker-save/OCI archive) \| `docker` (local daemon) |

```shell
kunnus sbom container alpine:3.20 -o alpine.cdx.json
kunnus sbom container ./image.tar -o image.cdx.json
kunnus sbom container myapp:dev --source docker
```

## `kunnus upload <sbom-file>`

Upload an SBOM file to the kunnus platform. Prints the server response to
stdout.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--api-key` (required) | `KUNNUS_API_KEY` | | API key for the kunnus platform |
| `--component-id` | `KUNNUS_COMPONENT_ID` | | Associate the SBOM with this platform component |
| `--url` | `KUNNUS_UPLOAD_URL` | `https://app.kunnus.tech/api/sboms/upload` | Upload endpoint |

```shell
kunnus upload sbom.cdx.json --api-key "$KUNNUS_API_KEY" --component-id "$KUNNUS_COMPONENT_ID"
```

On upload errors the response body is logged at `info` level rather than
printed — re-run with `--verbosity info` to see it.
