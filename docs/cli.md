# CLI reference

```
kunnus [--verbosity <level>] <command> [flags] [args]
```

Operational output (logs, warnings) always goes to **stderr**; stdout carries
the SBOM payload (or the server response for `upload`), so every command is
pipe-safe. Shell completion is built in — see [Shell completion](#shell-completion).

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

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--output`, `-o` | | stdout | Write the SBOM to a file |
| `--enable` | | | Add a scalibr plugin by name (repeatable) |
| `--disable` | | | Remove a scalibr plugin by name (repeatable) |
| `--online-licenses` | | off | Look up component licences via deps.dev — the only scan feature that uses the network |
| `--component-id` | `KUNNUS_COMPONENT_ID` | | Stable component identity; scans sharing an id + version reuse one `serialNumber` (a document series — see [serial-numbers.md](serial-numbers.md)) |
| `--component-version` | `KUNNUS_COMPONENT_VERSION` | | Component version, for the SBOM root component and the serial-number series |
| `--author` | `KUNNUS_AUTHOR` | Kunnus, with a warning | SBOM author — the entity running the scan, as `"Name"` or `"Name <email>"`; lands in `metadata.authors` and `metadata.manufacturer` |
| `--serial-number` | `KUNNUS_SERIAL_NUMBER` | derived | Explicit `serialNumber` (UUID, bare or `urn:uuid:` form); overrides derivation from `--component-id` |

Output format is always CycloneDX 1.6 (BSI TR-03183-2 conformant). Every SBOM
records its generation context in `metadata.lifecycles`: `pre-build` for
`repo` (source analysis), `post-build` for `os` and `container`
(built-artifact analysis). Pass `--author` to record your organization as the
SBOM author (CISA's SBOM Author element is the entity *operating* the tool);
unset, the document carries the Kunnus identity and the CLI warns that you are
shipping a placeholder author. Without
identity flags each run gets a fresh random `serialNumber`; supply
`--component-id` (or scan a container registry reference, which carries its
own identity) to make rescans form a stable document series —
[serial-numbers.md](serial-numbers.md) has the full story.

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

## Shell completion

**Homebrew, `.deb` and `.rpm` installs need no setup** — they drop bash, zsh and
fish completions into the standard directories, active in the next shell. The
rest of this section is for the tarball, `go install`, and powershell.

`kunnus completion <shell>` prints a completion script for `bash`, `zsh`,
`fish`, or `pwsh`. Install it once per shell:

```shell
# zsh — add to ~/.zshrc
source <(kunnus completion zsh)

# bash — add to ~/.bashrc
source <(kunnus completion bash)

# fish — one-off, picked up automatically from then on
kunnus completion fish > ~/.config/fish/completions/kunnus.fish

# powershell — add to $PROFILE
kunnus completion pwsh | Out-String | Invoke-Expression
```

Sourcing on every shell start costs a `kunnus` exec. To pay it once, write the
script to a file and source that instead, regenerating it when you upgrade:

```shell
kunnus completion zsh > ~/.kunnus-completion.zsh   # then: source ~/.kunnus-completion.zsh
```

The script holds no knowledge of kunnus itself — on TAB it re-runs the binary
with the words typed so far, so completion always matches the installed
version. Subcommands, their aliases (`sbom image` as well as `sbom container`),
and flags all complete, each shown with the description from `--help`. Where a
command takes a path rather than a subcommand — `sbom repo`, `sbom os`,
`sbom container` with a tarball, `upload` — kunnus offers nothing so the shell
falls back to its own file completion.

Two caveats. The powershell script takes its command name from the filename it
is saved under, so save it as `kunnus.ps1` if you write it to disk rather than
piping it to `Invoke-Expression`. And on macOS, bash completion needs the
`bash-completion` package (`brew install bash-completion`) — zsh, the default
shell, needs nothing extra.
