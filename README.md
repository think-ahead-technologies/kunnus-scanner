# kunnus

SBOM generation and upload for your software supply chain.

kunnus generates Software Bill of Materials (SBOMs) for your projects and uploads them to the [kunnus platform](https://kunnus.tech). It is built on [osv-scalibr](https://github.com/google/osv-scalibr) and supports a wide range of languages and package managers.

Beyond raw SBOM generation, kunnus adds convenience for manufacturers who need to meet EU Cyber Resilience Act (CRA) compliance obligations: automated upload to the [kunnus platform](https://kunnus.tech), CI/CD integration, and ongoing features that make compliance easier to achieve and maintain. The kunnus platform uses the uploaded SBOMs to track and manage vulnerabilities across your products, giving you full insights into your product's complete bill of materials.

## Installation

### Homebrew (macOS / Linux)

```shell
brew install think-ahead-technologies/tap/kunnus
```

### Scoop (Windows)

```shell
scoop bucket add think-ahead-technologies https://github.com/think-ahead-technologies/scoop-bucket
scoop install kunnus
```

### Docker

```shell
# Generate an SBOM for the current directory
docker run --rm -v $(pwd):/src ghcr.io/think-ahead-technologies/kunnus-scanner sbom /src

# Generate and save to file
docker run --rm -v $(pwd):/src ghcr.io/think-ahead-technologies/kunnus-scanner sbom --output /src/sbom.spdx.json /src

# Upload an SBOM
docker run --rm -v $(pwd):/src \
  -e KUNNUS_API_KEY=$KUNNUS_API_KEY \
  -e KUNNUS_COMPONENT_ID=$KUNNUS_COMPONENT_ID \
  ghcr.io/think-ahead-technologies/kunnus-scanner upload /src/sbom.spdx.json
```

### Prebuilt binaries

Download the latest release for your platform from the [releases page](https://github.com/think-ahead-technologies/kunnus-scanner/releases).

### From source

```shell
git clone https://github.com/think-ahead-technologies/kunnus-scanner.git
cd kunnus-scanner
go build -o kunnus ./cmd/kunnus
```

## Usage

### Global flags

These flags apply to all subcommands:

| Flag              | Description                                                            |
| ----------------- | ---------------------------------------------------------------------- |
| `--quiet`, `-q`   | Suppress progress and summary output on stderr; only errors are printed |
| `--verbosity`     | Log verbosity level (`error`, `warn`, `info`, `debug`); default `warn` |

### Generate an SBOM

```shell
# Scan current directory (default: spdx-2-3 format)
kunnus sbom

# Scan specific directories
kunnus sbom ./path/to/project

# Choose SBOM format
kunnus sbom --format cyclonedx-1-5

# Write SBOM to a file
kunnus sbom --output sbom.spdx.json

# Include OS-level packages (e.g. Windows registry) in the SBOM
kunnus sbom --include-os
```

Supported formats: `spdx-2-3` (default), `cyclonedx-1-4`, `cyclonedx-1-5`.

| Flag                                   | Default    | Description                                               |
| -------------------------------------- | ---------- | --------------------------------------------------------- |
| `--format`, `-f`                       | `spdx-2-3` | SBOM output format                                        |
| `--output`, `-o`                       | —          | Save SBOM to file; writes to stdout if omitted            |
| `--recursive` / `--no-recursive`       | on         | Scan subdirectories                                       |
| `--all-packages` / `--no-all-packages` | on         | Include all packages, not just vulnerable ones            |
| `--offline-vulnerabilities`            | off        | Use locally cached vulnerability databases                |
| `--include-os`                         | off        | Include OS-level packages (e.g. Windows registry) in SBOM |

### Upload an SBOM

```shell
kunnus upload sbom.spdx.json \
  --api-key $KUNNUS_API_KEY \
  --component-id $KUNNUS_COMPONENT_ID \
  --version 1.2.3
```

| Flag                   | Env var               | Description                                                        |
| ---------------------- | --------------------- | ------------------------------------------------------------------ |
| `--api-key`, `-k`      | `KUNNUS_API_KEY`      | API key for the kunnus platform                                    |
| `--component-id`, `-c` | `KUNNUS_COMPONENT_ID` | Target component ID                                                |
| `--version`            | —                     | Version label for the SBOM                                         |
| `--url`                | `KUNNUS_URL`          | API endpoint (default: `https://app.kunnus.tech/api/sboms/upload`) |
| `--source`             | —                     | Source label (auto-detected in CI: `CiPipeline`, otherwise `CLI`)  |
| `--mark-as-current`    | —                     | Mark this SBOM as the current version (default: `true`)            |

## GitHub Actions

### Generate SBOM

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
  with:
    output: sbom.spdx.json
```

### Upload SBOM

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
  with:
    file: sbom.spdx.json
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: ${{ vars.KUNNUS_COMPONENT_ID }}
    version: ${{ github.sha }}
```

### Generate and upload in one job

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
        with:
          output: sbom.spdx.json

      - uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
        with:
          file: sbom.spdx.json
          version: ${{ github.ref_name }}
          api-key: ${{ secrets.KUNNUS_API_KEY }}
          component-id: ${{ vars.KUNNUS_COMPONENT_ID }}
```

## Attribution

kunnus is a soft fork of [osv-scanner](https://github.com/google/osv-scanner) (Apache 2.0) by Google. We aim to keep this fork in sync with upstream to benefit from ongoing improvements to the scanner and its ecosystem.
