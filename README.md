# kunnus

**Open-source SBOM generation for manufacturers who need to know what software runs on their machines.**

Starting December 11, 2027, the [EU Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) requires manufacturers of products with digital elements to provide a Software Bill of Materials (SBOM) — a complete, machine-readable inventory of all software components in the product. This applies to every product newly placed on the market after that date: CNC machines with embedded IPCs, IoT gateways, AGVs, packaging lines with web dashboards — if it contains software, you need an SBOM.

kunnus-scanner generates that SBOM. No installer, no cloud connection, no account required. It runs on Windows, Linux, and macOS, detects installed software down to individual libraries and version numbers, and outputs standard-compliant SPDX or CycloneDX files. It is built on Google's [osv-scalibr](https://github.com/google/osv-scalibr) and supports over 30 language ecosystems and OS-level package detection.

Beyond generating SBOMs, kunnus automatically checks every detected component against the [OSV vulnerability database](https://osv.dev/). You see immediately whether your machine image ships a library with known CVEs — before you deliver.

## Quick start

```shell
# Install (macOS / Linux)
brew install think-ahead-technologies/tap/kunnus

# Generate an SBOM
kunnus sbom

# Save to file
kunnus sbom --output sbom.spdx.json
```

That's it. Your first SBOM in under three minutes. Also available via [Scoop (Windows)](#scoop-windows), [Docker](#docker), or as a [prebuilt binary](#prebuilt-binaries).

## Use cases

### Industrial PC on a machine tool

Your machining center ships with a Windows IPC running your HMI, OPC UA server, drivers, and various utilities. Nobody has a complete list of what's installed. Copy the kunnus binary to a USB stick, plug it into the IPC, and run:

```shell
kunnus sbom --include-os --format spdx-2-3 --output machine-x200.spdx.json
```

You get a complete inventory — every installed program, every library, every OS package with exact version numbers. Standard-compliant. No network connection needed.

### Automated CI/CD pipeline for IoT devices

Your IoT gateway firmware is built in a CI/CD pipeline with weekly releases and dozens of open-source dependencies. A manually maintained SBOM is outdated the moment you create it. Integrate kunnus into your GitHub Actions workflow and every release gets a current SBOM automatically:

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
  with:
    output: sbom.cdx.json

- uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
  with:
    file: sbom.cdx.json
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: ${{ vars.KUNNUS_COMPONENT_ID }}
    version: ${{ github.ref_name }}
```

### AGVs and mobile robots

AGVs with Linux-based navigation stacks, ROS middleware, and fleet management dashboards are clearly products with digital elements under the CRA. kunnus provides multi-arch Docker images (amd64/arm64), so you can scan directly on the ARM-based vehicle computer:

```shell
docker run --rm -v /opt/agv-software:/scan \
  ghcr.io/think-ahead-technologies/kunnus-scanner \
  sbom --include-os --format cyclonedx-1-5 --output /scan/agv-sbom.cdx.json
```

## Why open source?

Every manufacturer has a different software stack. Proprietary runtimes, custom configuration formats, specialized control platforms — no tool covers every edge case from day one.

kunnus-scanner is open source under **Apache 2.0**. That means:

- **No procurement process needed.** Download it today and generate your first SBOM before the purchase order would have been written.
- **Adaptable to your stack.** Your team — or a service provider — can contribute parsers for your specific environment.
- **Transparent and auditable.** You can trace exactly how the SBOM is generated. For auditors and market surveillance authorities, that matters.

## Beyond the SBOM file

The CRA requires more than a one-time SBOM: continuous vulnerability monitoring, documented risk assessments, and notification obligations over the entire support period of your product.

The [kunnus platform](https://kunnus.tech) handles that. Upload your SBOMs and monitor the security status of all your products centrally. New CVE in a dependency? Automatic notification. Market surveillance authority asks for documentation? Everything on record.

---

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

| Flag            | Description                                                             |
| --------------- | ----------------------------------------------------------------------- |
| `--quiet`, `-q` | Suppress progress and summary output on stderr; only errors are printed |
| `--verbosity`   | Log verbosity level (`error`, `warn`, `info`, `debug`); default `warn`  |

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
