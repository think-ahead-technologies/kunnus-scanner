# kunnus-scanner

**Open-source SBOM generation for manufacturers who need to know what software runs on their machines.**

Starting December 11, 2027, the [EU Cyber Resilience Act (CRA)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) requires manufacturers of products with digital elements to provide a Software Bill of Materials (SBOM) — a complete, machine-readable inventory of all software components in the product. This applies to every product newly placed on the market after that date: CNC machines with embedded IPCs, IoT gateways, AGVs, packaging lines with web dashboards — if it contains software, you need an SBOM.

kunnus-scanner generates that SBOM. No installer, no cloud connection, no account required. It runs on Windows, Linux, and macOS, detects installed software down to individual libraries and version numbers, and outputs standard-compliant CycloneDX 1.7 files. It is built on Google's [osv-scalibr](https://github.com/google/osv-scalibr) and supports a broad set of language ecosystems and OS-level package detection.

## Quick start

```shell
# Install (macOS / Linux)
brew install think-ahead-technologies/tap/kunnus

# Scan a source-code repository
kunnus sbom repo

# Scan the running OS / firmware image
kunnus sbom os --output machine.cdx.json
```

That's it. Your first SBOM in under three minutes. Also available as a [Docker image](https://github.com/think-ahead-technologies/kunnus-scanner/pkgs/container/kunnus-scanner), via [Scoop on Windows](https://github.com/think-ahead-technologies/scoop-bucket), or as a [prebuilt binary](https://github.com/think-ahead-technologies/kunnus-scanner/releases).

## Use cases

### Industrial PC on a machine tool

Your machining center ships with a Windows IPC running your HMI, OPC UA server, drivers, and various utilities. Nobody has a complete list of what's installed. Copy the `kunnus` binary to a USB stick, plug it into the IPC, and run:

```shell
kunnus sbom os --output machine-x200.cdx.json
```

You get a complete inventory — every installed program, every library, every OS package with exact version numbers. Standard-compliant. No network connection needed.

### Automated CI/CD pipeline for IoT devices

Your IoT gateway firmware is built in a CI/CD pipeline with weekly releases and dozens of open-source dependencies. A manually maintained SBOM is outdated the moment you create it. Pull the multi-arch Docker image into your GitHub Actions workflow and every release gets a current SBOM automatically:

```yaml
- name: Generate SBOM
  run: |
    docker run --rm -v ${{ github.workspace }}:/src \
      ghcr.io/think-ahead-technologies/kunnus-scanner:latest \
      sbom repo /src --output /src/sbom.cdx.json

- name: Upload to kunnus platform
  env:
    KUNNUS_API_KEY: ${{ secrets.KUNNUS_API_KEY }}
    KUNNUS_COMPONENT_ID: ${{ vars.KUNNUS_COMPONENT_ID }}
  run: |
    docker run --rm -v ${{ github.workspace }}:/src \
      -e KUNNUS_API_KEY -e KUNNUS_COMPONENT_ID \
      ghcr.io/think-ahead-technologies/kunnus-scanner:latest \
      upload /src/sbom.cdx.json
```

### AGVs and mobile robots

AGVs with Linux-based navigation stacks, ROS middleware, and fleet management dashboards are clearly products with digital elements under the CRA. kunnus-scanner ships multi-arch Docker images (amd64/arm64), so you can scan directly on the ARM-based vehicle computer:

```shell
docker run --rm -v /opt/agv-software:/scan \
  ghcr.io/think-ahead-technologies/kunnus-scanner \
  sbom os /scan --output /scan/agv-sbom.cdx.json
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

## What it does

- **`kunnus sbom repo [path]`** — scan a source-code tree, auto-detect ecosystems (npm, Go, Cargo, NuGet, Maven, Python, …), emit CycloneDX 1.7.
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
  sbom/            # inventory -> CycloneDX encoder
  hashes/          # native component-content hashes from lockfiles (BSI TR-03183-2)
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
