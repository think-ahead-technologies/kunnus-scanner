# Getting started

This guide takes you from installation to your first uploaded SBOM. For the
full flag reference see [cli.md](cli.md).

## Install

```shell
# macOS (Homebrew cask)
brew install think-ahead-technologies/tap/kunnus

# Linux — grab a prebuilt binary from the releases page (below),
# or use the Docker image

# Windows
scoop bucket add think-ahead https://github.com/think-ahead-technologies/scoop-bucket
scoop install kunnus

# Docker (multi-arch: amd64/arm64)
docker pull ghcr.io/think-ahead-technologies/kunnus-scanner:latest
```

Prebuilt binaries for every platform are on the
[releases page](https://github.com/think-ahead-technologies/kunnus-scanner/releases) —
a single static binary, no installer, no runtime dependencies. Verify it works:

```shell
kunnus --version
```

## Your first scan

kunnus has three scan modes. Pick the one that matches what you're pointing
it at:

| You have… | Use |
|---|---|
| A source-code checkout (lockfiles, manifests) | `kunnus sbom repo` |
| A running machine or an extracted firmware/OS filesystem | `kunnus sbom os` |
| A container image (registry, tarball, or docker daemon) | `kunnus sbom container` |

### Scan a source repository

```shell
cd my-project
kunnus sbom repo --output sbom.cdx.json
```

kunnus walks the tree, auto-detects every ecosystem present (npm, Python, Go,
Cargo, Maven, embedded firmware manifests, … — see the README for the full
list), and emits a CycloneDX 1.6 SBOM. Without `--output` the SBOM goes to
stdout, so you can pipe it; all log output goes to stderr.

### Scan an operating system

```shell
# The machine you're standing on (default root: / on Unix, C:\ on Windows)
kunnus sbom os --output machine.cdx.json

# A mounted firmware image or extracted rootfs
kunnus sbom os /mnt/firmware --output firmware.cdx.json

# A Linux rootfs while running on your Mac
kunnus sbom os /path/to/rootfs --target-os linux --output rootfs.cdx.json
```

On Linux targets kunnus fingerprints the distro family (Debian, RHEL, SUSE,
Alpine, Arch, Gentoo, Nix, …) and reads its package database; on Windows it
reads the registry. It also surfaces non-packaged binaries — software
compiled straight onto the image that no package manager knows about.

#### Mounting a firmware image

`kunnus sbom os` scans a directory tree, so a firmware image file first needs
to be mounted (or extracted). All of the following are read-only — kunnus
never writes to the scan root, and `-o ro` makes sure nothing else does
either.

**Raw or single-partition image** (`.img`, `.ext4`, `.bin` that is a plain
filesystem):

```shell
sudo mkdir -p /mnt/firmware
sudo mount -o ro,loop firmware.img /mnt/firmware
kunnus sbom os /mnt/firmware --target-os linux --output firmware.cdx.json
sudo umount /mnt/firmware
```

**Disk image with a partition table** (a full eMMC/SD dump): let the loop
device expose the partitions, then mount the rootfs partition — usually the
largest one:

```shell
sudo losetup -f --show -P firmware.img     # prints e.g. /dev/loop0
lsblk /dev/loop0                           # find the rootfs partition
sudo mount -o ro /dev/loop0p2 /mnt/firmware
kunnus sbom os /mnt/firmware --target-os linux --output firmware.cdx.json
sudo umount /mnt/firmware && sudo losetup -d /dev/loop0
```

**SquashFS** (very common in embedded firmware — OpenWrt, appliance images):

```shell
sudo mount -o ro,loop rootfs.squashfs /mnt/firmware
# or, without root privileges:
unsquashfs -d rootfs rootfs.squashfs && kunnus sbom os ./rootfs --target-os linux
```

**Vendor update packages** (`.swu`, `.raucb`, zip/tar containers) usually
wrap one of the above — unpack the container first (`cpio`, `tar`, `unzip`),
then mount the filesystem image found inside. When the format is unknown,
[binwalk](https://github.com/ReFirmLabs/binwalk) (`binwalk -e firmware.bin`)
finds and extracts embedded filesystems; scan the extracted directory.

**On macOS or Windows** there is no loop mount for Linux filesystems — extract
instead of mounting: `7z x firmware.img`, `unsquashfs`, or binwalk all work,
and `--target-os linux` tells kunnus what it's looking at regardless of the
host. Alternatively mount inside a Linux container and run the Docker image
against it.

Two things to double-check on embedded targets:

- Scan the **rootfs**, not the boot partition — the package database
  (`var/lib/dpkg`, `lib/apk/db`, …) is what drives OS-package detection.
- If the device splits the OS across partitions (A/B update schemes, separate
  `/usr`), mount the full set the way the device would, or scan each mount
  and merge downstream.

### Scan a container image

```shell
kunnus sbom container alpine:3.20 --output alpine.cdx.json     # registry pull
kunnus sbom container ./image.tar --output image.cdx.json      # docker save / OCI tarball
kunnus sbom container myapp:dev --source docker                # local docker daemon
```

Each component in the result carries per-layer attribution: which image layer
introduced it.

## Reading the output

The SBOM is a [CycloneDX 1.6](https://cyclonedx.org/) JSON document,
conformant with BSI TR-03183-2. Each component carries a purl, cpes where
derivable, licences where the package data provides them
([licenses.md](licenses.md)), content hashes where the lockfile provides them,
and `bsi:*`/`kunnus:*` properties documented in
[sbom-properties.md](sbom-properties.md).

Three behaviours worth knowing:

- **Serial numbers form a series only when you supply an identity.** Without
  flags, every run gets a fresh random `serialNumber` — honest, but no lineage.
  Pass `--component-id` (and ideally `--component-version`) to make rescans of
  the same component share one serial number, ordered by the document version,
  so consumers can tell "new revision of this SBOM" from "different SBOM".
  Container scans of a registry reference get this automatically. See
  [serial-numbers.md](serial-numbers.md).
- **Offline by default.** Scans make no network requests. `--online-licenses`
  opts into deps.dev licence lookups; remote container references pull from
  the registry. Nothing else touches the network.
- **Exit codes distinguish clean from degraded scans.** Exit 0 means every
  plugin ran clean. If the scan finishes but some plugins failed, the SBOM is
  still written and kunnus exits non-zero with a summary — CI can tell
  "complete SBOM" from "SBOM with gaps". Add `--verbosity info` (or the
  `KUNNUS_VERBOSITY` env var) for per-plugin detail.

## Upload to the kunnus platform

Continuous CRA compliance — vulnerability monitoring, notifications,
documentation — happens on the [kunnus platform](https://kunnus.tech):

```shell
kunnus upload sbom.cdx.json --api-key $KUNNUS_API_KEY --component-id $KUNNUS_COMPONENT_ID
```

All flags are also readable from env vars (`KUNNUS_API_KEY`,
`KUNNUS_COMPONENT_ID`, `KUNNUS_UPLOAD_URL`), which is the natural fit for CI.

## Automate it in CI

```yaml
- name: Generate SBOM
  env:
    # The same component id used for upload also keys the SBOM's serialNumber,
    # so successive pipeline runs form one document series (see
    # serial-numbers.md). Without it every run gets a random serial.
    KUNNUS_COMPONENT_ID: ${{ vars.KUNNUS_COMPONENT_ID }}
    KUNNUS_COMPONENT_VERSION: ${{ github.ref_name }}
  run: |
    docker run --rm -v ${{ github.workspace }}:/src \
      -e KUNNUS_COMPONENT_ID -e KUNNUS_COMPONENT_VERSION \
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

Every release now ships with a current SBOM, and the platform flags new CVEs
in your dependencies as they appear.
