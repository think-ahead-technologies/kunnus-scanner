# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub's security advisory
workflow: open the [**Security** tab](https://github.com/think-ahead-technologies/kunnus-scanner/security)
of this repository and click **Report a vulnerability**.

Do **not** open a public issue for anything you believe has security impact —
give us a chance to fix it first.

What to include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal input file, image, or command line is ideal).
- The kunnus version (`kunnus --version`) and platform.

We will acknowledge your report within **5 business days** and keep you
informed as we triage and fix. We credit reporters in the release notes unless
you prefer otherwise.

## Supported versions

Only the **latest release** receives security fixes. kunnus-scanner is a
standalone binary with no state to migrate — upgrading is replacing the
binary — so we do not backport patches to older versions.

## Scope notes

Context that helps judge impact:

- **The scanner is offline by design.** A scan makes no network requests
  unless you explicitly opt in: `--online-licenses` (deps.dev lookups),
  `kunnus sbom container` with a remote image reference (registry pull), and
  `kunnus upload`. Anything that makes the scanner phone home outside these
  paths is a vulnerability — please report it.
- **Scan inputs are untrusted.** The scanner parses attacker-controllable
  files (lockfiles, manifests, package databases, ELF binaries, container
  images). Crashes, hangs, path traversal, or memory exhaustion triggered by
  crafted inputs are in scope.
- **Dependencies** are monitored via Dependabot and the pinned
  [osv-scalibr](https://github.com/google/osv-scalibr) revision is updated
  regularly. Vulnerabilities in scalibr itself are best reported upstream,
  but feel free to tell us too so we can ship the bumped pin.
