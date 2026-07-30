# Serial numbers and document series

Every SBOM kunnus emits carries a CycloneDX `serialNumber` (a `urn:uuid`) and
a document `version`. Together they express **lineage**: rescans of the same
component form a *series* — documents sharing one serial number, ordered by
version — which is how a consumer (and [CISA's SBOM minimum
elements](https://www.cisa.gov/sbom)) can tell "a new revision of this SBOM"
from "an SBOM of something else".

## What you get, by invocation

| Invocation | serialNumber | version |
|---|---|---|
| No identity flags (`sbom repo .`, `sbom os`) | Random per run — every document is a series of one | `1` |
| `--component-id` (± `--component-version`) | Deterministic — stable across rescans of the same id + version | Generation timestamp (epoch seconds) |
| `sbom container <registry-ref>` | Deterministic automatically — derived from the image's repository path, tag as version | Generation timestamp (epoch seconds) |
| `--serial-number <uuid>` | Exactly the given value | Generation timestamp (epoch seconds) |

**If you want a series, say who you are.** kunnus deliberately does *not*
invent an identity from what it can see: the only thing a repo scan knows on
its own is the scanned directory's basename, and a serial derived from that
would be stable in the wrong way — colliding across unrelated projects that
all mount at `/src` in CI, while changing when someone renames a checkout. A
random serial that honestly says "no known lineage" beats a deterministic one
that fabricates it.

```shell
# One series across every release pipeline run:
kunnus sbom repo --component-id acme/widget --component-version 1.2.3 -o sbom.cdx.json

# Same thing via env vars — the natural fit for CI:
export KUNNUS_COMPONENT_ID=acme/widget
export KUNNUS_COMPONENT_VERSION=1.2.3
kunnus sbom repo -o sbom.cdx.json
```

Container scans of a registry reference need no flags: `ghcr.io/acme/app:v1.2.3`
already *is* an identity. The repository path (without tag or digest) keys the
series and the tag becomes the component version, so successive builds pushed
to the same tag stay in one series. Tarball scans (`sbom container ./image.tar`)
have no stable identity — a file path isn't one — and fall back to a random
serial unless you pass `--component-id`.

## The pieces

- **`--component-id`** (`KUNNUS_COMPONENT_ID`) — the stable identity of what
  you're scanning. Use the same value you use for `kunnus upload
  --component-id`; any stable, deliberately-assigned handle works. Scans
  sharing an id + version (in the same mode) produce the same serial number.
- **`--component-version`** (`KUNNUS_COMPONENT_VERSION`) — the version of the
  scanned component. It lands on the SBOM's root component
  (`metadata.component.version`) *and* in the series key: per CISA, a series
  is per name/version pair, so releasing `1.2.4` deliberately starts a new
  series. Omitting it is fine — the series is still stable, keyed on the
  empty version — but supply it when you can.
- **`--serial-number`** (`KUNNUS_SERIAL_NUMBER`) — bypass derivation and use
  this exact serial (bare UUID or `urn:uuid:` form). For build systems that
  already mint document identifiers (PLM/ALM integration); what you supply is
  more trustworthy than anything kunnus can derive. A malformed value fails
  before the scan runs.

The scan **mode is part of the series key**: a `repo` SBOM and an `os` SBOM of
the same component are different documents with different generation
semantics, and never share a series.

## Document version = generation timestamp

For series members, `version` is the SBOM's generation timestamp
(`metadata.timestamp`) in Unix epoch seconds. That makes versions strictly
increasing across rescans **without the scanner keeping state** — knowing
"this is revision 4" requires knowing revisions 1–3 existed, and a stateless
CLI can't and shouldn't track that. Any two documents in a series are ordered
by exactly the field CycloneDX tells consumers to order by ("use the most
recent version"), and the version is always self-consistent with the
timestamp inside the same document.

Downstream systems that track revision counts (like the kunnus platform) can
re-stamp `version` with pretty sequential integers at ingest; the epoch-based
value loses nothing they need.

## Derivation, for auditors

The serial is reproducible by any third party from public inputs:

```
namespace = UUIDv5(DNS namespace, "kunnus.tech")
          = d22e9dc1-292c-5b0d-a2d4-b10793fdb5ea

key    = "v1" ␟ <mode> ␟ <component-id> ␟ <component-version>   (␟ = 0x1F)
serial = UUIDv8( SHA-256(namespace, key) )
```

UUIDv8 is [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562)'s
vendor-specific version: the first 128 bits of the SHA-256 digest with the
version/variant bits stamped in — a name-based UUID like v5, without v5's
SHA-1. The `"v1"` prefix versions the key layout itself, so a future change
to the derivation can never silently merge old and new series. The
implementation lives in `internal/sbom/serial.go`; the namespace value is
pinned by a test.
