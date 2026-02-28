# kunnus sbom Action

Generates an SBOM for your project using [`kunnus`](../../cmd/kunnus).

## Usage

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `directory` | no | `./` | Directory to scan |
| `format` | no | `spdx-2-3` | SBOM format: `spdx-2-3`, `cyclonedx-1-4`, or `cyclonedx-1-5` |
| `output` | no | `sbom.spdx.json` | Output file path |

## Examples

### Minimal — scan current directory

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
```

Writes `sbom.spdx.json` to the workspace root.

### Custom format and output path

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
  with:
    format: cyclonedx-1-5
    output: sbom.cdx.json
```

### Scan a subdirectory

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/sbom@main
  with:
    directory: ./backend
    output: backend-sbom.spdx.json
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
          component-id: your-component-id
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Error (invalid arguments, scan failure) |
