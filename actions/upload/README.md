# kunnus upload Action

Uploads an SBOM to the Kunnus platform using [`kunnus`](../../cmd/kunnus).

## Usage

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
  with:
    file: sbom.spdx.json
    version: ${{ github.ref_name }}
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: your-component-id
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `file` | **yes** | — | Path to the SBOM file to upload |
| `version` | **yes** | — | Version string to associate with the SBOM (e.g. git SHA or tag) |
| `api-key` | **yes** | — | Kunnus API key — use a secret |
| `component-id` | **yes** | — | Component ID to associate the SBOM with |
| `mark-as-current` | no | `true` | Mark this SBOM as the current version for the component |
| `upload-url` | no | — | Override the Kunnus upload API URL |

`api-key` and `upload-url` are injected as environment variables so they never appear in command-line arguments or logs.

The `source` field is auto-detected: `CiPipeline` when running in GitHub Actions (or any CI environment), `CLI` otherwise.

## Examples

### Upload with a git tag as version

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
  with:
    file: sbom.spdx.json
    version: ${{ github.ref_name }}
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: your-component-id
```

### Upload with a commit SHA as version

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
  with:
    file: sbom.spdx.json
    version: ${{ github.sha }}
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: your-component-id
```

### Upload without marking as current

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/upload@main
  with:
    file: sbom.spdx.json
    version: ${{ github.sha }}
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: your-component-id
    mark-as-current: "false"
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Error (invalid arguments, file not found, HTTP 4xx) |
| `3` | Network or API failure (HTTP 5xx) |
