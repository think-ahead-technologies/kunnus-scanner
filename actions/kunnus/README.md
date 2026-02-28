# kunnus GitHub Action

Runs [`kunnus`](../../cmd/kunnus) in a Docker container. Use it to generate an SBOM for your project, upload an SBOM to the Kunnus platform, or do both in a single workflow step.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `scan-args` | no | `sbom\n./` | Arguments passed to `kunnus`, one per line |
| `api-key` | no | — | Kunnus API key — maps to `KUNNUS_API_KEY`. Use a secret. |
| `component-id` | no | — | Component ID to associate the SBOM with — maps to `KUNNUS_COMPONENT_ID` |
| `upload-url` | no | — | Override the upload API URL — maps to `KUNNUS_URL` |

`api-key`, `component-id`, and `upload-url` are injected as environment variables so they never appear in command-line arguments or logs.

## Generate an SBOM

Scan the repository and write `sbom-<project>-<date>.spdx.json` to the workspace:

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/kunnus@main
  with:
    scan-args: |-
      sbom
      ./
```

Choose a different format:

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/kunnus@main
  with:
    scan-args: |-
      sbom
      --format
      cyclonedx-1-5
      --output
      sbom.cdx.json
      ./
```

## Upload an SBOM

Upload a previously generated SBOM file to the Kunnus platform:

```yaml
- uses: think-ahead-technologies/kunnus-scanner/actions/kunnus@main
  with:
    scan-args: |-
      upload
      sbom.spdx.json
      --version
      ${{ github.sha }}
    api-key: ${{ secrets.KUNNUS_API_KEY }}
    component-id: your-component-id
```

The `source` field defaults to `CiPipeline` when `CI=true` (which GitHub Actions sets automatically), so you don't need to pass it explicitly.

## Generate and upload in one job

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: think-ahead-technologies/kunnus-scanner/actions/kunnus@main
        with:
          scan-args: |-
            sbom
            --output
            sbom.spdx.json
            ./

      - name: Upload SBOM
        uses: think-ahead-technologies/kunnus-scanner/actions/kunnus@main
        with:
          scan-args: |-
            upload
            sbom.spdx.json
            --version
            ${{ github.ref_name }}
          api-key: ${{ secrets.KUNNUS_API_KEY }}
          component-id: your-component-id
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Vulnerabilities found (SBOM scan only) |
| `2` | Error (invalid arguments, file not found, HTTP 4xx) |
| `3` | Network or API failure (HTTP 5xx) |
