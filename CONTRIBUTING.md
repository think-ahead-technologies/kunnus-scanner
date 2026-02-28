# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

For any new feature, please create an issue first to discuss the proposed changes
before proceeding to make a pull request. This helps ensure that your contribution
is aligned with the project's goals and avoids duplicate work.

## Community Guidelines

We are committed to providing a welcoming and inclusive environment. All contributors
are expected to be respectful and considerate in their interactions.

## Contributing code

### Prerequisites

Install:

1. [Go](https://go.dev/) 1.21+, use `go version` to check.
2. [GoReleaser](https://goreleaser.com/) (Optional, only if you want reproducible builds).

> **Note**
>
> The scripts within `/scripts` expect to be run from the root of the repository

### Building

#### Build using only `go`

Run the following in the project directory:

```shell
go build ./cmd/kunnus/
```

Produces a `kunnus` binary.

#### Build using `goreleaser`

Run the following in the project directory:

```shell
./scripts/build_snapshot.sh
```

See GoReleaser [documentation](https://goreleaser.com/cmd/goreleaser_build/) for build options.

### Running tests

To run tests:

```shell
go test ./cmd/kunnus/...
```

To get consistent test results, please run with `GOTOOLCHAIN=go<go version in go.mod>`.

You can regenerate snapshots by setting `UPDATE_SNAPS=true` when running tests:

```shell
UPDATE_SNAPS=true go test ./cmd/kunnus/...
```

### Linting

To lint your code, run

```shell
./scripts/run_lints.sh
```

### Making commits

Please follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification when squashing commits during a merge. This is typically the commit merged into the main branch and is often based on the PR title. Doing so helps us to automate processes like changelog generation and ensures a clear and consistent commit history.

Some types: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, and others.
