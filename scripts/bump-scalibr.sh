#!/usr/bin/env bash
# ABOUTME: Bumps osv-scalibr to upstream HEAD and tidies go.mod for the weekly Dependencies workflow.
# ABOUTME: Writes the resolved commit SHA to $GITHUB_OUTPUT as `commit`.
set -euo pipefail

latest_commit=$(git ls-remote https://github.com/google/osv-scalibr.git HEAD | cut -f1)
echo "updating osv-scalibr to $latest_commit"
go get github.com/google/osv-scalibr@"$latest_commit"
go mod tidy
echo "commit=$latest_commit" >> "$GITHUB_OUTPUT"
