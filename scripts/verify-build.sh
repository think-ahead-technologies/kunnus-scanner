#!/usr/bin/env bash
# ABOUTME: Builds and tests the module for the weekly Dependencies workflow, capturing the result honestly.
# ABOUTME: Writes `ok` (true/false) and the last 40 lines of output as `log` to $GITHUB_OUTPUT.
set -uo pipefail

# Capture the build+test result instead of swallowing it with `|| true`. The
# outcome drives the draft flag and the PR body in the workflow.
log=$( { go build ./... && go test ./...; } 2>&1 )
code=$?
echo "$log"

if [ "$code" -eq 0 ]; then
	echo "ok=true" >> "$GITHUB_OUTPUT"
else
	echo "ok=false" >> "$GITHUB_OUTPUT"
fi

{
	echo "log<<__VERIFY_EOF__"
	echo "$log" | tail -40
	echo "__VERIFY_EOF__"
} >> "$GITHUB_OUTPUT"
