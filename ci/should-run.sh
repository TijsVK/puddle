#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Gate for the nightly workflows: sets `run=true|false` in $GITHUB_OUTPUT. Only scheduled runs can
# skip; they skip when this workflow already has a green run (nightly, dispatch or push) on exactly
# this commit. Usage: ci/should-run.sh <workflow-file>. Needs GH_TOKEN and `actions: read`.
set -euo pipefail

workflow=${1:?usage: should-run.sh <workflow-file>}

if [ "${GITHUB_EVENT_NAME:-}" != "schedule" ]; then
    echo "run=true" >>"$GITHUB_OUTPUT"
    exit 0
fi

green=$(gh run list -R "$GITHUB_REPOSITORY" --workflow "$workflow" --status success \
    --commit "$GITHUB_SHA" --limit 1 --json databaseId --jq 'length')
if [ "$green" != "0" ]; then
    echo "$workflow already has a green run on $GITHUB_SHA; skipping"
    echo "run=false" >>"$GITHUB_OUTPUT"
else
    echo "run=true" >>"$GITHUB_OUTPUT"
fi
