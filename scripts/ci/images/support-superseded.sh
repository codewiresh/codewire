#!/usr/bin/env bash
# Whether this support-images.yaml push run's commit is still main's tip.
# Writes superseded=false or superseded=true to $GITHUB_OUTPUT, and fails
# closed when canonical main cannot be read.
#
# The selection job asks first, and each build job asks again as its first
# step, before it reads a credential or starts a build: a build job can wait
# minutes for a protected runner, and main may move meanwhile. A commit main
# has moved past publishes nothing; the newer commit's run is queued behind
# this one and plans against the published pair, so it publishes the
# cumulative change. A build that has started is never stopped (owner,
# 2026-10-21). A release that needs the skipped commit's pair dispatches
# support-images.yaml for it.
#
# A dispatch names the commit it publishes for (dispatch-source.sh
# --main-history), usually an earlier one a release needs, so it is never
# superseded: it builds that commit's pair when its inputs need one (owner,
# 2026-11-12, #4243).
#
# Usage: support-superseded.sh (reads GITHUB_EVENT_NAME, GITHUB_SHA and
# GITHUB_OUTPUT)
set -euo pipefail

: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
if [[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]]; then
  echo 'superseded=false' >> "$GITHUB_OUTPUT"
  echo 'a dispatch publishes for the commit it names, wherever main is now'
  exit 0
fi
canonical_main_sha="$(
  git ls-remote origin refs/heads/main |
    awk '$2 == "refs/heads/main" { print $1 }'
)"
[[ "$canonical_main_sha" =~ ^[0-9a-f]{40}$ ]]
if [[ "$canonical_main_sha" == "$GITHUB_SHA" ]]; then
  echo 'superseded=false' >> "$GITHUB_OUTPUT"
else
  echo 'superseded=true' >> "$GITHUB_OUTPUT"
  echo "main is now ${canonical_main_sha}; its queued run publishes this commit's changes"
fi
