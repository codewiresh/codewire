#!/usr/bin/env bash
# wait-for-production-accepted.sh TAG TAG_OBJECT_SHA SOURCE_SHA: wait until
# Production has accepted the same release, tag object and commit
# (require-production-accepted.sh), then return. cli-release builds from the
# tag while deploy-prod delivers it, and each of its signing jobs runs this
# before it holds any credential, so nothing is signed, notarized or published
# before Production runs the release (#4492). The check reads deploy-prod's
# successful runs, so it also waits for the rest of that run, such as its GHCR
# mirror.
#
# GITEA_TOKEN is the job's own token. PRODUCTION_WAIT_SECONDS bounds the wait.
# Its default, 310 minutes, outlasts deploy-prod's longest delivery: release
# selection 25 and publication 90 (test-cli-release-workflow.py derives that
# bound from deploy-prod.yaml), so a release Production accepts late is still
# published. Each signing job then keeps 15 to 20 minutes of its own within
# the trusted light runner's 330-minute cap. PRODUCTION_POLL_SECONDS (default
# 30) spaces the checks.
set -euo pipefail

fail() {
  printf 'production acceptance: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || {
  printf 'usage: wait-for-production-accepted.sh TAG TAG_OBJECT_SHA SOURCE_SHA\n' >&2
  exit 2
}
readonly tag="$1" tag_object_sha="$2" source_sha="$3"
readonly wait_seconds="${PRODUCTION_WAIT_SECONDS:-18600}"
readonly poll_seconds="${PRODUCTION_POLL_SECONDS:-30}"
[[ "$wait_seconds" =~ ^[1-9][0-9]*$ ]] || fail 'PRODUCTION_WAIT_SECONDS must be a whole number of seconds'
[[ "$poll_seconds" =~ ^[0-9]+$ ]] || fail 'PRODUCTION_POLL_SECONDS must be a whole number of seconds'
[[ -n "${GITEA_TOKEN:-}" ]] || fail 'GITEA_TOKEN is required to read deploy-prod runs'
token="$GITEA_TOKEN"
unset GITEA_TOKEN
check="$(dirname "$0")/require-production-accepted.sh"
readonly check
log="$(mktemp "${RUNNER_TEMP:-/tmp}/codewire-production-wait.XXXXXX")"
trap 'rm -f "$log"' EXIT

started=$SECONDS
while :; do
  if GITEA_TOKEN="$token" "$check" "$tag" "$tag_object_sha" "$source_sha" >"$log" 2>&1; then
    cat "$log"
    printf 'production acceptance: Production accepted %s after %ss of waiting\n' "$tag" "$((SECONDS - started))"
    exit 0
  fi
  if ((SECONDS - started >= wait_seconds)); then
    cat "$log" >&2
    fail "Production did not accept $tag within ${wait_seconds}s; nothing was signed or published"
  fi
  printf 'production acceptance: waiting for Production to accept %s (%ss so far): %s\n' \
    "$tag" "$((SECONDS - started))" "$(tail -n 1 "$log")"
  sleep "$poll_seconds"
done
