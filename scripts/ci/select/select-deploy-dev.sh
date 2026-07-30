#!/usr/bin/env bash
# Select whether cumulative deployed-source..main changes need a dev release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CLASSIFIER="$ROOT/scripts/ci/select/artifact-impact.py"

fail_safe() {
  local reason="$1"
  local output="${GITHUB_OUTPUT:-}"
  printf 'deploy_dev=true\nreason=%s\nmatched_categories=ambiguous-baseline\nbaseline_sha=\nhead_sha=%s\n' \
    "$reason" "$HEAD_SHA"
  if [[ -n "$output" ]]; then
    printf 'deploy_dev=true\nreason=%s\nmatched_categories=ambiguous-baseline\nbaseline_sha=\nhead_sha=%s\n' \
      "$reason" "$HEAD_SHA" >>"$output"
  fi
}

[[ $# -eq 2 ]] || {
  printf 'usage: select-deploy-dev.sh DEPLOYED_SOURCE_SHA HEAD_SHA\n' >&2
  exit 2
}
readonly BASE_SHA="$1"
readonly HEAD_SHA="$2"

if [[ ! "$BASE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  fail_safe baseline_unavailable
  exit 0
fi

tmp="$(mktemp)"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

python3 "$CLASSIFIER" select \
  --mode runtime \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" >"$tmp"

selected="$(sed -n 's/^selected=//p' "$tmp")"
reason="$(sed -n 's/^reason=//p' "$tmp")"
categories="$(sed -n 's/^matched_categories=//p' "$tmp")"
[[ "$selected" == true || "$selected" == false ]] || {
  fail_safe classifier_invalid
  exit 0
}

printf 'deploy_dev=%s\nreason=%s\nmatched_categories=%s\nbaseline_sha=%s\nhead_sha=%s\n' \
  "$selected" "$reason" "$categories" "$BASE_SHA" "$HEAD_SHA"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'deploy_dev=%s\nreason=%s\nmatched_categories=%s\nbaseline_sha=%s\nhead_sha=%s\n' \
    "$selected" "$reason" "$categories" "$BASE_SHA" "$HEAD_SHA" >>"$GITHUB_OUTPUT"
fi
