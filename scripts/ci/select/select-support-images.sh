#!/usr/bin/env bash
# Select whether the latest main commit changes the atomic support-image pair.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CLASSIFIER="$ROOT/scripts/ci/select/artifact-impact.py"

[[ $# -eq 2 ]] || {
  printf 'usage: select-support-images.sh BASE_SHA HEAD_SHA\n' >&2
  exit 2
}

tmp="$(mktemp)"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

python3 "$CLASSIFIER" select \
  --mode support \
  --base "$1" \
  --head "$2" >"$tmp"

selected="$(sed -n 's/^selected=//p' "$tmp")"
reason="$(sed -n 's/^reason=//p' "$tmp")"
categories="$(sed -n 's/^matched_categories=//p' "$tmp")"
if [[ "$selected" != true && "$selected" != false ]]; then
  selected=true
  reason=classifier_invalid
  categories=ambiguous-definition
fi

printf 'build_support_images=%s\nreason=%s\nmatched_categories=%s\nbaseline_sha=%s\nhead_sha=%s\n' \
  "$selected" "$reason" "$categories" "$1" "$2"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'build_support_images=%s\nreason=%s\nmatched_categories=%s\nbaseline_sha=%s\nhead_sha=%s\n' \
    "$selected" "$reason" "$categories" "$1" "$2" >>"$GITHUB_OUTPUT"
fi
