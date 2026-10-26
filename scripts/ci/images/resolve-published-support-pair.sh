#!/usr/bin/env bash
set -euo pipefail

# Resolve untrusted registry metadata for the currently published atomic
# support-image pair. Git ancestry and artifact impact are deliberately
# validated later by the credential-free planner.
#
# A push run reads the latest pair. A dispatch for SOURCE_SHA reads the pair of
# its newest first-parent ancestor (itself included) that GHCR serves under
# that commit's tag, so an earlier commit plans against the pair its own push
# would have, whatever main published since. Run it from the full checkout.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CANDIDATE_SCHEMA='codewire.ci-published-support-candidate/v1'

[[ $# -eq 1 || $# -eq 2 ]] || {
  echo 'Usage: resolve-published-support-pair.sh OUTPUT_JSON [SOURCE_SHA]' >&2
  exit 2
}
output="$1"
source_sha="${2:-}"
[[ -z "$source_sha" || "$source_sha" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'SOURCE_SHA must be a full lowercase commit ID' >&2
  exit 2
}
readonly source_sha
# How far back a dispatch looks for a published pair.
readonly MAX_ANCESTORS=1000
tag=latest
skopeo_runner="${SKOPEO_RUNNER:-$ROOT/scripts/ci/images/run-skopeo-container.sh}"

umask 077
work="$(mktemp -d)"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

write_unavailable() {
  local reason="$1"
  jq -n --arg schema "$CANDIDATE_SCHEMA" --arg reason "$reason" '{
    schema: $schema,
    retrieval: {valid: false, reasons: [$reason]},
    images: {}
  }' >"$output"
}

write_candidate() {
  jq -n \
    --arg schema "$CANDIDATE_SCHEMA" \
    --arg tag "$tag" \
    --slurpfile base "$work/base.json" \
    --slurpfile workspace "$work/workspace.json" '{
      schema: $schema,
      retrieval: {valid: true, reasons: []},
      images: {
        base: {
          repository: $base[0].Name,
          tag: $tag,
          digest: $base[0].Digest,
          revision: $base[0].Labels["org.opencontainers.image.revision"]
        },
        workspace: {
          repository: $workspace[0].Name,
          tag: $tag,
          digest: $workspace[0].Digest,
          revision: $workspace[0].Labels["org.opencontainers.image.revision"]
        }
      }
    }' >"$output"
}

lookup_failure_reason=''
# find_ancestor_pair sets tag to the newest first-parent ancestor of
# source_sha whose base and workspace GHCR serves under that commit's tag.
find_ancestor_pair() {
  local image
  for image in base workspace; do
    if ! "$skopeo_runner" list-tags --no-creds "docker://ghcr.io/codewiresh/$image" \
        >"$work/$image.tags" 2>"$work/$image.tags.error"; then
      lookup_failure_reason="${image}_registry_tags_failed"
      return 1
    fi
    if [[ "$(wc -c <"$work/$image.tags")" -gt 16777216 ]] \
      || ! jq -r '.Tags | arrays | .[] | strings | select(test("^[0-9a-f]{40}$"))' \
        "$work/$image.tags" >"$work/$image.commits" 2>/dev/null; then
      lookup_failure_reason="${image}_registry_tags_malformed"
      return 1
    fi
  done
  if ! git rev-list --first-parent --max-count="$MAX_ANCESTORS" "$source_sha" \
      >"$work/ancestors" 2>/dev/null; then
    lookup_failure_reason=source_history_unreadable
    return 1
  fi
  tag="$({ grep -Fxf "$work/base.commits" "$work/ancestors" || true; } |
    { grep -Fxf "$work/workspace.commits" || true; } | head -n 1)"
  if [[ -z "$tag" ]]; then
    lookup_failure_reason=no_published_ancestor_pair
    return 1
  fi
  printf 'Planning %s against the pair published for its ancestor %s\n' "$source_sha" "$tag" >&2
}

inspect_pair() {
  local image inspect
  for image in base workspace; do
    inspect="$work/$image.json"
    if ! "$skopeo_runner" inspect --no-creds \
        --override-os linux --override-arch amd64 \
        "docker://ghcr.io/codewiresh/$image:$tag" \
        >"$inspect" 2>"$work/$image.error"; then
      lookup_failure_reason="${image}_registry_lookup_failed"
      return 1
    fi
    if [[ ! -s "$inspect" ]] || [[ "$(wc -c <"$inspect")" -gt 1048576 ]] \
      || ! jq -e 'type == "object"' "$inspect" >/dev/null 2>&1; then
      lookup_failure_reason="${image}_registry_response_malformed"
      return 1
    fi
  done
}

if [[ ! -x "$skopeo_runner" ]]; then
  write_unavailable resolver_unavailable
  exit 0
fi
if [[ -n "$source_sha" ]] && ! find_ancestor_pair; then
  write_unavailable "$lookup_failure_reason"
  exit 0
fi
if inspect_pair; then
  write_candidate
  exit 0
fi
write_unavailable "$lookup_failure_reason"
