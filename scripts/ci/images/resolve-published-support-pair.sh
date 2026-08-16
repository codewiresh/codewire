#!/usr/bin/env bash
set -euo pipefail

# Resolve untrusted registry metadata for the currently published atomic
# support-image pair. Git ancestry and artifact impact are deliberately
# validated later by the credential-free planner.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly CANDIDATE_SCHEMA='codewire.ci-published-support-candidate/v1'

[[ $# -eq 1 ]] || {
  echo 'Usage: resolve-published-support-pair.sh OUTPUT_JSON' >&2
  exit 2
}
output="$1"
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
    --slurpfile base "$work/base.json" \
    --slurpfile workspace "$work/workspace.json" '{
      schema: $schema,
      retrieval: {valid: true, reasons: []},
      images: {
        base: {
          repository: $base[0].Name,
          tag: "latest",
          digest: $base[0].Digest,
          revision: $base[0].Labels["org.opencontainers.image.revision"]
        },
        workspace: {
          repository: $workspace[0].Name,
          tag: "latest",
          digest: $workspace[0].Digest,
          revision: $workspace[0].Labels["org.opencontainers.image.revision"]
        }
      }
    }' >"$output"
}

lookup_failure_reason=''
inspect_pair() {
  local image inspect
  for image in base workspace; do
    inspect="$work/$image.json"
    if ! "$skopeo_runner" inspect --no-creds \
        --override-os linux --override-arch amd64 \
        "docker://ghcr.io/codewiresh/$image:latest" \
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
if inspect_pair; then
  write_candidate
  exit 0
fi
write_unavailable "$lookup_failure_reason"
