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
secret_fetcher="${INFISICAL_SECRET_FETCHER:-$ROOT/scripts/ci/setup/fetch-infisical-ci-secret.sh}"
skopeo_runner="${SKOPEO_RUNNER:-$ROOT/scripts/ci/images/run-skopeo-container.sh}"
docker_bin="${DOCKER_BIN:-docker}"
username="${GHCR_PUBLISH_USERNAME:-}"

umask 077
work="$(mktemp -d)"
token_file="$work/ghcr-token"
auth_volume=''
cleanup() {
  if [[ -n "$auth_volume" ]]; then
    "$docker_bin" volume rm "$auth_volume" >/dev/null 2>&1 || true
  fi
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
  local mode="$1" image inspect
  local -a auth_args
  auth_args=(--no-creds)
  if [[ "$mode" == authenticated ]]; then
    auth_args=(--authfile /auth/auth.json)
  fi
  for image in base workspace; do
    inspect="$work/$image.json"
    if ! SKOPEO_AUTH_VOLUME="${auth_volume:-}" \
      "$skopeo_runner" inspect "${auth_args[@]}" \
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
if inspect_pair anonymous; then
  write_candidate
  exit 0
fi
rm -f "$work/base.json" "$work/workspace.json"

if [[ -z "$username" ]]; then
  write_unavailable username_unavailable
  exit 0
fi
if [[ ! -x "$secret_fetcher" ]]; then
  write_unavailable resolver_unavailable
  exit 0
fi
if ! "$secret_fetcher" GHCR_PUBLISH_TOKEN "$token_file" >/dev/null 2>&1; then
  write_unavailable credential_unavailable
  exit 0
fi
if [[ ! -s "$token_file" ]]; then
  write_unavailable credential_unavailable
  exit 0
fi
if ! auth_volume="$($docker_bin volume create 2>/dev/null)" \
  || [[ ! "$auth_volume" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]]; then
  auth_volume=''
  write_unavailable auth_runtime_unavailable
  exit 0
fi
readonly auth_volume

if ! SKOPEO_AUTH_VOLUME="$auth_volume" \
  "$skopeo_runner" login --authfile /auth/auth.json --username "$username" \
    --password-stdin ghcr.io <"$token_file" >/dev/null 2>"$work/login.error"; then
  write_unavailable registry_authentication_failed
  exit 0
fi

if ! inspect_pair authenticated; then
  write_unavailable "$lookup_failure_reason"
  exit 0
fi
write_candidate
