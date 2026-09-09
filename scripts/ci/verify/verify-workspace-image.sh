#!/usr/bin/env bash
# Build and inspect the workspace image without publishing it. This runs in
# pull-request CI and intentionally proves the user-facing agent contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
base_context_name="codewire-verified-base"
artifact_tool="$ROOT/scripts/ci/verify/workspace-image-artifact.py"
receipt="$ROOT/.tmp/codewire-workspace-image-verification.json"
source "$ROOT/scripts/ci/images/workspace-cache.sh"
workspace_cache_validate
case "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" in
  auto|disabled) ;;
  *) echo 'workspace image reuse must be auto or disabled' >&2; exit 2 ;;
esac
export CODEWIRE_SCCACHE_MODE="$sccache_mode" CODEWIRE_BUILDKIT_CACHE_MODE="$layer_cache_mode"

for tool in "$docker_bin" python3 jq timeout bash tee stat realpath; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'workspace image verification: missing required tool: %s\n' "$tool" >&2
    exit 1
  }
done

[[ "$#" -eq 0 ]] || { echo 'workspace image verifier accepts no arguments' >&2; exit 2; }
identity="$(python3 "$artifact_tool" identity "$ROOT")"
source_id="$(jq -er '.source_sha' <<<"$identity")"
source_tree="$(jq -er '.source_tree' <<<"$identity")"
architecture="$(jq -er '.architecture' <<<"$identity")"
contract_sha="$(jq -er '.inputs["scripts/ci/verify/workspace-agent-contract.sh"]' <<<"$identity")"
workspace_tag="codewire-workspace-verify:${source_id}"
if [[ "${CODEWIRE_WORKSPACE_IMAGE_REUSE:-auto}" == auto ]] \
    && alias="$(python3 "$artifact_tool" reuse-for-build "$ROOT" "$receipt" 2>/dev/null)"; then
  printf 'workspace image verification: reused exact verified image %s\n' "$alias"
  exit 0
fi
mkdir -p "$ROOT/.tmp"
# A fresh failed attempt must never leave an older acceptance marker behind.
[[ ! -L "$receipt" && ! -L "$ROOT/.tmp" ]] || { echo 'invalid workspace receipt destination' >&2; exit 2; }
umask 077
work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-image-verify.XXXXXX")"
archive_work="$(mktemp -d "$ROOT/.tmp/.workspace-oci.XXXXXX")"
workspace_archive="$archive_work/workspace.oci.tar"
previous_receipt="$archive_work/previous-receipt.json"
base_layout="$work/base.oci"
base_metadata="$work/base-metadata.json"
workspace_id=''
base_digest=''
contract_container=''

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM

  workspace_cache_cleanup_builder || cleanup_status=$?
  if [[ -n "$contract_container" ]]; then
    timeout --signal=TERM --kill-after=3s 10s \
      "$docker_bin" rm --force "$contract_container" >/dev/null 2>&1 || cleanup_status=$?
  fi
  rm -rf "$work"

  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    printf 'workspace image verification: failed to remove ephemeral builder %s\n' \
      "$builder" >&2
    status="$cleanup_status"
  fi
  if [[ "$status" -eq 0 ]]; then
    # No acceptance marker may survive a failed contract or builder cleanup.
    local -a prior_receipt=()
    [[ ! -e "$previous_receipt" ]] || prior_receipt+=("$previous_receipt")
    CODEWIRE_BUILDKIT_CACHE_FALLBACK="$workspace_cache_fallback" \
      python3 "$artifact_tool" seal "$ROOT" "$receipt" "$workspace_id" \
        "$base_digest" "$workspace_archive" "${prior_receipt[@]}" || status=$?
  fi
  rm -rf "$archive_work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -e "$receipt" ]]; then
  [[ -f "$receipt" ]] || { echo 'invalid workspace receipt destination' >&2; exit 2; }
  mv -- "$receipt" "$previous_receipt"
fi

started_at="$(date +%s)"
workspace_cache_create_builder "$work"
workspace_cache_compiler_args

# Export the exact base as a local OCI layout. The workspace build consumes the
# exported manifest by digest through a named context, so this handoff neither
# relies on a daemon-local tag nor publishes an intermediate image.
workspace_cache_build base "$source_tree" "$architecture" "$work/base-build.log" \
  --pull \
  --metadata-file "$base_metadata" \
  --output "type=oci,dest=$base_layout,tar=false" \
  --file "$ROOT/images/base/Dockerfile" \
  "$ROOT/images/base"

base_digest="$(python3 - "$base_metadata" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as metadata_file:
    metadata = json.load(metadata_file)
digest = metadata.get("containerimage.digest", "")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("workspace image verification: base build returned no valid image digest")
print(digest)
PY
)"
readonly base_digest

workspace_cache_build workspace "$source_tree" "$architecture" "$work/workspace-build.log" \
  --pull \
  --build-context "$base_context_name=oci-layout://$base_layout@$base_digest" \
  --tag "$workspace_tag" \
  --label "org.opencontainers.image.revision=$source_id" \
  --label "dev.codewire.source-tree=$source_tree" \
  --label "dev.codewire.workspace-contract=$contract_sha" \
  --label dev.codewire.build.profile=workspace-verify \
  --label dev.codewire.promotable=false \
  --provenance=false --sbom=false \
  --output "type=oci,dest=$workspace_archive" \
  --load \
  "${compiler_args[@]}" \
  --build-arg "BASE_IMAGE_REF=$base_context_name" \
  --file "$ROOT/images/workspace/Dockerfile" \
  "$ROOT"
chmod 0400 "$workspace_archive"

# Loaded runtime bytes do not depend on BuildKit. Remove its provider file and
# state before any runtime inspection or potentially slow agent command.
workspace_cache_cleanup_builder
workspace_cache_command "$docker_bin" image inspect "$workspace_tag" --format '{{.Id}}' >"$work/workspace-id"
workspace_id="$(<"$work/workspace-id")"
[[ "$workspace_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid workspace image ID' >&2; exit 1; }
contract_container="$builder-full"
workspace_cache_command "$docker_bin" run --rm --interactive --pids-limit=2048 \
  --name "$contract_container" --user codewire --entrypoint bash \
  "$workspace_id" -eu -s <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
contract_container="$builder-mounted-home"
workspace_cache_command "$docker_bin" run --rm --interactive --pids-limit=2048 \
  --name "$contract_container" --user codewire \
  --tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m --entrypoint bash \
  "$workspace_id" -eu -s -- --mounted-home-agents <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
contract_container=''

printf 'workspace image verification: base=%s workspace=%s\n' "$base_digest" "$workspace_tag"
printf 'CODEWIRE_CI_PHASE name=workspace-image-verification seconds=%s compiler=%s layers=%s layer_fallback=%s\n' \
  "$(( $(date +%s) - started_at ))" "$sccache_mode" "$layer_cache_mode" "$workspace_cache_fallback"
