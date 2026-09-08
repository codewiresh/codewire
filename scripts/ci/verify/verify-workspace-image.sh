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

for tool in "$docker_bin" python3 jq sed; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'workspace image verification: missing required tool: %s\n' "$tool" >&2
    exit 1
  }
done

[[ "$#" -eq 0 ]] || { echo 'workspace image verifier accepts no arguments' >&2; exit 2; }
identity="$(python3 "$artifact_tool" identity "$ROOT")"
source_id="$(jq -er '.source_sha' <<<"$identity")"
source_tree="$(jq -er '.source_tree' <<<"$identity")"
contract_sha="$(jq -er '.inputs["scripts/ci/verify/workspace-agent-contract.sh"]' <<<"$identity")"
workspace_tag="codewire-workspace-verify:${source_id}"
if alias="$(python3 "$artifact_tool" reuse "$ROOT" "$receipt" 2>/dev/null)"; then
  printf 'workspace image verification: reused exact verified image %s\n' "$alias"
  exit 0
fi
mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-image-verify.XXXXXX")"
archive_work="$(mktemp -d "$ROOT/.tmp/.workspace-oci.XXXXXX")"
workspace_archive="$archive_work/workspace.oci.tar"
base_layout="$work/base.oci"
base_metadata="$work/base-metadata.json"
builder=""
owns_builder=false
workspace_id=''
base_digest=''

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM

  if [[ "$owns_builder" == true && -n "$builder" ]]; then
    "$docker_bin" buildx rm --force "$builder" >/dev/null 2>&1 || cleanup_status=$?
  fi
  rm -rf "$work"

  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then
    printf 'workspace image verification: failed to remove ephemeral builder %s\n' \
      "$builder" >&2
    status="$cleanup_status"
  fi
  if [[ "$status" -eq 0 ]]; then
    # No acceptance marker may survive a failed contract or builder cleanup.
    python3 "$artifact_tool" seal "$ROOT" "$receipt" "$workspace_id" "$base_digest" "$workspace_archive" || status=$?
  fi
  rm -rf "$archive_work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# OCI export is unavailable on Buildx's legacy Docker driver. Reuse an already
# selected container builder (and its cache); otherwise create an isolated
# fallback without changing the caller's selected builder.
builder_details="$("$docker_bin" buildx inspect)"
selected_builder="$(sed -n 's/^Name:[[:space:]]*//p' <<<"$builder_details" | head -n 1)"
selected_driver="$(sed -n 's/^Driver:[[:space:]]*//p' <<<"$builder_details" | head -n 1)"
if [[ "$selected_driver" == docker-container ]]; then
  builder="$selected_builder"
else
  builder="$("$docker_bin" buildx create --driver docker-container)"
  owns_builder=true
fi
if [[ ! "$builder" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]]; then
  echo 'workspace image verification: Buildx returned an invalid builder name' >&2
  exit 1
fi

# Export the exact base as a local OCI layout. The workspace build consumes the
# exported manifest by digest through a named context, so this handoff neither
# relies on a daemon-local tag nor publishes an intermediate image.
"$docker_bin" buildx build \
  --builder "$builder" \
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

"$docker_bin" buildx build \
  --builder "$builder" \
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
  --build-arg "BASE_IMAGE_REF=$base_context_name" \
  --file "$ROOT/images/workspace/Dockerfile" \
  "$ROOT"
chmod 0400 "$workspace_archive"

workspace_id="$("$docker_bin" image inspect "$workspace_tag" --format '{{.Id}}')"
[[ "$workspace_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid workspace image ID' >&2; exit 1; }
"$docker_bin" run --rm --interactive --pids-limit=2048 --user codewire --entrypoint bash \
  "$workspace_id" -eu -s <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"
"$docker_bin" run --rm --interactive --pids-limit=2048 --user codewire \
  --tmpfs /home/codewire:rw,exec,uid=1000,gid=1000,mode=0700,size=256m --entrypoint bash \
  "$workspace_id" -eu -s -- --mounted-home-agents <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

printf 'workspace image verification: base=%s workspace=%s\n' "$base_digest" "$workspace_tag"
