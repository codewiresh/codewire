#!/usr/bin/env bash
# Build and inspect the workspace image without publishing it. This runs in
# pull-request CI and intentionally proves the user-facing agent contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
source_id="${GITHUB_SHA:-local}"
workspace_tag="codewire-workspace-verify:${source_id}"
docker_bin="${CODEWIRE_DOCKER_BIN:-docker}"
base_context_name="codewire-verified-base"

for tool in "$docker_bin" python3 sed; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'workspace image verification: missing required tool: %s\n' "$tool" >&2
    exit 1
  }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-workspace-image-verify.XXXXXX")"
base_layout="$work/base.oci"
base_metadata="$work/base-metadata.json"
builder=""
owns_builder=false

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
  --load \
  --build-arg "BASE_IMAGE_REF=$base_context_name" \
  --file "$ROOT/images/workspace/Dockerfile" \
  "$ROOT"

"$docker_bin" run --rm --interactive --pids-limit=2048 --user codewire --entrypoint bash \
  "$workspace_tag" -eu -s <"$ROOT/scripts/ci/verify/workspace-agent-contract.sh"

printf 'workspace image verification: base=%s workspace=%s\n' "$base_digest" "$workspace_tag"
