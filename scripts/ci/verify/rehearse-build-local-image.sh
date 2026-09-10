#!/usr/bin/env bash
# Prove that a Docker-container builder needs --load, then prove the canonical
# helper loads the same scratch image without changing the selected builder.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/scripts/ci/images/build-local-image.sh"
native_import_bin=''
if [[ $# -ne 0 ]]; then
  [[ $# -eq 2 && "$1" == --workspace-image-import-bin ]] || {
    echo 'usage: rehearse-build-local-image.sh [--workspace-image-import-bin ABSOLUTE_PATH]' >&2
    exit 2
  }
  native_import_bin="$2"
  [[ "$native_import_bin" == /* && -f "$native_import_bin" &&
     ! -L "$native_import_bin" && -x "$native_import_bin" ]] || {
    echo 'local Buildx rehearsal: invalid native image importer' >&2
    exit 2
  }
fi

for tool in docker sed python3; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "local Buildx rehearsal: missing required tool: $tool" >&2
    exit 1
  }
done
docker buildx version >/dev/null

work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-buildx-rehearsal.XXXXXX")"
negative_builder=""
readonly negative_tag="codewire-buildx-rehearsal:no-load-$$-${RANDOM}"
readonly positive_tag="codewire-buildx-rehearsal:loaded-$$-${RANDOM}"

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$negative_builder" ]]; then
    docker buildx rm --force "$negative_builder" >/dev/null 2>&1 || true
  fi
  docker image rm --force "$negative_tag" "$positive_tag" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'local-buildx-rehearsal\n' >"$work/marker"
cat >"$work/Dockerfile" <<'EOF'
FROM scratch
COPY marker /marker
EOF

current_builder() {
  docker buildx inspect 2>/dev/null | sed -n 's/^Name:[[:space:]]*//p' | head -n 1
}

default_before="$(current_builder)"
readonly default_before
[[ -n "$default_before" ]] || {
  echo 'local Buildx rehearsal: unable to identify the selected builder' >&2
  exit 1
}

negative_builder="$(docker buildx create --driver docker-container)"
docker buildx build \
  --builder "$negative_builder" \
  --pull \
  --tag "$negative_tag" \
  --file "$work/Dockerfile" \
  "$work"
if docker image inspect "$negative_tag" >/dev/null 2>&1; then
  echo 'local Buildx rehearsal: image without --load unexpectedly reached Docker' >&2
  exit 1
fi
docker buildx rm --force "$negative_builder" >/dev/null
negative_builder=""

"$HELPER" "$positive_tag" "$work/Dockerfile" "$work" \
  --provenance=false --sbom=false --output "type=oci,dest=$work/workspace.oci.tar"
image_id="$(docker image inspect "$positive_tag" --format '{{.Id}}')"
chmod 0400 "$work/workspace.oci.tar"
# Prove the real Buildx multi-export handoff on a tiny scratch image before
# spending the full workspace build. Docker config IDs and OCI manifest IDs
# are different identities; the repository adapter must link them correctly.
archive_identity="$(PYTHONDONTWRITEBYTECODE=1 python3 - \
  "$ROOT/scripts/ci/verify/workspace-image-artifact.py" "$work/workspace.oci.tar" "$image_id" <<'PY'
import importlib.util
import json
from pathlib import Path
import platform
import sys
spec = importlib.util.spec_from_file_location('workspace_artifact', sys.argv[1])
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)
architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
print(json.dumps(artifact.archive_identity(Path(sys.argv[2]), sys.argv[3], architecture), sort_keys=True))
PY
)"
printf '%s\n' "$archive_identity"
if [[ -n "$native_import_bin" ]]; then
  # Exercise the actual Buildx tar format through the same native admission
  # helper used by the full VM gate. This owns no VM or provider credentials.
  IFS=' ' read -r archive_sha archive_size source_digest < <(
    python3 -c 'import json,sys; x=json.load(sys.stdin); print(x["sha256"], x["size"], x["source_digest"])' \
      <<<"$archive_identity"
  )
  [[ -n "$archive_sha" && -n "$archive_size" && -n "$source_digest" ]] || exit 1
  mkdir -m 0700 "$work/home" "$work/native-state"
  imported="$(env -i PATH=/usr/bin:/bin HOME="$work/home" LC_ALL=C \
    "$native_import_bin" --archive "$work/workspace.oci.tar" \
    --archive-sha256 "$archive_sha" --archive-size "$archive_size" \
    --source-digest "$source_digest" --state-root "$work/native-state")"
  [[ "$imported" == "registry.invalid/codewire/workspace@$source_digest" ]] || {
    echo 'local Buildx rehearsal: native import identity mismatch' >&2
    exit 1
  }
  echo 'local Buildx rehearsal: native verified import passed'
fi

default_after="$(current_builder)"
readonly default_after
if [[ "$default_after" != "$default_before" ]]; then
  echo "local Buildx rehearsal: selected builder changed ($default_before -> $default_after)" >&2
  exit 1
fi

echo "local Buildx rehearsal: OK (no-load invisible, loaded image visible, selected builder $default_after preserved)"
