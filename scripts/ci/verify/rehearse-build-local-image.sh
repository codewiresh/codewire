#!/usr/bin/env bash
# Prove that a Docker-container builder needs --load, then prove the canonical
# helper loads the same scratch image without changing the selected builder.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly HELPER="$ROOT/scripts/ci/images/build-local-image.sh"

for tool in docker sed; do
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

"$HELPER" "$positive_tag" "$work/Dockerfile" "$work"
docker image inspect "$positive_tag" >/dev/null

default_after="$(current_builder)"
readonly default_after
if [[ "$default_after" != "$default_before" ]]; then
  echo "local Buildx rehearsal: selected builder changed ($default_before -> $default_after)" >&2
  exit 1
fi

echo "local Buildx rehearsal: OK (no-load invisible, loaded image visible, selected builder $default_after preserved)"
