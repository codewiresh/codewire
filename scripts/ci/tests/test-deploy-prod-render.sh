#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/deploy/deploy-prod.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

expect_retired() {
  local name="$1"
  shift
  if REGISTRY_HOST=registry.test "$SCRIPT" "$@" >"$WORK/$name.out" 2>&1; then
    echo "$name unexpectedly accepted a retired production mode" >&2
    exit 1
  fi
  grep -Fq 'direct production mutation is retired' "$WORK/$name.out"
}

expect_retired direct-tag v9.8.7
expect_retired temporal-preflight --preflight-only fixture

out="$WORK/render"
(
  cd "$ROOT"
  REGISTRY_HOST=registry.test \
    "$SCRIPT" --render-only v9.8.7 "$out"
)

for file in production.yaml derp.yaml mesh.yaml images.env; do
  test -s "$out/$file"
done

for family in services gateway derp mesh; do
  grep -Fq "registry.test/codewire/${family}:v9.8.7" "$out/images.env"
done

grep -Fq 'registry.test/codewire/services:v9.8.7' "$out/production.yaml"
grep -Fq 'registry.test/codewire/gateway:v9.8.7' "$out/production.yaml"
grep -Fq 'registry.test/codewire/derp:v9.8.7' "$out/derp.yaml"
grep -Fq 'registry.test/codewire/mesh:v9.8.7' "$out/mesh.yaml"

# shellcheck disable=SC2016 # Literal Flux marker, not shell expansion.
if grep -REn '\$imagepolicy|git\.example\.com/codewire|codewire/(services|gateway|derp|mesh):latest' "$out"; then
  echo 'production render contains retired setters or mutable/placeholder images' >&2
  exit 1
fi

echo 'production render-only boundary passed'
