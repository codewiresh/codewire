#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${KIND_CLUSTER_NAME}}"
NAMESPACE="${NAMESPACE:-default}"
DATABASE_URL="${DATABASE_URL:-postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable}"
BUILD_PARENT="$ROOT/apps/dashboard/.tmp"
BUILD_DIR=''

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ -n "$BUILD_DIR" ]]; then
    if [[ -d "$BUILD_DIR" && ! -L "$BUILD_DIR" &&
      "$(dirname "$BUILD_DIR")" == "$BUILD_PARENT" &&
      "${BUILD_DIR##*/}" == seed-users.* ]]; then
      rm -rf -- "$BUILD_DIR"
    else
      echo "refusing to remove unexpected seed build directory: $BUILD_DIR" >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$KUBE_CONTEXT" != "kind-${KIND_CLUSTER_NAME}" ]]; then
  echo "local Kind context mismatch: cluster=${KIND_CLUSTER_NAME} context=${KUBE_CONTEXT}" >&2
  exit 1
fi

if ! kind get clusters | grep -Fxq "$KIND_CLUSTER_NAME"; then
  echo "local Kind cluster ${KIND_CLUSTER_NAME} is not running; run make up first" >&2
  exit 1
fi

KUBE_CONTEXT="$KUBE_CONTEXT" NAMESPACE="$NAMESPACE" \
  "$ROOT/scripts/dev/kind/kind-forwards.sh" start postgres

echo "seeding synthetic e2e users in local Kind"
cd "$ROOT"
mkdir -p "$BUILD_PARENT"
[[ -d "$BUILD_PARENT" && ! -L "$BUILD_PARENT" ]] || {
  echo "dashboard build temp parent must be a non-symlink directory: $BUILD_PARENT" >&2
  exit 1
}
BUILD_DIR="$(mktemp -d "$BUILD_PARENT/seed-users.XXXXXX")"
chmod 0700 "$BUILD_DIR"
bun build apps/dashboard/e2e/seed-users.ts \
  --target=node --packages=external --outfile="$BUILD_DIR/seed-users.mjs"
DATABASE_URL="$DATABASE_URL" node "$BUILD_DIR/seed-users.mjs"
