#!/usr/bin/env bash
# Build the retained Kind suites' smoke inventory in the same kind-dev
# BuildKit builder and per-worktree Cargo target as the service deploys
# (deploy-service.sh), and install it where the suites read it. After a deploy
# compiled orchestration and cw, the orchestration smokes and the host cw only
# link; the client examples and the billing contract reuse the dependencies
# already built there. The target keeps its content-hash freshness guard (see
# kind-dev-binary.Dockerfile), so a binary is never reused across source.
#
# Usage: build-smokes.sh SMOKE_DIR BILLING_TEST_ARTIFACT_JSONL
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
# shellcheck source=scripts/dev/kind/dev-builder.sh
source "$ROOT/scripts/dev/kind/dev-builder.sh"

log() { printf '[kind-smokes] %s\n' "$*" >&2; }
die() { printf '[kind-smokes] error: %s\n' "$*" >&2; exit 1; }

[[ $# -eq 2 && "$1" == /* && "$2" == /* ]] ||
  die 'usage: build-smokes.sh SMOKE_DIR BILLING_TEST_ARTIFACT_JSONL (absolute paths)'
readonly SMOKE_DIR="$1" BILLING_JSONL="$2"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
STATE="$ROOT/.tmp/kind-dev/${KIND_CLUSTER_NAME}"
umask 077
mkdir -p "$STATE" "$SMOKE_DIR/examples" "$SMOKE_DIR/kind-smoke-tests" "$(dirname "$BILLING_JSONL")"

started_at="$(date +%s)"
BUILDER="$(kind_dev_builder codewire-kind-dev "$STATE")"
TREE="$(kind_dev_tree "$ROOT")"
work="$(mktemp -d "$STATE/smokes.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# smoke CRATE FEATURES BINS EXAMPLES TEST: one kind-dev-binary solve.
smoke() {
  local crate="$1" features="$2" bins="$3" examples="$4" test_name="$5" out
  out="$(mktemp -d "$work/out.XXXXXX")"
  log "building ${crate}${bins:+ ${bins}}${examples:+ examples ${examples}}${test_name:+ test ${test_name}}${features:+ (features ${features})}"
  KIND_DEV_CRATE="$crate" KIND_DEV_BIN="$bins" KIND_DEV_FEATURES="$features" \
    docker buildx bake --builder "$BUILDER" --file "$ROOT/docker-bake.hcl" \
      --set "kind-dev-binary.args.KIND_DEV_TREE=${TREE}" \
      --set "kind-dev-binary.args.KIND_DEV_EXAMPLES=${examples}" \
      --set "kind-dev-binary.args.KIND_DEV_TEST=${test_name}" \
      --set "kind-dev-binary.output=type=local,dest=${out}" kind-dev-binary
  local name
  for name in $bins; do
    [ -x "$out/$name" ] || die "the build produced no ${name}"
    install -m 0755 "$out/$name" "$SMOKE_DIR/$name"
  done
  for name in $examples; do
    [ -x "$out/examples/$name" ] || die "the build produced no example ${name}"
    install -m 0755 "$out/examples/$name" "$SMOKE_DIR/examples/$name"
  done
  if [ -n "$test_name" ]; then
    [ -x "$out/tests/$test_name" ] || die "the build produced no test ${test_name}"
    install -m 0755 "$out/tests/$test_name" "$SMOKE_DIR/kind-smoke-tests/$test_name"
  fi
}

smoke codewire-orchestration kind-e2e \
  'crd-smoke environment-setup-smoke exec-smoke exec-stream-smoke file-service-smoke prepare-stream-smoke log-stream-smoke temporal-smoke temporal-fencing-smoke reconciler-ttl-smoke sidecar-smoke' \
  '' ''
smoke codewire-client '' '' \
  'platform-run-smoke environment-session-smoke environment-cw-runtime-smoke' ''
smoke codewire-client kind-e2e '' 'coordinator-ingress-smoke' ''
# The same build the daemon deploy layers into the sandbox image.
smoke codewire-cli-bin '' 'cw' '' ''
smoke codewire-billing '' '' '' wire_contract

# The suite reads the billing contract the way Cargo reports it.
jq -cn --arg executable "$SMOKE_DIR/kind-smoke-tests/wire_contract" '{
  reason: "compiler-artifact",
  profile: {test: true},
  target: {name: "wire_contract"},
  executable: $executable
}' >"$BILLING_JSONL"
printf 'CODEWIRE_CI_PHASE name=kind-smoke-binary-build seconds=%s\n' \
  "$(( $(date +%s) - started_at ))"
