#!/usr/bin/env bash
# Rust checks (compile once, infra#1632): the checks that build no test
# archive, in their own job on a metal guest with its warm Rust cache and the
# shared compiler cache, beside the build runner's test archives. Each runs
# when its inputs are selected, as its build-runner leg did:
# - always: compile-all-targets.sh, clippy with default and all features over
#   every target, and the curated image workspaces;
# - with |rust|: the feature graphs' lints, checks and dependency-graph
#   checks;
# - with BUILD_ONCE_LOCAL_VMM: the local-vmm shard's checks (the local VMM's
#   Darwin cross-check, the static guest's reproducibility proof, the desktop
#   check and package), and the artifact-selected desktop package;
# - with CW_PACKAGE_SELECTED: the cw Darwin cross-check (#3119 A13).
# The job sets up the pinned zig and cargo-zigbuild before this when a Darwin
# check is selected. CARGO_TARGET_DIR is the job's host-debug folder; the
# desktop builds use CODEWIRE_DESKTOP_CHECK_TARGET_DIR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR is required}"
desktop_target="${CODEWIRE_DESKTOP_CHECK_TARGET_DIR:-$CARGO_TARGET_DIR/desktop}"
readonly ARTIFACT_DESKTOP_SELECTION='|valid:v3|rust_pkg_codewire_desktop|complete|'
status=0

phase() {
  local name="$1" started=$SECONDS result=0
  shift
  echo "[rust-checks] $name: start"
  "$@" || result=$?
  echo "[rust-checks] $name: finish (status=$result elapsed_seconds=$((SECONDS - started)))"
  if [ "$result" -ne 0 ]; then
    echo "::error::the $name check failed"
    status=1
  fi
}

selected() {
  [[ "${VERIFICATION_SELECTION:-}" == *"|$1|"* ]]
}

# shellcheck disable=SC2329 # phase calls it by name.
shard_checks() {
  # shard_checks FAMILY SHARD [ENV...]: one shard's checks stage.
  local family="$1" shard="$2"
  shift 2
  env RUST_TRANSPORT_SHARD="$shard" RUST_SHARD_STAGE=checks RUST_SHARD_ARCHIVES='' "$@" \
    scripts/ci/verify/run-product-verification.sh "$family"
}

phase 'compile-all-targets' scripts/ci/verify/compile-all-targets.sh

if selected rust; then
  phase 'feature-graph checks' shard_checks rust-transport features
fi

if [ "${BUILD_ONCE_LOCAL_VMM:-}" = true ]; then
  if selected rust || selected transport; then
    phase 'local-vmm checks' shard_checks rust-transport local-vmm \
      CODEWIRE_DESKTOP_CARGO_TARGET_DIR="$desktop_target"
  fi
  # The desktop package outside the Rust selection, which Rust / transport
  # verification checks separately (its artifact-selected desktop step).
  if [ "${DESKTOP_PACKAGE_SELECTED:-}" = true ] && ! selected rust_pkg_codewire_desktop; then
    phase 'desktop checks' shard_checks rust local-vmm \
      VERIFICATION_SELECTION="$ARTIFACT_DESKTOP_SELECTION" \
      CODEWIRE_DESKTOP_CARGO_TARGET_DIR="$desktop_target"
  fi
fi

if [ "${CW_PACKAGE_SELECTED:-}" = true ]; then
  phase 'cw Darwin cross-check' scripts/ci/verify/check-darwin-cross.sh --cli
fi

exit "$status"
