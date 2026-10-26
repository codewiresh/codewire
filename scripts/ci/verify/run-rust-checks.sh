#!/usr/bin/env bash
# Rust checks (compile once, infra#1632): the checks that build no test
# archive, in their own job on the build runner after its test archives, in
# the build folder's warm target folders (build-once.sh checks). Each runs
# when its inputs are selected:
# - always: compile-all-targets.sh, clippy with default and all features over
#   every target, and the curated image workspaces;
# - with |rust|: the feature graphs' lints, checks and dependency-graph
#   checks;
# - with BUILD_ONCE_LOCAL_VMM: the local-vmm shard's checks (the local VMM's
#   Darwin cross-check, the static guest's reproducibility proof, the desktop
#   check and package), and the artifact-selected desktop package;
# - with CW_PACKAGE_SELECTED: the cw Darwin cross-check (#3119 A13).
# The job sets up the pinned zig and cargo-zigbuild before this when a Darwin
# check is selected.
#
# Every selected check runs at once, each with its own log (infra#1534, #3494:
# one after another they averaged 6.6 of the runner's cores, run 24112).
# build-once.sh checks runs this under one jobserver, so the checks share the
# runner's compilers and the one still compiling gets the cores the finished
# ones no longer use. Cargo locks a target folder for a whole build, so each
# check has its own: CARGO_TARGET_DIR for compile-all-targets,
# RUST_CHECKS_FEATURES_TARGET_DIR for the feature graphs,
# RUST_CHECKS_DARWIN_TARGET_DIR for the local-vmm checks and
# RUST_CHECKS_CW_DARWIN_TARGET_DIR for the cw Darwin cross-check;
# CODEWIRE_DESKTOP_CHECK_TARGET_DIR holds the desktop builds of whichever
# check builds the desktop (the local-vmm checks with
# rust_pkg_codewire_desktop selected, the desktop checks without it, never
# both). Each defaults under CARGO_TARGET_DIR. Each Darwin check also keeps
# its own cargo-zigbuild wrapper folder (CARGO_ZIGBUILD_CACHE_DIR, which
# cargo-zigbuild extends with cargo-zigbuild/<version>), so two cargo-zigbuilds
# never rewrite one linker wrapper while the other runs it.
# Once every check has ended, each one's log is printed in a fixed order
# between its start and finish lines; any failed check fails the script.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR is required}"
features_target="${RUST_CHECKS_FEATURES_TARGET_DIR:-$CARGO_TARGET_DIR/features-checks}"
darwin_target="${RUST_CHECKS_DARWIN_TARGET_DIR:-$CARGO_TARGET_DIR/darwin}"
cw_darwin_target="${RUST_CHECKS_CW_DARWIN_TARGET_DIR:-$CARGO_TARGET_DIR/cw-darwin}"
desktop_target="${CODEWIRE_DESKTOP_CHECK_TARGET_DIR:-$CARGO_TARGET_DIR/desktop}"
readonly ARTIFACT_DESKTOP_SELECTION='|valid:v3|rust_pkg_codewire_desktop|complete|'
logs="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rust-checks.XXXXXX")"
names=()
pids=()

phase() {
  # phase NAME COMMAND...: start one check in the background; its output goes
  # to its own log, and its status and time to LOGS/<index>.status.
  local name="$1" index="${#names[@]}"
  shift
  names+=("$name")
  (
    started=$SECONDS
    result=0
    "$@" > "$logs/$index.log" 2>&1 < /dev/null || result=$?
    echo "$result $((SECONDS - started))" > "$logs/$index.status"
  ) &
  pids+=("$!")
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
  phase 'feature-graph checks' shard_checks rust-transport features \
    CARGO_TARGET_DIR="$features_target"
fi

if [ "${BUILD_ONCE_LOCAL_VMM:-}" = true ]; then
  if selected rust || selected transport; then
    phase 'local-vmm checks' shard_checks rust-transport local-vmm \
      CARGO_TARGET_DIR="$darwin_target" CODEWIRE_DESKTOP_CARGO_TARGET_DIR="$desktop_target" \
      CARGO_ZIGBUILD_CACHE_DIR="$darwin_target"
  fi
  # The desktop package outside the Rust selection, which Rust / transport
  # verification checks separately (its artifact-selected desktop step).
  if [ "${DESKTOP_PACKAGE_SELECTED:-}" = true ] && ! selected rust_pkg_codewire_desktop; then
    phase 'desktop checks' shard_checks rust local-vmm \
      VERIFICATION_SELECTION="$ARTIFACT_DESKTOP_SELECTION" \
      CARGO_TARGET_DIR="$desktop_target" CODEWIRE_DESKTOP_CARGO_TARGET_DIR="$desktop_target"
  fi
fi

if [ "${CW_PACKAGE_SELECTED:-}" = true ]; then
  phase 'cw Darwin cross-check' env CARGO_TARGET_DIR="$cw_darwin_target" \
    CARGO_ZIGBUILD_CACHE_DIR="$cw_darwin_target" \
    scripts/ci/verify/check-darwin-cross.sh --cli
fi

joined="$(printf '%s, ' "${names[@]}")"
echo "[rust-checks] at once: ${joined%, }"
for index in "${!pids[@]}"; do
  wait "${pids[$index]}" || true
done

status=0
for index in "${!names[@]}"; do
  name="${names[$index]}"
  result=1 elapsed=0
  [ ! -f "$logs/$index.status" ] || read -r result elapsed < "$logs/$index.status"
  echo "[rust-checks] $name: start"
  cat "$logs/$index.log" 2>/dev/null || true
  echo "[rust-checks] $name: finish (status=$result elapsed_seconds=$elapsed)"
  if [ "$result" -ne 0 ]; then
    echo "::error::the $name check failed"
    status=1
  fi
done
rm -rf -- "$logs"
exit "$status"
