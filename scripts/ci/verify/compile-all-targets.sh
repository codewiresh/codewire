#!/usr/bin/env bash
# Compile and lint every Rust target the product and its images build, in
# minutes: root workspace clippy over all targets with default and with all
# features (feature-gated binaries, smokes and test modules included), and
# each curated image workspace exactly as its image stages it, all three at
# once. CI runs this
# beside the heavy jobs so a compile or lint error fails fast; developers run
# the same script locally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
MANIFEST_DIR="${CURATED_RUST_MANIFEST_DIR:-$ROOT/deployments/docker}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
# Each curated workspace is staged at the same path on every run, beside its
# target folder: TARGET_DIR/curated/NAME, built in TARGET_DIR/curated-NAME. In
# CI TARGET_DIR is the job's warm target folder (Rust checks:
# target/ci-cache/host-debug, select-warm-rust-cache.sh); locally it is the
# checkout's target folder. A stable path keeps the staged packages' paths,
# and so Cargo's fingerprints, equal between runs: an unchanged run is fresh
# and a change rebuilds only what it touches. A fresh mktemp path rebuilt
# codewire-proto and everything above it every time (34-54 s per CI run).
STAGING_ROOT="$TARGET_DIR/curated"
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
select_local_rust_cache "$ROOT" || true

phase() {
  local name="$1"
  shift
  local started_at=$SECONDS status=0
  printf '[compile-all-targets] %s: start\n' "$name"
  "$@" || status=$?
  printf '[compile-all-targets] %s: finish (status=%s elapsed_seconds=%s)\n' \
    "$name" "$status" "$((SECONDS - started_at))"
  return "$status"
}

cd "$ROOT"
# The workspace hack unifies third-party features for every build below; a
# stale one is cheap to detect before any of them compiles.
phase "workspace hack" "$ROOT/scripts/ci/verify/check-workspace-hack.sh"

shopt -s nullglob
manifests=("$MANIFEST_DIR"/*.Cargo.toml)
[ "${#manifests[@]}" -gt 0 ] || {
  printf 'no curated Rust workspace manifests found under %s\n' "$MANIFEST_DIR" >&2
  exit 1
}

curated() {
  # One run at a time stages and checks in this target folder: another run
  # would replace the staged workspace under it. The lock is held until this
  # function's subshell exits. Linux hosts and CI images have flock; a host
  # without it (macOS) runs one compile-all-targets.sh per target folder at a
  # time.
  mkdir -p "$TARGET_DIR"
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$STAGING_ROOT.lock"
    flock 9
  else
    printf '[compile-all-targets] flock is missing: run one at a time in %s\n' "$TARGET_DIR" >&2
  fi
  # Staged afresh at the same path on every run: nothing from an earlier run,
  # such as a curated workspace that no longer exists, stays, and the folder
  # is always a new directory, never a link left in a shared warm cache.
  rm -rf -- "$STAGING_ROOT"
  mkdir "$STAGING_ROOT"
  local manifest filename name stage
  for manifest in "${manifests[@]}"; do
    filename="${manifest##*/}"
    name="${filename%.Cargo.toml}"
    stage="$STAGING_ROOT/$name"
    mkdir -p "$stage"
    cp "$manifest" "$stage/Cargo.toml"
    cp "$MANIFEST_DIR/$name.Cargo.lock" "$stage/Cargo.lock"
    ln -s "$ROOT/crates" "$stage/crates"
    ln -s "$ROOT/proto" "$stage/proto"
    ln -s "$ROOT/libs" "$stage/libs"
    # Separate target directories keep each image's dependency versions from
    # invalidating the root build's artifacts.
    phase "curated $name" env CARGO_TARGET_DIR="$TARGET_DIR/curated-$name" \
      "$CARGO_BIN" check --locked --workspace --manifest-path "$stage/Cargo.toml" || return
  done
}

# Clippy compiles every target and lints it: once with default features and
# once with all features, so feature-gated and default-only code are linted.
# Each of the three builds has its own target folder (Cargo locks a folder for
# a whole build); the all-features one sits inside TARGET_DIR, as the curated
# ones do, so it stays and goes with it. Under a shared jobserver (CI's build
# job, which bounds every compiler) they run at once: one after another they
# took the sum of their times (infra#1534, step A). Without one (a
# workstation, where preflight runs this script as one job) they run one after
# another, so they never take every core three times over. Each build's output
# is printed whole when it ends, and the first failure is the exit status.
default_clippy() {
  phase "root clippy (default features)" \
    "$CARGO_BIN" clippy --locked --workspace --all-targets -- -D warnings
}
all_features_clippy() {
  phase "root clippy (all features)" env CARGO_TARGET_DIR="$TARGET_DIR/all-features" \
    "$CARGO_BIN" clippy --locked --workspace --all-targets --all-features -- -D warnings
}
builds=(default_clippy all_features_clippy curated)
logs="$(mktemp -d "${TMPDIR:-/tmp}/compile-all-targets.XXXXXX")"
trap 'rm -rf -- "$logs"' EXIT
status=0
if [[ "${CARGO_MAKEFLAGS:-}" == *--jobserver-auth=* ]]; then
  pids=()
  for index in "${!builds[@]}"; do
    ( "${builds[$index]}" ) >"$logs/$index" 2>&1 &
    pids+=($!)
  done
  for index in "${!pids[@]}"; do
    wait "${pids[$index]}" || { result=$?; [ "$status" != 0 ] || status=$result; }
    cat -- "$logs/$index"
  done
else
  # One after another, stopping at the first failure, as before. Each runs as
  # its own job: a function called left of || would run with set -e off.
  for build in "${builds[@]}"; do
    ( "$build" ) &
    wait "$!" || { status=$?; break; }
  done
fi
[ "$status" = 0 ] || exit "$status"
printf '[compile-all-targets] every Rust target compiles\n'
