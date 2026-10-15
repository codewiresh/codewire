#!/usr/bin/env bash
# Compile and lint every Rust target the product and its images build, in
# minutes: root workspace clippy over all targets with default and with all
# features (feature-gated binaries, smokes and test modules included), then
# each curated image workspace exactly as its image stages it. CI runs this
# beside the heavy jobs so a compile or lint error fails fast; developers run
# the same script locally.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
MANIFEST_DIR="${CURATED_RUST_MANIFEST_DIR:-$ROOT/deployments/docker}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/codewire-compile-all-targets.XXXXXX")"
trap 'rm -rf -- "$STAGING_ROOT"' EXIT
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
# Clippy compiles every target and lints it: once with default features and
# once with all features, so feature-gated and default-only code are linted.
phase "root clippy (default features)" \
  "$CARGO_BIN" clippy --locked --workspace --all-targets -- -D warnings
phase "root clippy (all features)" \
  "$CARGO_BIN" clippy --locked --workspace --all-targets --all-features -- -D warnings

shopt -s nullglob
manifests=("$MANIFEST_DIR"/*.Cargo.toml)
[ "${#manifests[@]}" -gt 0 ] || {
  printf 'no curated Rust workspace manifests found under %s\n' "$MANIFEST_DIR" >&2
  exit 1
}
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
    "$CARGO_BIN" check --locked --workspace --manifest-path "$stage/Cargo.toml"
done
printf '[compile-all-targets] every Rust target compiles\n'
