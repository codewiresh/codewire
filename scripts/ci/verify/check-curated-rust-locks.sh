#!/usr/bin/env bash
# Reject manifest/lock drift in the reduced Rust workspaces copied into images.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CARGO_BIN="${CARGO_BIN:-cargo}"
MANIFEST_DIR="${CURATED_RUST_MANIFEST_DIR:-$ROOT/deployments/docker}"
STAGING_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/codewire-curated-rust-locks.XXXXXX")"

cleanup() {
  rm -rf -- "$STAGING_ROOT"
}
trap cleanup EXIT

check_workspace() {
  local name="$1"
  local manifest="$2"
  local lock="$3"
  local stage="$STAGING_ROOT/$name"
  local output

  mkdir -p "$stage"
  cp "$manifest" "$stage/Cargo.toml"
  cp "$lock" "$stage/Cargo.lock"
  ln -s "$ROOT/crates" "$stage/crates"
  ln -s "$ROOT/proto" "$stage/proto"
  ln -s "$ROOT/libs" "$stage/libs"

  run_locked_metadata() {
    {
      "$CARGO_BIN" metadata \
        --locked \
        --offline \
        --manifest-path "$stage/Cargo.toml" \
        --format-version 1 \
        >/dev/null
    } 2>&1
  }

  if ! output="$(run_locked_metadata)"; then
    if {
      grep -qF 'no matching package named' <<<"$output" \
        && grep -qF 'offline mode' <<<"$output"
    } || {
      grep -qF "can't checkout from" <<<"$output" \
        && grep -qF 'offline mode' <<<"$output"
    } || {
      grep -qF 'failed to download' <<<"$output" \
        && grep -qF 'attempting to make an HTTP request, but --offline was specified' <<<"$output"
    }; then
      printf '[curated-rust-locks] %s: populating exact locked Cargo inputs\n' "$name"
      "$CARGO_BIN" fetch --locked --manifest-path "$stage/Cargo.toml"
      if output="$(run_locked_metadata)"; then
        check_root_versions "$name" "$lock"
        printf '[curated-rust-locks] %s: OK\n' "$name"
        return
      fi
    fi
    printf '%s\n' "$output" >&2
    printf 'curated Rust workspace %s has manifest/lock drift\n' "$name" >&2
    return 1
  fi

  check_root_versions "$name" "$lock"
  printf '[curated-rust-locks] %s: OK\n' "$name"
}

# The curated images must build the versions the root workspace already
# selects. Drift is fixed with scripts/dev/sync-curated-rust-locks.sh.
check_root_versions() {
  python3 "$ROOT/scripts/ci/verify/curated_rust_locks.py" check-drift \
    "${CURATED_RUST_ROOT_LOCK:-$ROOT/Cargo.lock}" "$2" "$1"
}

shopt -s nullglob
manifests=("$MANIFEST_DIR"/*.Cargo.toml)
if [ "${#manifests[@]}" -eq 0 ]; then
  printf 'no curated Rust workspace manifests found under %s\n' "$MANIFEST_DIR" >&2
  exit 1
fi

for manifest in "${manifests[@]}"; do
  filename="${manifest##*/}"
  name="${filename%.Cargo.toml}"
  lock="$MANIFEST_DIR/$name.Cargo.lock"
  if [ ! -f "$lock" ]; then
    printf 'curated Rust workspace %s is missing %s\n' "$name" "$lock" >&2
    exit 1
  fi
  check_workspace "$name" "$manifest" "$lock"
done
