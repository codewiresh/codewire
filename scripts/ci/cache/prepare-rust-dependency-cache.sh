#!/usr/bin/env bash
# Build one trusted Rust dependency-cache flavor, then remove first-party outputs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
flavor="${1:-}"
target_dir="${CARGO_TARGET_DIR:-}"
clean_profiles=()
clean_targets=('')

die() {
  printf 'prepare-rust-dependency-cache: %s\n' "$*" >&2
  exit 2
}

[[ "$target_dir" = /* ]] || die 'CARGO_TARGET_DIR must be an absolute path'
case "$target_dir" in
  "$ROOT"/target/ci-cache/*) ;;
  *) die 'CARGO_TARGET_DIR must be beneath target/ci-cache' ;;
esac

cd "$ROOT"
mkdir -p "$target_dir"
rust_host="$(rustc -vV | awk '/^host:/ { print $2 }')"
[ "$rust_host" = x86_64-unknown-linux-gnu ] \
  || die 'cache producer requires the declared x86_64 GNU/Linux host'

case "$flavor" in
  host-debug)
    cargo test --locked --workspace --all-targets --no-run
    clean_profiles=('')
    ;;
  host-ci)
    cargo test --locked --profile ci --workspace --all-targets --no-run
    clean_profiles=(ci)
    ;;
  kind-ci)
    cargo build --locked --profile ci -p codewire-orchestration \
      --features kind-e2e --bins
    cargo build --locked --profile ci -p codewire-client \
      --features kind-e2e --examples
    cargo build --locked --profile ci -p codewire-billing
    clean_profiles=(ci)
    ;;
  cw-cross-ci)
    tool_root="$target_dir/tools"
    if [ ! -x "$tool_root/bin/cargo-zigbuild" ]; then
      cargo install --locked cargo-zigbuild --version 0.23.0 --root "$tool_root"
    fi
    export PATH="$tool_root/bin:$PATH"
    clean_targets=(
      x86_64-unknown-linux-musl
      aarch64-unknown-linux-gnu
      x86_64-apple-darwin
      aarch64-apple-darwin
    )
    for target in "${clean_targets[@]}"; do
      cargo zigbuild --locked --profile ci \
        --package codewire-cli-bin --bin cw --target "$target"
    done
    clean_profiles=(ci)
    ;;
  desktop-release)
    cargo test --locked --manifest-path crates/codewire-desktop/Cargo.toml --no-run
    CARGO_TARGET_DIR="$target_dir" \
      scripts/ci/release/package-codewire-desktop.sh --dry-run 0.0.0-ci
    clean_profiles=(dev release)
    ;;
  *)
    die 'flavor must be host-debug, host-ci, kind-ci, cw-cross-ci, or desktop-release'
    ;;
esac

manifest='Cargo.toml'
if [ "$flavor" = desktop-release ]; then
  manifest='crates/codewire-desktop/Cargo.toml'
fi
mapfile -t workspace_packages < <(
  cargo metadata --offline --locked --format-version 1 \
    --manifest-path "$manifest" \
    | jq -er '.packages[] | select(.source == null) | .name'
)
[ "${#workspace_packages[@]}" -gt 0 ] || die 'Cargo metadata found no first-party packages'
clean_args=()
for package in "${workspace_packages[@]}"; do
  clean_args+=( -p "$package" )
done
for clean_target in "${clean_targets[@]}"; do
  target_args=()
  if [ -n "$clean_target" ]; then
    target_args+=(--target "$clean_target")
  fi
  for clean_profile in "${clean_profiles[@]}"; do
    profile_args=()
    if [ -n "$clean_profile" ]; then
      profile_args+=(--profile "$clean_profile")
    fi
    cargo clean --manifest-path "$manifest" --target-dir "$target_dir" \
      "${target_args[@]}" "${profile_args[@]}" "${clean_args[@]}"
  done
done

offending_fingerprint="$(
  find "$target_dir" -type d -path '*/.fingerprint/codewire-*' -print -quit
)"
if [ -n "$offending_fingerprint" ]; then
  die "first-party fingerprint remained after Cargo clean: ${offending_fingerprint#"$target_dir"/}"
fi
offending_output="$(
  find "$target_dir" -type f \( -name 'libcodewire_*' -o -name 'codewire_*' \) \
    -print -quit
)"
if [ -n "$offending_output" ]; then
  die "first-party build output remained after Cargo clean: ${offending_output#"$target_dir"/}"
fi

size_bytes="$(du -sk "$target_dir" | awk '{ print $1 * 1024 }')"
[[ "$size_bytes" =~ ^[0-9]+$ ]] || die 'unable to measure cache size'
if (( size_bytes > 4294967296 )); then
  die "cache exceeds 4 GiB publication ceiling: ${size_bytes} bytes"
fi
printf 'rust dependency cache prepared: flavor=%s bytes=%s target=%s\n' \
  "$flavor" "$size_bytes" "$target_dir"
