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

# Full Cargo metadata can require registry packages for target configurations
# that the selected host build never fetched. First-party pruning only needs
# package identities, so keep metadata offline and dependency-free. The root
# workspace covers every shared path dependency; a detached manifest is added
# separately so its own package is pruned as well.
metadata_manifests=(Cargo.toml)
if [ "$manifest" != Cargo.toml ]; then
  metadata_manifests+=("$manifest")
fi

clean_first_party_packages() {
  local metadata_manifest="$1" metadata_json package clean_target clean_profile
  local -a manifest_packages clean_args target_args profile_args
  metadata_json="$(
    cargo metadata --offline --locked --no-deps --format-version 1 \
      --manifest-path "$metadata_manifest"
  )" || die "Cargo metadata failed for $metadata_manifest"
  mapfile -t manifest_packages < <(
    jq -er '.packages[] | select(.source == null) | .name' <<< "$metadata_json"
  )
  [ "${#manifest_packages[@]}" -gt 0 ] \
    || die "Cargo metadata found no first-party packages for $metadata_manifest"
  for package in "${manifest_packages[@]}"; do
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
      cargo clean --manifest-path "$metadata_manifest" --target-dir "$target_dir" \
        "${target_args[@]}" "${profile_args[@]}" "${clean_args[@]}"
    done
  done
}

for metadata_manifest in "${metadata_manifests[@]}"; do
  clean_first_party_packages "$metadata_manifest"
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
