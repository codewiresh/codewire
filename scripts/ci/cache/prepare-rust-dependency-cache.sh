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
    CARGO_TARGET_DIR="$target_dir" \
      scripts/ci/release/package-codewire-desktop.sh --dry-run 0.0.0-ci
    clean_profiles=(release)
    ;;
  *)
    die 'flavor must be host-debug, host-ci, kind-ci, cw-cross-ci, or desktop-release'
    ;;
esac

manifest='Cargo.toml'
lockfile='Cargo.lock'
if [ "$flavor" = desktop-release ]; then
  manifest='crates/codewire-desktop/Cargo.toml'
  lockfile='crates/codewire-desktop/Cargo.lock'
fi

# Full Cargo metadata can require registry packages for target configurations
# that the selected host build never fetched, while --no-deps omits excluded
# local path dependencies from detached workspaces. Cargo.lock already records
# every resolved local package without a source, so derive the complete pruning
# set from the selected build's lockfile without consulting a registry.
first_party_package_lines="$(
  python3 - "$lockfile" <<'PY'
import re
import sys
import tomllib
from pathlib import Path

lockfile = Path(sys.argv[1])
document = tomllib.loads(lockfile.read_text(encoding="utf-8"))
packages = document.get("package")
if not isinstance(packages, list):
    raise SystemExit(f"{lockfile}: package records are missing")

names = []
for package in packages:
    if not isinstance(package, dict):
        raise SystemExit(f"{lockfile}: package record is invalid")
    source = package.get("source")
    if source is not None and not isinstance(source, str):
        raise SystemExit(f"{lockfile}: package source is invalid")
    if source is not None:
        continue
    name = package.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise SystemExit(f"{lockfile}: local package name is invalid")
    names.append(name)

if not names:
    raise SystemExit(f"{lockfile}: no local packages were found")
if len(names) != len(set(names)):
    raise SystemExit(f"{lockfile}: local package names are ambiguous")
print(*sorted(names), sep="\n")
PY
)" || die "first-party package discovery failed for $lockfile"
mapfile -t first_party_packages <<< "$first_party_package_lines"
[ "${#first_party_packages[@]}" -gt 0 ] \
  || die "lockfile found no first-party packages for $manifest"

clean_args=()
for package in "${first_party_packages[@]}"; do
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
    cargo clean --offline --locked --manifest-path "$manifest" \
      --target-dir "$target_dir" "${target_args[@]}" \
      "${profile_args[@]}" "${clean_args[@]}"
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
