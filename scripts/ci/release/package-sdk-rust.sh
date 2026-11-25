#!/usr/bin/env bash
# Package the Rust SDK: codewire-proto and codewire, as the two .crate files
# crates.io receives.
#
# usage: package-sdk-rust.sh OUTDIR
#
# `cargo package` builds each crate from its packaged sources alone, with
# codewire built against the packaged codewire-proto rather than the
# workspace's copy, so a crate that would not build from crates.io is never
# written to OUTDIR. The packages may carry only their own sources, examples,
# licenses and the protos codewire-proto compiles, never a global-administrator one;
# nothing else from the workspace. CODEWIRE_SDK_PACKAGE_TARGET_DIR names a target folder to
# build in, which CI keeps warm between runs; by default it is a temporary one.
set -euo pipefail

fail() {
  printf '[package-sdk-rust] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 1 ]] || {
  printf 'usage: package-sdk-rust.sh OUTDIR\n' >&2
  exit 2
}
root="$(cd "$(dirname "$0")/../../.." && pwd)"
mkdir -p "$1"
outdir="$(cd "$1" && pwd)"

work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-rust-package.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

version="$(cd "$root" && cargo metadata --locked --no-deps --format-version 1 |
  jq -r '[.packages[] | select(.name == "codewire" or .name == "codewire-proto") | .version] | unique | join(" ")')"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "codewire and codewire-proto must share one MAJOR.MINOR.PATCH version, not: $version"

target="${CODEWIRE_SDK_PACKAGE_TARGET_DIR:-$work/target}"
# codewire-proto's protos are staged beside it in a copy of HEAD's tree, as
# the published crate carries them (stage-sdk-rust-source.sh).
mkdir "$work/source"
"$root/scripts/ci/release/stage-sdk-rust-source.sh" "$work/source"
# A kept target (CI's) would verify against an earlier tree's crates, so
# rebuild the two crates every time; their registry dependencies stay warm.
# Two copies go stale. Cargo verifies codewire against codewire-proto from a
# local registry in "$target/package", unpacked under CARGO_HOME's
# registry/src/-<hash>/; a registry crate of one version is never unpacked
# again, and the hash follows the target, so that copy is the first run's
# forever. Its compiled crates are fingerprinted by that version too, and
# `cargo package` stamps every file with one fixed mtime, so nothing looks
# changed. Remove the unpacked copies of only these two crates from only
# Cargo's local registries (folders named -<hash>), then clean the two crates
# from the target. Cargo cleans only a folder tagged as a cache, and tags only
# the folders it creates itself, not one made before its first build, as
# CI's is.
if [[ -d "$target" ]]; then
  for unpacked in "${CARGO_HOME:-$HOME/.cargo}"/registry/src/-*/{codewire-proto,codewire}-"$version"; do
    [[ -d "$unpacked" ]] && rm -rf -- "$unpacked"
  done
  [[ -f "$target/CACHEDIR.TAG" ]] ||
    printf 'Signature: 8a477f597d28d172789f06886806bc55\n# This file is a cache directory tag created by cargo.\n# For information about cache directory tags see https://bford.info/cachedir/\n' \
      >"$target/CACHEDIR.TAG"
  (cd "$work/source" && cargo clean --locked -p codewire-proto -p codewire --target-dir "$target")
fi
# Cargo's verify build only checks that the packaged tarballs compile cleanly;
# debuginfo is never part of a .crate archive and more than doubles compile
# time for the 17 MB generated codewire-proto crate (infra#1534).
(cd "$work/source" && CARGO_PROFILE_DEV_DEBUG=0 \
  cargo package --locked -p codewire-proto -p codewire --target-dir "$target")

for crate in codewire-proto codewire; do
  file="$target/package/$crate-$version.crate"
  [[ -f "$file" ]] || fail "cargo package wrote no $crate-$version.crate"
  tar -tzf "$file" | sed "s|^$crate-$version/||" >"$work/$crate.contents"
  grep -qx 'LICENSE' "$work/$crate.contents" || fail "$crate is packaged without its LICENSE"
  if grep -vE '^(\.cargo_vcs_info\.json|Cargo\.toml|Cargo\.toml\.orig|Cargo\.lock|LICENSE|LICENSE-APACHE|README\.md|build\.rs|src/.*\.rs|examples/.*\.rs|proto/(codewire|google)/.*\.proto)$' \
    "$work/$crate.contents"; then
    fail "$crate's package carries files beyond its sources and licenses"
  fi
  if grep -E '^proto/codewire/admin/' "$work/$crate.contents"; then
    fail "$crate's package carries a global-administrator proto"
  fi
  cp "$file" "$outdir/"
  printf '[package-sdk-rust] wrote %s\n' "$outdir/$crate-$version.crate"
done
