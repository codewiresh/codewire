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
(cd "$work/source" && cargo package --locked -p codewire-proto -p codewire --target-dir "$target")

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
