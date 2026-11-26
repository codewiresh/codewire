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
# time for the 17 MB generated codewire-proto crate (infra#1534). Optimizing
# build-dependencies (protox + connectrpc-build) speeds up cold builds too.
#
# When a kept target folder is supplied (CI's warm sdk-package folder) and the
# caller did not set RUSTC_WRAPPER, run an isolated local-disk sccache beside
# the target so repeated verify builds with unchanged protos/sources hit local
# disk (~15 s vs ~250 s) without any remote backend or OIDC identity (#5231).
(
  cd "$work/source"
  export CARGO_PROFILE_DEV_DEBUG=0
  export CARGO_PROFILE_DEV_BUILD_OVERRIDE_OPT_LEVEL=2
  if [[ -n "${CODEWIRE_SDK_PACKAGE_TARGET_DIR:-}" && -z "${RUSTC_WRAPPER:-}" ]]; then
    candidate="${CODEWIRE_SDK_PACKAGE_SCCACHE_BIN:-$(command -v sccache || true)}"
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      # Local must stay local (#5231): drop every ambient SCCACHE_/AWS_ variable
      # and point SCCACHE_CONF at /dev/null so sccache can never talk to a
      # remote backend or another process's server.
      for env_name in $(compgen -e); do
        case "$env_name" in
          SCCACHE_*|AWS_*) unset "$env_name" ;;
        esac
      done
      mkdir -p "$target/.sccache"
      export SCCACHE_DIR="$target/.sccache"
      export SCCACHE_CACHE_SIZE="${CODEWIRE_SDK_PACKAGE_SCCACHE_SIZE:-2G}"
      export SCCACHE_CONF=/dev/null
      export SCCACHE_SERVER_UDS="$work/sccache.sock"
      if "$candidate" --start-server >/dev/null 2>&1; then
        export RUSTC_WRAPPER="$candidate"
        export CARGO_INCREMENTAL=0
        trap '"$RUSTC_WRAPPER" --stop-server >/dev/null 2>&1 || true' EXIT
      else
        unset SCCACHE_DIR SCCACHE_CACHE_SIZE SCCACHE_CONF SCCACHE_SERVER_UDS
      fi
    fi
  fi
  cargo package --locked -p codewire-proto -p codewire --target-dir "$target"
  if [[ -n "${SCCACHE_SERVER_UDS:-}" && -n "${RUSTC_WRAPPER:-}" ]]; then
    "$RUSTC_WRAPPER" --show-stats 2>/dev/null \
      | grep -E '^(Compile requests|Cache hits|Cache misses|Cache location)' || true
  fi
)

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
