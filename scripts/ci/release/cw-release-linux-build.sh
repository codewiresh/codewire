#!/usr/bin/env bash
# Runs inside cw-release-linux.Dockerfile on the trusted BuildKit builder
# (#3119): one Linux cw, built by the unchanged package-cw-release.sh exactly as
# the in-job build runs it, from the selected commit (.git included). Writes
# cw-<version>-<target>, its .sha256 line and the .admitted line
# package-cw-release.sh printed for it; build-cw-linux.sh verifies all three.
# CW_RELEASE_SRC, CW_RELEASE_SCRIPTS and CW_RELEASE_OUT default to the
# Dockerfile's /src, /workflow/scripts and /out; the test sets them.
set -euo pipefail

die() {
  echo "cw-release-linux-build: $*" >&2
  exit 1
}

src="${CW_RELEASE_SRC:-/src}"
scripts="${CW_RELEASE_SCRIPTS:-/workflow/scripts}"
out="${CW_RELEASE_OUT:-/out}"
target="${CW_RELEASE_TARGET:?}"
version="${CW_RELEASE_VERSION:?}"
case "$target" in
  x86_64-unknown-linux-musl|aarch64-unknown-linux-gnu) ;;
  *) die "unexpected target: $target" ;;
esac

# The runtime document every release cw embeds, when the run packed one.
case "${CW_RELEASE_HAS_RUNTIME:-}" in
  1) export CW_RELEASE_LOCAL_RUNTIME_DIR="${CW_RELEASE_RUNTIME:-/local-runtime}" ;;
  0) unset CW_RELEASE_LOCAL_RUNTIME_DIR ;;
  *) die "CW_RELEASE_HAS_RUNTIME must be exactly 0 or 1" ;;
esac
# Empty means the checkout's HEAD, as package-cw-release.sh defaults.
[ -n "${CW_RELEASE_SOURCE_SHA:-}" ] || unset CW_RELEASE_SOURCE_SHA
[ -n "${CW_RELEASE_TAG_OBJECT_SHA:-}" ] || unset CW_RELEASE_TAG_OBJECT_SHA
[ -n "${CARGO_BUILD_JOBS:-}" ] || unset CARGO_BUILD_JOBS

# warm: the builder's per-target Cargo target directory, kept between main
# builds. cold: a fresh one inside this step, discarded with it.
case "${CW_RELEASE_TARGET_CACHE:-}" in
  warm) export CARGO_TARGET_DIR="${CW_RELEASE_WARM_TARGET:-/cargo-target}" ;;
  cold) CARGO_TARGET_DIR="$(mktemp -d)/cw-release-target"; export CARGO_TARGET_DIR ;;
  *) die "CW_RELEASE_TARGET_CACHE must be warm or cold" ;;
esac

cd "$src"
# The source keeps the clone's modification times, which can be older than
# what another commit compiled into the warm target directory since (or skewed
# against the builder's clock). Cargo would then reuse that commit's workspace
# crates under this commit's build record. Every source file is newer than
# anything in the target directory once touched here, inside the locked step:
# the workspace always rebuilds, and the lockfile-pinned dependencies stay warm.
find "$src" -path "$src/.git" -prune -o -exec touch -h {} +

log="$(mktemp)"
CW_RELEASE_BUILD_CMD='cargo zigbuild' CW_RELEASE_TARGETS="$target" \
  "$scripts/ci/release/package-cw-release.sh" "$version" | tee "$log"
admitted="$(grep -E "^cw-release: admitted target=$target version=$version " "$log")" ||
  die "package-cw-release.sh reported no admission for $target $version"
[ "$(printf '%s\n' "$admitted" | wc -l)" -eq 1 ] || die "more than one admission for $target"

name="cw-$version-$target"
mkdir "$out"
cp "dist/cw-release/$name" "$out/$name"
(cd "$out" && sha256sum "$name" > "$name.sha256")
printf '%s\n' "$admitted" > "$out/$name.admitted"
