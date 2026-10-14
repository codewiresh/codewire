#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: build-runtime-guest-root.sh --target TARGET --busybox FILE --runc FILE --rust-std FILE
                                   --rust-std FILE --protoc-zip FILE --output FILE
                                   [--job-container CONTAINER]

Builds one of the local VM runtime's guest roots with
scripts/ci/verify/build-local-vmm-initramfs.sh --verify-root --target TARGET,
inside the pinned Rust 1.93.0 image from
scripts/ci/release/local-runtime-sources.json: aarch64-unknown-linux-musl for
macOS hosts (#2539), x86_64-unknown-linux-musl for Linux hosts (#2733). The CI
runner's sealed toolchain has no aarch64-unknown-linux-musl, and no host
toolchain is changed: the container installs the standard libraries of both
musl targets the recipe builds (the guest and the x86_64 archive packer)
from their pinned tarballs, offline, and protoc 35.1 from its pinned zip.

FILE inputs are the target's BusyBox and runc the guest root seals (checked
against their pins here and by the recipe), each pinned rust-std tarball and
the protoc zip (checked here). The build runs as the caller's uid with this checkout and the inputs
mounted read-only; --job-container is as for build-runtime-kernel.sh. FILE's
directory must exist; FILE must not.
EOF
}

die() {
  echo "build-runtime-guest-root: $*" >&2
  exit 1
}

target="" busybox="" runc="" protoc_zip="" output="" job_container=""
rust_std=()
while [ $# -gt 0 ]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --busybox) busybox="${2:-}"; shift 2 ;;
    --runc) runc="${2:-}"; shift 2 ;;
    --rust-std) rust_std+=("${2:-}"); shift 2 ;;
    --protoc-zip) protoc_zip="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --job-container) job_container="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$target" in
  aarch64-unknown-linux-musl|x86_64-unknown-linux-musl) ;;
  *) die "--target must be aarch64-unknown-linux-musl or x86_64-unknown-linux-musl" ;;
esac
absolute_file() {
  case "$2" in /*) ;; *) die "--$1 must be an absolute path" ;; esac
  [ "$1" = output ] || { [ -f "$2" ] && [ ! -L "$2" ]; } || die "--$1 is not a regular file"
}
for name in busybox runc protoc_zip output; do
  absolute_file "${name//_/-}" "${!name}"
done
for file in ${rust_std[@]+"${rust_std[@]}"}; do
  absolute_file rust-std "$file"
done
[ ! -e "$output" ] || die "output already exists"
parent="$(dirname "$output")"
[ -d "$parent" ] || die "output parent does not exist"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
pins="$repo/scripts/ci/release/local-runtime-sources.json"
pin() {
  python3 -c 'import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2:]:
    value = value[key]
print(value)' "$pins" "$@"
}
# Each rust-std tarball is the pinned one of exactly one target; every pinned
# target is given.
targets="$(python3 -c 'import json, sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["guest_root_builder"]["rust_std"])))' "$pins")"
members=""
for target in $targets; do
  found=""
  for file in ${rust_std[@]+"${rust_std[@]}"}; do
    [ "$(sha256sum "$file" | cut -c1-64)" = "$(pin guest_root_builder rust_std "$target" sha256)" ] && found="$file"
  done
  [ -n "$found" ] || die "no --rust-std is the pinned $target tarball"
  members="$members $found=rust-std-1.93.0-$target/rust-std-$target/lib/rustlib/$target"
done
[ "${#rust_std[@]}" = "$(wc -w <<<"$targets")" ] || die "give exactly one --rust-std per pinned target"
[ "$(sha256sum "$protoc_zip" | cut -c1-64)" = "$(pin guest_root_builder protoc sha256)" ] ||
  die "the protoc zip differs from its pin"
image="$(pin guest_root_builder image)"
busybox_sha256="$(pin initramfs_inputs "$target" busybox member_sha256)"
runc_sha256="$(pin initramfs_inputs "$target" runc sha256)"
[ "$(sha256sum "$busybox" | cut -c1-64)" = "$busybox_sha256" ] || die "BusyBox is not the pinned $target build"
[ "$(sha256sum "$runc" | cut -c1-64)" = "$runc_sha256" ] || die "runc is not the pinned $target build"
uid="$(id -u)" gid="$(id -g)"

# The build's scratch (Cargo home, staging) and output share one writable
# directory beside the output, on the job's workspace in CI.
scratch="$(mktemp -d "$parent/.guest-root.XXXXXX")"
trap 'chmod -R u+w "$scratch" 2>/dev/null || true; rm -rf "$scratch"' EXIT
# The x86_64 recipe runs runc to check its version, and the input is mounted
# read-only: the build gets an executable copy of the same checked bytes.
install -m 0500 "$runc" "$scratch/runc"
[ "$(sha256sum "$scratch/runc" | cut -c1-64)" = "$runc_sha256" ] || die "runc changed while it was staged"

# Everything inside runs from this one script; the host passes values only.
# shellcheck disable=SC2016 # expanded inside the container
inner='
set -euo pipefail
sysroot="$(rustc --print sysroot)"
# Root-owned files stay in the container, never in the shared scratch.
for entry in $MEMBERS; do
  tar -xJf "${entry%%=*}" -C /tmp "${entry#*=}"
  cp -R "/tmp/${entry#*=}" "$sysroot/lib/rustlib/"
done
mkdir /opt/protoc
unzip -q "$PROTOC_ZIP" -d /opt/protoc
groupadd -g "$BUILD_GID" builder 2>/dev/null || true
# A CI job runs as root, which the image already has.
getent passwd "$BUILD_UID" >/dev/null || useradd -u "$BUILD_UID" -g "$BUILD_GID" -M -d /nonexistent builder
mkdir "$SCRATCH/cargo-home" "$SCRATCH/home"
chown "$BUILD_UID:$BUILD_GID" "$SCRATCH/cargo-home" "$SCRATCH/home"
exec setpriv --reuid="$BUILD_UID" --regid="$BUILD_GID" --init-groups \
  env HOME="$SCRATCH/home" CARGO_HOME="$SCRATCH/cargo-home" PATH="/opt/protoc/bin:$sysroot/bin:/usr/bin:/bin" \
  "$REPO/scripts/ci/verify/build-local-vmm-initramfs.sh" --verify-root --target "$TARGET" \
  --busybox "$BUSYBOX" --busybox-sha256 "$BUSYBOX_SHA256" \
  --runc "$RUNC" --runc-sha256 "$RUNC_SHA256" --output "$OUTPUT"
'
# shellcheck source=scripts/ci/release/runtime-container.sh
. "$repo/scripts/ci/release/runtime-container.sh"
runtime_container_mounts "$job_container" "$repo" "$busybox" "${rust_std[@]}" "$protoc_zip" -- "$parent" ||
  die "the build's paths cannot be mounted"
started="$(date +%s)"
# The job's bounded cargo network settings (cli-release.yaml), when set,
# reach the probe build's git dependency fetches too (#2691), and a caller's
# CARGO_BUILD_JOBS bounds its parallelism.
docker run --rm --init "${RUNTIME_MOUNTS[@]}" \
  -e BUILD_UID="$uid" -e BUILD_GID="$gid" -e REPO="$repo" -e SCRATCH="$scratch" -e TARGET="$target" \
  -e MEMBERS="$members" -e PROTOC_ZIP="$protoc_zip" \
  -e BUSYBOX="$busybox" -e BUSYBOX_SHA256="$busybox_sha256" -e RUNC="$scratch/runc" -e RUNC_SHA256="$runc_sha256" \
  -e OUTPUT="$output" \
  -e CARGO_HTTP_TIMEOUT -e CARGO_NET_RETRY -e CARGO_BUILD_JOBS \
  "$image" bash -c "$inner" ||
  die "guest root build failed"
[ -f "$output" ] || die "the build left no guest root"
echo "build-runtime-guest-root: built in $(( $(date +%s) - started ))s sha256=$(sha256sum "$output" | cut -c1-64)"
