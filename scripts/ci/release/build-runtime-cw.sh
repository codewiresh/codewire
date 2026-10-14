#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: build-runtime-cw.sh --target TARGET --version VERSION --rust-std FILE --rust-std FILE
                           --protoc-zip FILE --zig FILE --output DIR [--jobs N]
                           [--job-container CONTAINER]

Builds a sealed cw runtime, DIR/cw-runtime.lock.json and DIR/runtime.pack, for
the local VM runtime of one host architecture (#2733): TARGET is
x86_64-unknown-linux-musl (Linux hosts) or aarch64-unknown-linux-musl (Apple
silicon Macs). scripts/dev/build-native-managed-agent.py builds the static cw
inside the pinned Rust 1.93.0 image from
scripts/ci/release/local-runtime-sources.json, cross-compiled and linked by
the pinned zig and cargo-zigbuild as release delivery builds its Linux cws;
then scripts/dev/cw-runtime-image.py builds its image and packs it. No host
toolchain is changed: the container installs both musl standard libraries
from their pinned tarballs, offline, protoc from its pinned zip and zig from
its pinned tarball, and installs exactly the pinned cargo-zigbuild with
`cargo install --locked`.

The cw is built from this checkout's HEAD with the explicit VERSION and no
CODEWIRE_LOCAL_RUNTIME: a blob the runtime document pins must never hold the
cw that embeds that document (crates/codewire-cli/build.rs).
scripts/dev/linux-local-runtime.py check-cw-runtime then checks the pack: a
static TARGET ELF whose build record names TARGET and HEAD, embedding no
local runtime document.

The build runs as the caller's uid with this checkout (and its Git directory)
and the inputs mounted read-only; --job-container is as for
build-runtime-kernel.sh. DIR must not exist; its parent must, and must not be
a source input of this checkout (git-ignored when inside it).
EOF
}

die() {
  echo "build-runtime-cw: $*" >&2
  exit 1
}

target="" version="" protoc_zip="" zig="" output="" jobs=4 job_container=""
rust_std=()
while [ $# -gt 0 ]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --rust-std) rust_std+=("${2:-}"); shift 2 ;;
    --protoc-zip) protoc_zip="${2:-}"; shift 2 ;;
    --zig) zig="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --jobs) jobs="${2:-}"; shift 2 ;;
    --job-container) job_container="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$target" in
  aarch64-unknown-linux-musl|x86_64-unknown-linux-musl) ;;
  *) die "--target must be aarch64-unknown-linux-musl or x86_64-unknown-linux-musl" ;;
esac
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version must be vMAJOR.MINOR.PATCH"
case "$jobs" in [1-8]) ;; *) die "--jobs must be 1 to 8" ;; esac
absolute_file() {
  case "$2" in /*) ;; *) die "--$1 must be an absolute path" ;; esac
  [ "$1" = output ] || { [ -f "$2" ] && [ ! -L "$2" ]; } || die "--$1 is not a regular file"
}
for name in protoc_zip zig output; do
  absolute_file "${name//_/-}" "${!name}"
done
for file in ${rust_std[@]+"${rust_std[@]}"}; do
  absolute_file rust-std "$file"
done
[ ! -e "$output" ] || die "output already exists"
parent="$(dirname "$output")"
[ -d "$parent" ] || die "output parent does not exist"
parent="$(cd "$parent" && pwd -P)"
output="$parent/$(basename "$output")"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
git_common="$(cd "$repo" && cd "$(git rev-parse --git-common-dir)" && pwd -P)"
revision="$(git -C "$repo" rev-parse HEAD)"
# The source digest covers untracked files of its patterns, so the build's
# scratch (Cargo sources, target directory) must not count as source.
case "$parent/" in
  "$repo"/*) git -C "$repo" check-ignore -q "$parent/" ||
               die "the output parent is inside the checkout and not git-ignored, so the build would change its source" ;;
esac
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
for each in $targets; do
  found=""
  for file in ${rust_std[@]+"${rust_std[@]}"}; do
    [ "$(sha256sum "$file" | cut -c1-64)" = "$(pin guest_root_builder rust_std "$each" sha256)" ] && found="$file"
  done
  [ -n "$found" ] || die "no --rust-std is the pinned $each tarball"
  members="$members $found=rust-std-1.93.0-$each/rust-std-$each/lib/rustlib/$each"
done
[ "${#rust_std[@]}" = "$(wc -w <<<"$targets")" ] || die "give exactly one --rust-std per pinned target"
[ "$(sha256sum "$protoc_zip" | cut -c1-64)" = "$(pin guest_root_builder protoc sha256)" ] ||
  die "the protoc zip differs from its pin"
[ "$(sha256sum "$zig" | cut -c1-64)" = "$(pin cw_runtime_builder zig sha256)" ] ||
  die "the zig tarball differs from its pin"
image="$(pin guest_root_builder image)"
zigbuild="$(pin cw_runtime_builder cargo_zigbuild)"
uid="$(id -u)" gid="$(id -g)"

# The build's scratch (Cargo home, tools, target directory, image) sits beside
# the output, on the job's workspace in CI.
scratch="$(mktemp -d "$parent/.cw-runtime.XXXXXX")"
trap 'chmod -R u+w "$scratch" 2>/dev/null || true; rm -rf "$scratch"' EXIT

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
mkdir /opt/protoc /opt/zig
unzip -q "$PROTOC_ZIP" -d /opt/protoc
tar -xJf "$ZIG" -C /opt/zig --strip-components=1
groupadd -g "$BUILD_GID" builder 2>/dev/null || true
# A CI job runs as root, which the image already has.
getent passwd "$BUILD_UID" >/dev/null || useradd -u "$BUILD_UID" -g "$BUILD_GID" -M -d /nonexistent builder
mkdir "$SCRATCH/cargo-home" "$SCRATCH/home" "$SCRATCH/tools"
chown "$BUILD_UID:$BUILD_GID" "$SCRATCH/cargo-home" "$SCRATCH/home" "$SCRATCH/tools"
exec setpriv --reuid="$BUILD_UID" --regid="$BUILD_GID" --init-groups \
  env HOME="$SCRATCH/home" CARGO_HOME="$SCRATCH/cargo-home" \
  PATH="/opt/zig:$SCRATCH/tools/bin:/opt/protoc/bin:$sysroot/bin:/usr/bin:/bin" SYSROOT="$sysroot" \
  bash -c "
set -euo pipefail
cargo install --locked --quiet --jobs \"\$JOBS\" cargo-zigbuild --version \"\$ZIGBUILD\" --root \"\$SCRATCH/tools\"
cargo fetch --locked --manifest-path \"\$REPO/Cargo.toml\"
exec python3 \"\$REPO/scripts/dev/build-native-managed-agent.py\" --target \"\$TARGET\" --version \"\$VERSION\" \
  --rust-tools \"\$SYSROOT/bin\" --protoc /opt/protoc/bin/protoc --output \"\$SCRATCH/build\" \
  --target-dir \"\$SCRATCH/target\" --cargo-cache \"\$SCRATCH/cargo-home\" --jobs \"\$JOBS\"
"
'
# shellcheck source=scripts/ci/release/runtime-container.sh
. "$repo/scripts/ci/release/runtime-container.sh"
runtime_container_mounts "$job_container" "$repo" "$git_common" "${rust_std[@]}" "$protoc_zip" "$zig" -- "$parent" ||
  die "the build's paths cannot be mounted"
started="$(date +%s)"
# The job's bounded cargo network settings (cli-release.yaml), when set,
# reach the dependency fetches too (#2691).
docker run --rm --init "${RUNTIME_MOUNTS[@]}" \
  -e BUILD_UID="$uid" -e BUILD_GID="$gid" -e REPO="$repo" -e SCRATCH="$scratch" \
  -e MEMBERS="$members" -e PROTOC_ZIP="$protoc_zip" -e ZIG="$zig" -e ZIGBUILD="$zigbuild" \
  -e TARGET="$target" -e VERSION="$version" -e JOBS="$jobs" \
  -e CARGO_HTTP_TIMEOUT -e CARGO_NET_RETRY \
  "$image" bash -c "$inner" || {
  # The scratch goes with this script; keep the compiler's last words.
  tail -n 60 "$scratch/build/build.log" >&2 2>/dev/null || true
  die "the $target cw build failed"
}

# The image and its pack, from exactly the admitted bytes; then the release
# checks of the result.
python3 "$repo/scripts/dev/cw-runtime-image.py" build --artifact "$scratch/build/managed-agent-cw.json" \
  --output "$scratch/image" >/dev/null || die "the cw image could not be built"
index="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["index_sha256"])' "$scratch/image/image.json")"
python3 "$repo/scripts/dev/cw-runtime-image.py" pack --image "$scratch/image/cw.oci.tar" --index-sha256 "$index" \
  --output "$scratch/runtime" >/dev/null || die "the cw runtime could not be packed"
python3 "$repo/scripts/dev/linux-local-runtime.py" check-cw-runtime --dir "$scratch/runtime" --target "$target" \
  --source-revision "$revision" || die "the cw runtime does not pass its release checks"
mkdir -m 0700 "$output"
cp "$scratch/runtime/cw-runtime.lock.json" "$scratch/runtime/runtime.pack" "$output/"
echo "build-runtime-cw: $target built in $(( $(date +%s) - started ))s" \
  "pack sha256=$(sha256sum "$output/runtime.pack" | cut -c1-64)"
