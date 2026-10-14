#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: build-runtime-kernel.sh --arch arm64|x86_64 --source LINUX_GIT_DIR --bc BUSYBOX --output DIR
                               [--jobs N] [--job-container CONTAINER]

Builds one of the local VM runtime's guest kernels with
scripts/ci/verify/build-linux-vmm-kernel.py --arch ARCH inside the pinned Arch
Linux container from scripts/ci/release/local-runtime-sources.json: the arm64
Image for macOS hosts (#2539), cross-compiled, or the x86_64 bzImage for Linux
hosts (#2733). pacman reads the pinned archive.archlinux.org snapshot and
installs exactly the toolchain packages pinned there, native and cross; the
recipe checks the versions it requires again.

The build runs as the caller's uid. The kernel source and this checkout are
mounted read-only at their own paths. A CI job runs in a container beside its
Docker daemon, which resolves bind sources in its own namespace, so there
--job-container names the job's container: for each path the build mounts the
job's volume or bind that holds it, at its own path, and nothing else (never
the job's Docker socket). DIR must not exist; its parent must be owned by the
caller. On success DIR holds the recipe's kernel image and build.json,
plus linux-source.tar.xz: the exact source the recipe archived, compressed
deterministically, published as the kernel's GPL source.
EOF
}

die() {
  echo "build-runtime-kernel: $*" >&2
  exit 1
}

arch="" source_dir="" bc="" output="" jobs=4 job_container=""
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) arch="${2:-}"; shift 2 ;;
    --source) source_dir="${2:-}"; shift 2 ;;
    --bc) bc="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --jobs) jobs="${2:-}"; shift 2 ;;
    --job-container) job_container="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
for name in source_dir bc output; do
  case "${!name}" in
    /*) ;;
    *) die "--${name%_dir} must be an absolute path" ;;
  esac
done
case "$arch" in arm64|x86_64) ;; *) die "--arch must be arm64 or x86_64" ;; esac
case "$jobs" in [1-8]) ;; *) die "--jobs must be 1 to 8" ;; esac
[ -d "$source_dir" ] || die "kernel source is not a directory"
[ -f "$bc" ] || die "bc is not a file"
[ ! -e "$output" ] || die "output already exists"
parent="$(dirname "$output")"
[ -d "$parent" ] || die "output parent does not exist"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
git_common="$(cd "$repo" && cd "$(git rev-parse --git-common-dir)" && pwd -P)"
pins="$repo/scripts/ci/release/local-runtime-sources.json"
read_pin() {
  python3 -c 'import json, sys
pins = json.load(open(sys.argv[1]))["kernel_builder"]
if sys.argv[2] == "packages":
    print(" ".join(f"{name}={version}" for name, version in sorted(pins["packages"].items())))
elif sys.argv[2] == "tools":
    print(" ".join(pins["tools"]))
else:
    print(pins[sys.argv[2]])' "$pins" "$1"
}
image="$(read_pin image)"
snapshot="$(read_pin snapshot)"
packages="$(read_pin packages)"
tools="$(read_pin tools)"
uid="$(id -u)" gid="$(id -g)"
name="$(basename "$output")"

# Everything inside runs from this one script; the host passes values only.
# shellcheck disable=SC2016 # expanded inside the container
inner='
set -euo pipefail
printf "Server = https://archive.archlinux.org/repos/%s/\$repo/os/\$arch\n" "$SNAPSHOT" > /etc/pacman.d/mirrorlist
# The keyring package populates the local keyring on install; give it one.
pacman-key --init >/dev/null 2>&1
pacman -Syuu --noconfirm --noprogressbar >/dev/null
# shellcheck disable=SC2086 # word lists
pacman -S --noconfirm --needed --noprogressbar $TOOLS >/dev/null
for pinned in $PACKAGES; do
  pacman -S --noconfirm --needed --noprogressbar "${pinned%%=*}" >/dev/null
  installed="$(pacman -Q "${pinned%%=*}" | cut -d" " -f2)"
  [ "$installed" = "${pinned#*=}" ] || { echo "build-runtime-kernel: ${pinned%%=*} is $installed, pinned ${pinned#*=}" >&2; exit 1; }
done
groupadd -g "$BUILD_GID" builder 2>/dev/null || true
# A CI job runs as root, which the image already has.
getent passwd "$BUILD_UID" >/dev/null || useradd -u "$BUILD_UID" -g "$BUILD_GID" -M -d /nonexistent builder
exec setpriv --reuid="$BUILD_UID" --regid="$BUILD_GID" --init-groups \
  python3 "$REPO/scripts/ci/verify/build-linux-vmm-kernel.py" --arch "$ARCH" \
  --source "$SOURCE" --bc "$BC" --output "$OUTPUT" --jobs "$JOBS"
'
# shellcheck source=scripts/ci/release/runtime-container.sh
. "$repo/scripts/ci/release/runtime-container.sh"
runtime_container_mounts "$job_container" "$repo" "$git_common" "$source_dir" "$bc" -- "$parent" ||
  die "the build's paths cannot be mounted"
started="$(date +%s)"
docker run --rm --init "${RUNTIME_MOUNTS[@]}" \
  -e SNAPSHOT="$snapshot" -e TOOLS="$tools" -e PACKAGES="$packages" \
  -e BUILD_UID="$uid" -e BUILD_GID="$gid" -e REPO="$repo" -e SOURCE="$source_dir" -e ARCH="$arch" \
  -e BC="$bc" -e OUTPUT="$output" -e JOBS="$jobs" \
  "$image" bash -c "$inner" ||
  die "kernel build failed; see $output/*.log"

# The recipe's exact source archive, compressed deterministically.
[ -f "$output/source.tar" ] || die "the kernel build left no source archive"
xz --threads=1 --format=xz --check=crc64 -6 --stdout "$output/source.tar" > "$output/linux-source.tar.xz"
echo "build-runtime-kernel: $name built in $(( $(date +%s) - started ))s"
