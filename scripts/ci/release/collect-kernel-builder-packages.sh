#!/usr/bin/env bash
# usage: collect-kernel-builder-packages.sh OUT [--job-container CONTAINER]
#
# The refresh half of the kernel builder's package mirror (#5619): installs
# exactly what build-runtime-kernel.sh installs, in the same pinned container,
# from the pinned archive.archlinux.org snapshot, and writes every file pacman
# read into OUT as a repository tree (OUT/<repo>/os/x86_64/<file>): the two
# sync databases and each package it downloaded. kernel_builder_mirror.py
# record then stores them by digest and writes the lock.
#
# pacman verifies each package's signature, from the sync database, against
# the snapshot's keyring as it installs it; the run refuses unless pacman.conf
# requires package signatures, so no unsigned or wrongly signed package is
# ever collected. This is the one step that reads the archive, and it runs
# only in cli-release.yaml's dispatched kernel builder mirror job.
set -euo pipefail

die() {
  echo "collect-kernel-builder-packages: $*" >&2
  exit 1
}

job_container=""
case "$#|${2:-}" in
  1\|) ;;
  3\|--job-container) job_container="$3" ;;
  *) die "usage: collect-kernel-builder-packages.sh OUT [--job-container CONTAINER]" ;;
esac
out="$1"
case "$out" in /*) ;; *) die "OUT must be an absolute path" ;; esac
[ ! -e "$out" ] || die "OUT already exists"
parent="$(dirname "$out")"
[ -d "$parent" ] || die "OUT's parent does not exist"

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
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

mkdir -m 0755 "$out"
# shellcheck disable=SC2016 # expanded inside the container
inner='
set -euo pipefail
grep -Eq "^SigLevel *= *Required" /etc/pacman.conf ||
  { echo "collect-kernel-builder-packages: pacman.conf does not require package signatures" >&2; exit 1; }
printf "Server = https://archive.archlinux.org/repos/%s/\$repo/os/\$arch\n" "$SNAPSHOT" > /etc/pacman.d/mirrorlist
cache=/collect-cache
mkdir -p "$cache"
fetch() {
  pacman "$@" --cachedir "$cache" --noconfirm --noprogressbar >/dev/null
}
pacman-key --init >/dev/null 2>&1
fetch -Syuu
# shellcheck disable=SC2086 # word lists
fetch -S --needed $TOOLS
for pinned in $PACKAGES; do
  fetch -S --needed "${pinned%%=*}"
  installed="$(pacman -Q "${pinned%%=*}" | cut -d" " -f2)"
  [ "$installed" = "${pinned#*=}" ] || { echo "collect-kernel-builder-packages: ${pinned%%=*} is $installed, pinned ${pinned#*=}" >&2; exit 1; }
done
for db in core extra; do
  mkdir -p "$OUT/$db/os/x86_64"
  cp "/var/lib/pacman/sync/$db.db" "$OUT/$db/os/x86_64/$db.db"
done
# Each downloaded package under the repository it came from.
count=0
while read -r where; do
  file="${where#*/}"
  [ -f "$cache/$file" ] || continue
  cp "$cache/$file" "$OUT/${where%%/*}/os/x86_64/$file"
  count=$((count + 1))
done < <(pacman -Sp --print-format "%r/%f" $(pacman -Qq) 2>/dev/null)
[ "$(find "$cache" -maxdepth 1 -name "*.pkg.tar.*" ! -name "*.sig" | wc -l)" = "$count" ] ||
  { echo "collect-kernel-builder-packages: a downloaded package is in neither core nor extra" >&2; exit 1; }
chown -R "$OWNER" "$OUT"
echo "collect-kernel-builder-packages: $count packages and 2 sync databases for snapshot $SNAPSHOT"
'
# A CI job's container: mount the job's volume that holds OUT, as the kernel
# build does (runtime-container.sh).
# shellcheck source=scripts/ci/release/runtime-container.sh
. "$repo/scripts/ci/release/runtime-container.sh"
runtime_container_mounts "$job_container" -- "$out" || die "OUT cannot be mounted"
# Inside the workstation's CPU slice when run there, as the runtime builders do.
# shellcheck source=scripts/dev/cpu-slice.sh
. "$repo/scripts/dev/cpu-slice.sh"
cpu_slice_docker_args
docker run --rm --init ${CPU_SLICE_DOCKER_ARGS[@]+"${CPU_SLICE_DOCKER_ARGS[@]}"} "${RUNTIME_MOUNTS[@]}" \
  -e SNAPSHOT="$snapshot" -e TOOLS="$tools" -e PACKAGES="$packages" -e OUT="$out" \
  -e OWNER="$(id -u):$(id -g)" \
  "$image" bash -c "$inner" ||
  die "collecting the kernel builder's packages failed"
