#!/usr/bin/env bash
# Build and name a `standard` workspace disk (#5602).
set -euo pipefail

usage() {
  cat <<'USAGE' >&2
usage: workspace-disk.sh build --smoke PATH --artifact-root DIR --artifact-lock FILE \
           --image REF@sha256:DIGEST --output DIR [--scratch-parent DIR]
       workspace-disk.sh line --disk REF@sha256:DIGEST --image REF@sha256:DIGEST --dir DIR

build  Pulls the workspace image anonymously and builds its image disk in a
       VM, with codewire-local-vmm-smoke image-disk on a host with /dev/kvm,
       over the pod-runtime image's own runtime (ARTIFACT_ROOT is its
       runtime/artifacts, FILE its runtime/artifacts.lock, from
       pod-runtime-context.py). It then shrinks the disk to its content and
       writes the new directory DIR with exactly image.raw, record.json,
       config.json and, when REF names an image index, index.json:
       images/workspace-disk/Dockerfile's context. The VM's state goes under
       a new directory of --scratch-parent (default TMPDIR), removed at the
       end; the VM's sockets live there, so the parent's path must be short
       (at most 28 bytes). Needs e2fsck, resize2fs and dumpe2fs.
line   Prints the SANDBOX_STANDARD_IMAGE_DISK value (docs/CONFIGURATION.md)
       for DIR once it is pushed as DISK: the disk image by digest, its image
       disk id, its build id and the workspace image it was built from. IMAGE
       must be the reference DIR was built from: its digest is the record's
       manifest or the index DIR holds.
USAGE
}

die() {
  printf 'workspace-disk: ERROR: %s\n' "$*" >&2
  exit 1
}

# REF@sha256:<64 lowercase hex>, and nothing after it.
pinned() {
  [[ $1 =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]
}

absolute() {
  [[ $1 == /* ]] || die "$2 must be an absolute path: $1"
}

build() {
  local smoke='' artifact_root='' artifact_lock='' image='' output='' parent="${TMPDIR:-/tmp}"
  while (($#)); do
    (($# >= 2)) || { usage; exit 2; }
    case $1 in
      --smoke) smoke=$2 ;;
      --artifact-root) artifact_root=$2 ;;
      --artifact-lock) artifact_lock=$2 ;;
      --image) image=$2 ;;
      --output) output=$2 ;;
      --scratch-parent) parent=$2 ;;
      *) usage; exit 2 ;;
    esac
    shift 2
  done
  [[ -n $smoke && -n $artifact_root && -n $artifact_lock && -n $image && -n $output ]] || { usage; exit 2; }
  pinned "$image" || die "--image must be pinned by digest: $image"
  for path in "$smoke" "$artifact_root" "$artifact_lock" "$output" "$parent"; do
    absolute "$path" "every path"
  done
  [[ -x $smoke ]] || die "--smoke is not an executable: $smoke"
  [[ ! -e $output && ! -L $output ]] || die "$output already exists; build into a new directory"
  for tool in e2fsck resize2fs dumpe2fs setpriv python3; do
    command -v "$tool" >/dev/null 2>&1 || die "missing required command: $tool"
  done

  # The longest socket the build makes is under its scratch directory; Linux
  # bounds a socket's path at 108 bytes, its terminating NUL included.
  local longest="$parent/wd.XXXXXX/state/image-builds/00000000000000000000000000000000/vsock/vsock.sock"
  ((${#longest} < 108)) || die "--scratch-parent is too long for the VM's sockets: keep it to $((107 - ${#longest} + ${#parent})) bytes"
  local scratch
  scratch=$(mktemp -d "$parent/wd.XXXXXX")
  # shellcheck disable=SC2064 # the path is fixed now
  trap "rm -rf -- '$scratch'" EXIT
  mkdir -m 0700 "$scratch/state" "$scratch/run" "$scratch/home" "$scratch/publish"
  local vm_id
  vm_id=$(tr -d '\n' </proc/sys/kernel/random/uuid)
  # The smoke runs without privileges or the caller's environment.
  timeout --foreground --signal=TERM --kill-after=10s 3000s \
    setpriv --no-new-privs --inh-caps=-all --ambient-caps=-all -- \
    env -i PATH=/usr/bin:/bin HOME="$scratch/home" TMPDIR="$scratch/run" LC_ALL=C \
    "$smoke" image-disk --artifact-root "$artifact_root" --artifact-lock "$artifact_lock" \
      --state-root "$scratch/state" --vm-id "$vm_id" --image "$image" --publish "$scratch/publish" \
      --cpus 4 --memory-mib 4096

  local publish=$scratch/publish id disk
  id=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["image_disk_id"])' "$publish/record.json")
  [[ $id =~ ^[0-9a-f]{64}$ ]] || die "the smoke's record names no image disk id"
  disk=$scratch/state/image-disks/disks/$id/image.raw
  [[ -f $disk ]] || die "the smoke left no disk for $id"
  # The store's disk is a fixed-size sparse file; the published one is its
  # filesystem shrunk to its content, a whole number of 4 KiB blocks.
  cp --sparse=always "$disk" "$publish/image.raw"
  # The store's disk is read-only, and so is the copy cp makes of it.
  chmod 0600 "$publish/image.raw"
  # e2fsck exits 1 when it only tidied the filesystem.
  local status=0
  e2fsck -fy "$publish/image.raw" >"$scratch/e2fsck.log" 2>&1 || status=$?
  ((status <= 1)) || { cat "$scratch/e2fsck.log" >&2; die "e2fsck exited $status on the disk"; }
  resize2fs -M "$publish/image.raw" >"$scratch/resize2fs.log" 2>&1 ||
    { cat "$scratch/resize2fs.log" >&2; die "resize2fs could not shrink the disk"; }
  local blocks block_size bytes
  blocks=$(dumpe2fs -h "$publish/image.raw" 2>/dev/null | awk -F: '/^Block count/ {gsub(/ /, "", $2); print $2}')
  block_size=$(dumpe2fs -h "$publish/image.raw" 2>/dev/null | awk -F: '/^Block size/ {gsub(/ /, "", $2); print $2}')
  [[ $blocks =~ ^[0-9]+$ && $block_size == 4096 ]] || die "the shrunk disk is not a 4 KiB-block ext4 filesystem"
  bytes=$((blocks * block_size))
  truncate -s "$bytes" "$publish/image.raw"
  python3 - "$publish/record.json" "$bytes" <<'PY'
import json, sys
path, size = sys.argv[1], int(sys.argv[2])
with open(path) as handle:
    record = json.load(handle)
record["disk_bytes"] = size
with open(path, "w") as handle:
    json.dump(record, handle, separators=(",", ":"))
PY
  chmod 0644 "$publish"/*
  mkdir -m 0755 "$output"
  cp --sparse=always -p "$publish"/* "$output/"
  printf 'workspace-disk: built %s: image disk %s, %s bytes\n' "$output" "$id" "$bytes"
}

line() {
  local disk='' image='' dir=''
  while (($#)); do
    (($# >= 2)) || { usage; exit 2; }
    case $1 in
      --disk) disk=$2 ;;
      --image) image=$2 ;;
      --dir) dir=$2 ;;
      *) usage; exit 2 ;;
    esac
    shift 2
  done
  [[ -n $disk && -n $image && -n $dir ]] || { usage; exit 2; }
  pinned "$disk" || die "--disk must be pinned by digest: $disk"
  pinned "$image" || die "--image must be pinned by digest: $image"
  python3 - "$disk" "$image" "$dir" <<'PY'
import hashlib, json, os, sys
disk, image, directory = sys.argv[1:]
names = sorted(os.listdir(directory))
if names not in (["config.json", "image.raw", "record.json"], ["config.json", "image.raw", "index.json", "record.json"]):
    sys.exit("workspace-disk: ERROR: %s does not hold exactly a built disk's files" % directory)
with open(os.path.join(directory, "record.json")) as handle:
    record = json.load(handle)
digest = image.rsplit("@sha256:", 1)[1]
paired = record["manifest_sha256"] == digest
if not paired and "index.json" in names:
    with open(os.path.join(directory, "index.json"), "rb") as handle:
        paired = hashlib.sha256(handle.read()).hexdigest() == digest
if not paired:
    sys.exit("workspace-disk: ERROR: %s was not built from %s" % (directory, image))
print(" ".join((disk, record["image_disk_id"], record["build_id"], image)))
PY
}

case ${1:-} in
  build) shift; build "$@" ;;
  line) shift; line "$@" ;;
  *) usage; exit 2 ;;
esac
