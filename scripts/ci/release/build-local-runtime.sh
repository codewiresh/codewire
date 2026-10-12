#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: build-local-runtime.sh linux --output DIR
       build-local-runtime.sh macos --linux DIR --source-sha SHA --output DIR

Builds the macOS local VM runtime that a release's arm64 cw embeds (#2539),
from this checkout. Run it from the release source; its scripts are that
source's own.

linux   x86_64 Linux with Docker and the pinned Rust 1.93.0. Builds the arm64
        guest root, takes the arm64 kernel from the parts cache or builds it in
        the pinned container, and fetches the Linux-side third-party sources.
        DIR gets initramfs.cpio, kernel/, sources/ and built/ (the cache
        records of parts built in this run).
macos   An Apple silicon Mac. Takes e2fsprogs and git from the parts cache or
        builds them, fetches the Mac-side sources, and packs DIR/runtime from
        the Linux job's DIR with the VZ helper built here. DIR/built gets this
        job's and the Linux job's cache records.

Only a release's publishing job writes cache records; nothing here holds a
credential. Set LOCAL_RUNTIME_NO_BUILD=1 to refuse a cache miss instead of
building (the per-push dry run): it then exits 4. LOCAL_RUNTIME_KERNEL_SOURCE
names an existing Linux clone to build the kernel from instead of cloning.
In a CI job container, LOCAL_RUNTIME_JOB_CONTAINER names that container so the
kernel build can reach its files (build-runtime-kernel.sh --job-container);
TMPDIR and DIR must then be on its workspace.
EOF
}

die() {
  echo "build-local-runtime: $*" >&2
  exit 1
}

log() {
  echo "build-local-runtime: $*"
}

mode="${1:-}"
[ -n "$mode" ] || { usage >&2; exit 2; }
shift
linux_dir="" source_sha="" output=""
while [ $# -gt 0 ]; do
  case "$1" in
    --linux) linux_dir="${2:-}"; shift 2 ;;
    --source-sha) source_sha="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$mode" in
  linux) [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die "the linux side runs on x86_64 Linux" ;;
  macos) [ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "the macos side runs on an Apple silicon Mac"
         case "$linux_dir" in /*) [ -d "$linux_dir" ] || die "--linux is not a directory" ;; *) die "--linux must be absolute" ;; esac
         [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "--source-sha must be the release commit" ;;
  *) die "mode must be linux or macos" ;;
esac
case "$output" in /*) ;; *) die "--output must be an absolute path" ;; esac
[ ! -e "$output" ] || die "output already exists"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
release_dir="$root/scripts/ci/release"
pins="$release_dir/local-runtime-sources.json"
parts="$release_dir/local_runtime_parts.py"
pin() {
  python3 -c 'import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2:]:
    value = value[key]
print(value)' "$pins" "$@"
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi
}
fetch() {
  local url="$1" digest="$2" target="$3"
  curl -fsSL --retry 3 --max-time 900 -o "$target" "$url" || die "download failed: $url"
  [ "$(sha256_of "$target")" = "$digest" ] || die "$url differs from its pinned SHA-256"
}
# A cached part, or a build the caller asks for; returns 0 when cached.
cached() {
  local part="$1" recipe="$2" dir="$3" status=0
  python3 "$parts" fetch --part "$part" --recipe "$recipe" --dir "$dir" || status=$?
  case "$status" in
    0) return 0 ;;
    3) if [ -n "${LOCAL_RUNTIME_NO_BUILD:-}" ]; then
         echo "build-local-runtime: $part is not cached and this run builds no slow parts" >&2
         exit 4
       fi
       return 1 ;;
    *) die "the $part cache could not be read" ;;
  esac
}
record() {
  local part="$1" recipe="$2" dir="$3"
  python3 "$parts" record --part "$part" --recipe "$recipe" --dir "$dir" > "$output/built/$recipe.json"
}

mkdir -m 0700 "$output" "$output/built"
work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-local-runtime.XXXXXX")"
chmod 0700 "$work"
trap 'chmod -R u+w "$work" 2>/dev/null || true; rm -rf "$work"' EXIT

linux() {
  # The guest root: the sealed probe built twice for arm64, with the pinned
  # Alpine BusyBox and official runc.
  log "building the arm64 guest root"
  rustup target add aarch64-unknown-linux-musl >/dev/null
  fetch "$(pin initramfs_inputs busybox url)" "$(pin initramfs_inputs busybox sha256)" "$work/busybox.apk"
  mkdir "$work/busybox"
  tar -xzf "$work/busybox.apk" -C "$work/busybox" "$(pin initramfs_inputs busybox member)" 2>/dev/null ||
    die "the BusyBox package holds no $(pin initramfs_inputs busybox member)"
  fetch "$(pin initramfs_inputs runc url)" "$(pin initramfs_inputs runc sha256)" "$work/runc.arm64"
  "$root/scripts/ci/verify/build-local-vmm-initramfs.sh" --verify-root --target aarch64-unknown-linux-musl \
    --busybox "$work/busybox/$(pin initramfs_inputs busybox member)" \
    --busybox-sha256 "$(pin initramfs_inputs busybox member_sha256)" \
    --runc "$work/runc.arm64" --runc-sha256 "$(pin initramfs_inputs runc sha256)" \
    --output "$output/initramfs.cpio"

  local recipe
  recipe="$(python3 "$parts" recipe --part kernel-arm64)"
  if cached kernel-arm64 "$recipe" "$output/kernel"; then
    log "kernel-arm64 cached (recipe $recipe)"
  else
    log "kernel-arm64 not cached (recipe $recipe); building it"
    local tag commit
    tag="v$(pin sources linux version)"
    commit="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["source_commit"])' \
      "$root/scripts/ci/verify/linux-vmm-kernel/provenance.json")"
    local linux_source="$work/linux"
    if [ -n "${LOCAL_RUNTIME_KERNEL_SOURCE:-}" ]; then
      # A developer's existing clone; the recipe checks its commit and tree.
      linux_source="$LOCAL_RUNTIME_KERNEL_SOURCE"
    else
      git clone -q --depth 1 --branch "$tag" \
        https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$linux_source"
      [ "$(git -C "$linux_source" rev-parse HEAD)" = "$commit" ] || die "$tag is not the pinned kernel commit"
    fi
    local container
    container="$(docker create "$(pin kernel_bc image)")"
    docker cp "$container:$(pin kernel_bc path)" "$work/bc" >/dev/null
    docker rm "$container" >/dev/null
    [ "$(sha256_of "$work/bc")" = "$(pin kernel_bc sha256)" ] || die "bc differs from its pin"
    mkdir -m 0700 "$work/kernel-parent"
    local shared=()
    [ -z "${LOCAL_RUNTIME_JOB_CONTAINER:-}" ] || shared=(--job-container "$LOCAL_RUNTIME_JOB_CONTAINER")
    "$release_dir/build-runtime-kernel.sh" --source "$linux_source" --bc "$work/bc" \
      --output "$work/kernel-parent/kernel" --jobs "${LOCAL_RUNTIME_JOBS:-4}" ${shared[@]+"${shared[@]}"}
    mkdir -m 0700 "$output/kernel"
    cp "$work/kernel-parent/kernel/Image-$(pin sources linux version)-codewire2" \
      "$work/kernel-parent/kernel/linux-source.tar.xz" "$output/kernel/"
    record kernel-arm64 "$recipe" "$output/kernel"
  fi
  python3 "$release_dir/local_runtime_sources.py" fetch --side linux --kernel "$output/kernel" \
    --output "$output/sources"
}

macos() {
  python3 -c 'import json, platform, subprocess, sys
json.dump({"macos": platform.mac_ver()[0],
           "sdk": subprocess.check_output(["xcrun", "--show-sdk-version"], text=True).strip(),
           "clang": subprocess.check_output(["xcrun", "clang", "--version"], text=True).splitlines()[0]},
          open(sys.argv[1], "w"))' "$work/host.json"
  local part tool name recipe archive
  for part in e2fsprogs-macos git-macos; do
    case "$part" in
      e2fsprogs-macos) tool=macos-ext4-tool.py name=e2fsprogs ;;
      git-macos) tool=macos-git-tool.py name=git ;;
    esac
    recipe="$(python3 "$parts" recipe --part "$part" --host-facts "$work/host.json")"
    if cached "$part" "$recipe" "$output/$part"; then
      log "$part cached (recipe $recipe)"
      continue
    fi
    log "$part not cached (recipe $recipe); building it"
    archive="$work/$(basename "$(pin sources "$name" url)")"
    fetch "$(pin sources "$name" url)" "$(pin sources "$name" sha256)" "$archive"
    mkdir -m 0700 "$work/$part-parent"
    python3 "$root/scripts/dev/$tool" --source-archive "$archive" --output "$work/$part-parent/out"
    mkdir -m 0700 "$output/$part"
    python3 -c 'import shutil, sys
sys.path.insert(0, sys.argv[1])
import local_runtime_parts as parts
for name in parts.PARTS[sys.argv[2]]["outputs"]:
    shutil.copy2(f"{sys.argv[3]}/{name}", f"{sys.argv[4]}/{name}")' \
      "$release_dir" "$part" "$work/$part-parent/out/bundle" "$output/$part"
    record "$part" "$recipe" "$output/$part"
  done
  python3 "$release_dir/local_runtime_sources.py" fetch --side macos --output "$output/sources"
  python3 "$root/scripts/dev/macos-local-runtime.py" \
    --kernel "$linux_dir/kernel/Image-$(pin sources linux version)-codewire2" \
    --initramfs "$linux_dir/initramfs.cpio" \
    --e2fsprogs "$output/e2fsprogs-macos" --git "$output/git-macos" \
    --components "$linux_dir/sources" --components "$output/sources" \
    --pack "$output/runtime" --source-revision "$source_sha"
  cp "$linux_dir"/built/*.json "$output/built/" 2>/dev/null || true
}

"$mode"
log "$mode side complete: $output"
