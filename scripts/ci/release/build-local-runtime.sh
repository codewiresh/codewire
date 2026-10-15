#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: build-local-runtime.sh linux --source-sha SHA --version VERSION --output DIR
       build-local-runtime.sh helper --output DIR
       build-local-runtime.sh macos --linux DIR --source-sha SHA [--helper DIR] --output DIR
       build-local-runtime.sh linux|macos --check

Builds the local VM runtime a release's cws embed, from this checkout: the
macOS target (#2539) and the Linux x86_64 target (#2733). Run it from the
release source; its scripts are that source's own.

linux   x86_64 Linux with Docker, from a checkout whose HEAD is SHA. Takes
        the arm64 and x86_64 kernels from the parts cache or builds them in
        the pinned Arch container; builds the arm64 and x86_64 guest roots and
        the aarch64 and x86_64 sealed cw runtimes (a cw of VERSION) in the
        pinned Rust container; fetches the pinned Cloud Hypervisor and
        virtiofsd and the third-party sources. It never changes the host's
        Rust toolchain. For the macOS target DIR gets initramfs.cpio, kernel/,
        sources/, cw-runtime-aarch64/ and built/ (the cache records of its
        parts built in this run). For the Linux target DIR gets linux-x86_64/,
        a local runtime directory whose one target is linux-x86_64 (the linux
        fragment; scripts/dev/linux-local-runtime.py), and linux-x86_64-built/,
        the cache records of its parts built in this run, which name only
        blobs of that target.
helper  An Apple silicon Mac. Writes DIR/recipe, the recipe of the Developer
        ID-signed VZ helper on this Mac (#1905), and, when the parts cache
        has none for it, DIR/codewire-vz-runner: the helper built here, not
        yet signed. The release's sign-helper job signs and notarizes it
        (sign-macos-helper.sh); nothing here signs.
macos   An Apple silicon Mac. Takes e2fsprogs and git from the parts cache or
        builds them, fetches the Mac-side sources, and packs the macOS target
        from the Linux job's DIR (with its aarch64 cw runtime) and the
        Developer ID-signed VZ helper: --helper DIR names one signed in this
        run (DIR holds codewire-vz-runner, recipe and provenance.json), and
        otherwise it comes from the parts cache. It is never built or signed
        here. DIR/runtime is the one local runtime every release cw embeds:
        the macOS target merged with the Linux job's linux-x86_64 fragment.
        DIR/built gets this job's and the Linux job's cache records, all of
        which now name only blobs the release publishes.

Only a release's publishing job writes cache records; nothing here holds a
credential. Set LOCAL_RUNTIME_NO_BUILD=1 to refuse a cache miss instead of
building (the per-push dry run): it then exits 4. LOCAL_RUNTIME_KERNEL_SOURCE
names an existing Linux clone to build the kernel from instead of cloning.
--check only reports whether that side's slow parts are cached: it exits 0
when all are, and 4 when one would be built.
In a CI job container, LOCAL_RUNTIME_JOB_CONTAINER names that container so the
container builds can reach its files (build-runtime-kernel.sh --job-container);
TMPDIR and DIR must then be on its workspace. LOCAL_RUNTIME_JOBS (default 4)
bounds each kernel and cw build's parallel jobs. The linux side fetches every
pinned download first, then builds the parts that do not depend on each other
side by side: the two kernels, then the two targets' guest roots and cw
runtimes.
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
linux_dir="" source_sha="" version="" output="" check="" helper_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1; shift ;;
    --linux) linux_dir="${2:-}"; shift 2 ;;
    --helper) helper_dir="${2:-}"; shift 2 ;;
    --source-sha) source_sha="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$mode" in
  linux) [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die "the linux side runs on x86_64 Linux"
         [ -z "$linux_dir" ] || die "--linux is for the macos side"
         [ -n "$check" ] || [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "--source-sha must be the release commit"
         [ -n "$check" ] || [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
           die "--version must be the release version vMAJOR.MINOR.PATCH" ;;
  macos) [ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "the macos side runs on an Apple silicon Mac"
         [ -n "$check" ] ||
           case "$linux_dir" in /*) [ -d "$linux_dir" ] || die "--linux is not a directory" ;; *) die "--linux must be absolute" ;; esac
         [ -n "$check" ] || [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "--source-sha must be the release commit"
         [ -z "$helper_dir" ] ||
           case "$helper_dir" in /*) [ -d "$helper_dir" ] || die "--helper is not a directory" ;; *) die "--helper must be absolute" ;; esac ;;
  helper) [ "$(uname -s)-$(uname -m)" = Darwin-arm64 ] || die "the helper is built on an Apple silicon Mac"
          [ -z "$check$linux_dir$source_sha$helper_dir" ] || die "helper takes only --output" ;;
  *) die "mode must be linux, helper or macos" ;;
esac
[ "$mode" = linux ] || [ -z "$version" ] || die "--version is for the linux side"
[ "$mode" = macos ] || [ -z "$helper_dir" ] || die "--helper is for the macos side"
if [ -n "$check" ]; then
  [ -z "$output$linux_dir$source_sha$version" ] || die "--check takes no other argument"
else
  case "$output" in /*) ;; *) die "--output must be an absolute path" ;; esac
  [ ! -e "$output" ] || die "output already exists"
fi

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
# Every cw the Linux side builds, and its document, name this commit.
if [ "$mode" = linux ] && [ -z "$check" ]; then
  [ "$(git -C "$root" rev-parse HEAD)" = "$source_sha" ] || die "--source-sha is not this checkout's HEAD"
fi
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi
}
# Bounded, logged attempts that fail a stalled connection in seconds (#2691).
fetch() {
  local url="$1" digest="$2" target="$3"
  "$release_dir/fetch-pinned.sh" "$url" "$digest" "$target" || die "download failed: $url"
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
# The cache record of a part built in this run, into RECORDS.
record() {
  local part="$1" recipe="$2" dir="$3" records="${4:-$output/built}"
  python3 "$parts" record --part "$part" --recipe "$recipe" --dir "$dir" > "$records/$recipe.json"
}
# Copy a built part's output files from FROM into DIR.
outputs() {
  local part="$1" from="$2" dir="$3"
  python3 -c 'import shutil, sys
sys.path.insert(0, sys.argv[1])
import local_runtime_parts as parts
for name in parts.PARTS[sys.argv[2]]["outputs"]:
    shutil.copy2(f"{sys.argv[3]}/{name}", f"{sys.argv[4]}/{name}")' "$release_dir" "$part" "$from" "$dir"
}

if [ "$mode" = helper ]; then
  mkdir -m 0700 "$output"
elif [ -z "$check" ]; then
  mkdir -m 0700 "$output" "$output/built"
  [ "$mode" != linux ] || mkdir -m 0700 "$output/linux-x86_64-built"
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-local-runtime.XXXXXX")"
chmod 0700 "$work"
trap 'chmod -R u+w "$work" 2>/dev/null || true; rm -rf "$work"' EXIT

host_facts() {
  python3 -c 'import json, platform, subprocess, sys
json.dump({"macos": platform.mac_ver()[0],
           "sdk": subprocess.check_output(["xcrun", "--show-sdk-version"], text=True).strip(),
           "clang": subprocess.check_output(["xcrun", "clang", "--version"], text=True).splitlines()[0]},
          open(sys.argv[1], "w"))' "$work/host.json"
}

# Whether each slow part of this side is cached, without reading its blobs.
check() {
  local part missing=0 status recipe
  local -a facts=()
  if [ "$mode" = macos ]; then
    host_facts
    facts=(--host-facts "$work/host.json")
  fi
  for part in $( [ "$mode" = linux ] && echo kernel-arm64 kernel-x86_64 ||
                 echo e2fsprogs-macos git-macos vz-runner-macos ); do
    recipe="$(python3 "$parts" recipe --part "$part" "${facts[@]}")"
    status=0
    python3 "$parts" present --part "$part" --recipe "$recipe" || status=$?
    case "$status" in
      0) ;;
      3) missing=1 ;;
      *) die "the $part cache could not be read" ;;
    esac
  done
  [ "$missing" = 0 ] || exit 4
}

# The pinned kernel source and bc, once for every kernel this run builds.
linux_source=""
kernel_source() {
  [ -z "$linux_source" ] || return 0
  if [ -n "${LOCAL_RUNTIME_KERNEL_SOURCE:-}" ]; then
    # A developer's existing clone; the recipe checks its commit and tree.
    linux_source="$LOCAL_RUNTIME_KERNEL_SOURCE"
  else
    local tag commit
    tag="v$(pin sources linux version)"
    commit="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["source_commit"])' \
      "$root/scripts/ci/verify/linux-vmm-kernel/provenance.json")"
    linux_source="$work/linux"
    git clone -q --depth 1 --branch "$tag" \
      https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$linux_source"
    [ "$(git -C "$linux_source" rev-parse HEAD)" = "$commit" ] || die "$tag is not the pinned kernel commit"
  fi
  local container
  container="$(docker create "$(pin kernel_bc image)")"
  docker cp "$container:$(pin kernel_bc path)" "$work/bc" >/dev/null
  docker rm "$container" >/dev/null
  [ "$(sha256_of "$work/bc")" = "$(pin kernel_bc sha256)" ] || die "bc differs from its pin"
}

# The ARCH kernel part in DIR from the parts cache; a miss is added to
# kernels_missing (and with LOCAL_RUNTIME_NO_BUILD stops the run).
kernel_lookup() {
  local arch="$1" dir="$2" part="kernel-$1" recipe
  recipe="$(python3 "$parts" recipe --part "$part")"
  if cached "$part" "$recipe" "$dir"; then
    log "$part cached (recipe $recipe)"
  else
    log "$part not cached (recipe $recipe); building it"
    kernels_missing+=("$arch")
  fi
}

# Build the ARCH kernel part into DIR in the pinned Arch container; its record
# goes to RECORDS. kernel_source has run.
kernel_build() {
  local arch="$1" dir="$2" records="$3" part="kernel-$1" recipe
  recipe="$(python3 "$parts" recipe --part "$part")"
  mkdir -m 0700 "$work/$part-build"
  "$release_dir/build-runtime-kernel.sh" --arch "$arch" --source "$linux_source" --bc "$work/bc" \
    --output "$work/$part-build/kernel" --jobs "${LOCAL_RUNTIME_JOBS:-4}" ${shared[@]+"${shared[@]}"}
  mkdir -m 0700 "$dir"
  outputs "$part" "$work/$part-build/kernel" "$dir"
  record "$part" "$recipe" "$dir" "$records"
}
kernel-arm64() { kernel_build arm64 "$output/kernel" "$output/built"; }
kernel-x86_64() { kernel_build x86_64 "$work/kernel-x86_64" "$output/linux-x86_64-built"; }

# Run each named function in its own subshell at the same time, every line it
# writes prefixed with its name, and fail when any fails. The functions write
# disjoint paths and share only this run's read-only inputs.
side_by_side() {
  local name pid failed=0
  local -a pids=()
  for name in "$@"; do
    ( "$name" ) > >(sed -u "s/^/[$name] /") 2>&1 &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || failed=1
  done
  [ "$failed" = 0 ] || die "a part built side by side failed; its lines above say which"
}

# The TARGET guest root at FILE: the sealed probe built twice, with the pinned
# Alpine BusyBox and official runc, in the pinned Rust container (not on the
# runner's sealed toolchain).
guest_root() {
  local target="$1" file="$2" member
  log "building the $target guest root"
  member="$(pin initramfs_inputs "$target" busybox member)"
  mkdir "$work/busybox-$target"
  tar -xzf "$work/busybox-$target.apk" -C "$work/busybox-$target" "$member" 2>/dev/null ||
    die "the $target BusyBox package holds no $member"
  "$release_dir/build-runtime-guest-root.sh" --target "$target" --busybox "$work/busybox-$target/$member" \
    --runc "$work/runc-$target" "${rust_std[@]}" --protoc-zip "$work/protoc.zip" \
    --output "$file" ${shared[@]+"${shared[@]}"}
}

# The sealed TARGET cw runtime in DIR, a cw of the release version built from
# this checkout with no local runtime embedded.
cw_runtime() {
  local target="$1" dir="$2"
  log "building the $target cw runtime"
  "$release_dir/build-runtime-cw.sh" --target "$target" --version "$version" "${rust_std[@]}" \
    --protoc-zip "$work/protoc.zip" --zig "$work/zig.tar.xz" --output "$dir" \
    --jobs "${LOCAL_RUNTIME_JOBS:-4}" ${shared[@]+"${shared[@]}"}
}

# The two targets' guest roots and sealed cw runtimes, one chain per target.
# Each chain runs its cw build when the other's guest root builds, so the two
# Rust builds overlap for a minute or two rather than end to end.
aarch64-parts() {
  guest_root aarch64-unknown-linux-musl "$output/initramfs.cpio"
  cw_runtime aarch64-unknown-linux-musl "$output/cw-runtime-aarch64"
}
x86_64-parts() {
  cw_runtime x86_64-unknown-linux-musl "$work/cw-runtime-x86_64"
  guest_root x86_64-unknown-linux-musl "$work/initramfs-x86_64.cpio"
}

linux() {
  shared=()
  [ -z "${LOCAL_RUNTIME_JOB_CONTAINER:-}" ] || shared=(--job-container "$LOCAL_RUNTIME_JOB_CONTAINER")
  # The slow parts first: with LOCAL_RUNTIME_NO_BUILD a miss stops here.
  kernels_missing=()
  kernel_lookup arm64 "$output/kernel"
  kernel_lookup x86_64 "$work/kernel-x86_64"

  # Every pinned download before any build, so an unreachable origin fails
  # the run in minutes, not after the builds.
  local target
  rust_std=()
  for target in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
    fetch "$(pin guest_root_builder rust_std "$target" url)" "$(pin guest_root_builder rust_std "$target" sha256)" \
      "$work/rust-std-$target.tar.xz"
    rust_std+=(--rust-std "$work/rust-std-$target.tar.xz")
  done
  fetch "$(pin guest_root_builder protoc url)" "$(pin guest_root_builder protoc sha256)" "$work/protoc.zip"
  fetch "$(pin cw_runtime_builder zig url)" "$(pin cw_runtime_builder zig sha256)" "$work/zig.tar.xz"
  fetch "$(pin linux_runtime cloud_hypervisor url)" "$(pin linux_runtime cloud_hypervisor sha256)" \
    "$work/cloud-hypervisor"
  fetch "$(pin linux_runtime virtiofsd url)" "$(pin linux_runtime virtiofsd sha256)" "$work/virtiofsd.zip"
  python3 "$release_dir/local_runtime_sources.py" fetch --side linux-host --output "$work/host-sources"
  local guest
  for guest in aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
    fetch "$(pin initramfs_inputs "$guest" busybox url)" "$(pin initramfs_inputs "$guest" busybox sha256)" \
      "$work/busybox-$guest.apk"
    fetch "$(pin initramfs_inputs "$guest" runc url)" "$(pin initramfs_inputs "$guest" runc sha256)" \
      "$work/runc-$guest"
  done

  # A kernel that missed is built beside the other, from one source clone.
  if [ "${#kernels_missing[@]}" -gt 0 ]; then
    kernel_source
    side_by_side "${kernels_missing[@]/#/kernel-}"
  fi
  # Each target's guest root and cw runtime, beside the other target's.
  side_by_side aarch64-parts x86_64-parts

  # The macOS target's Linux side.
  python3 "$release_dir/local_runtime_sources.py" fetch --side linux --kernel "$output/kernel" \
    --output "$output/sources"

  # The Linux target, packed as the linux fragment. Its kernel source is the
  # archive above: the same pinned commit.
  python3 "$root/scripts/dev/linux-local-runtime.py" pack \
    --kernel "$work/kernel-x86_64/vmlinuz-$(pin sources linux version)-codewire2" \
    --initramfs "$work/initramfs-x86_64.cpio" \
    --cloud-hypervisor "$work/cloud-hypervisor" --virtiofsd-zip "$work/virtiofsd.zip" \
    --cw-runtime "$work/cw-runtime-x86_64" \
    --components "$output/sources" --components "$work/host-sources" \
    --source-revision "$source_sha" --output "$output/linux-x86_64"
}

# The VZ helper part's recipe on this Mac and, on a cache miss, the helper
# built from this checkout, unsigned (sign-macos-helper.sh signs it).
helper() {
  local recipe status=0 package="$root/crates/codewire-local-vmm/macos-vz-runner" bin
  host_facts
  recipe="$(python3 "$parts" recipe --part vz-runner-macos --host-facts "$work/host.json")"
  printf '%s\n' "$recipe" >"$output/recipe"
  python3 "$parts" present --part vz-runner-macos --recipe "$recipe" || status=$?
  case "$status" in
    0) log "vz-runner-macos cached (recipe $recipe); nothing to sign"
       return 0 ;;
    3) log "vz-runner-macos not cached (recipe $recipe); building it for signing" ;;
    *) die "the vz-runner-macos cache could not be read" ;;
  esac
  # The build stays in this run's work directory, out of the checkout.
  swift build -c release --package-path "$package" --scratch-path "$work/swift"
  bin="$(swift build -c release --package-path "$package" --scratch-path "$work/swift" --show-bin-path)"
  [ -f "$bin/codewire-vz-runner" ] && [ ! -L "$bin/codewire-vz-runner" ] || die "swift build produced no helper"
  install -m 0755 "$bin/codewire-vz-runner" "$output/codewire-vz-runner"
}

# The Developer ID-signed VZ helper part in DIR: signed in this run (its
# record, with the run's provenance, goes to the publishing job) or cached.
signed_helper() {
  local dir="$1" recipe
  recipe="$(python3 "$parts" recipe --part vz-runner-macos --host-facts "$work/host.json")"
  if [ -n "$helper_dir" ]; then
    [ "$(cat "$helper_dir/recipe")" = "$recipe" ] ||
      die "the signed helper was built for another recipe than this Mac's $recipe"
    [ "$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("source_sha", ""))' \
      "$helper_dir/provenance.json")" = "$source_sha" ] || die "the signed helper's provenance names another commit"
    mkdir -m 0700 "$dir"
    outputs vz-runner-macos "$helper_dir" "$dir"
    python3 "$parts" record --part vz-runner-macos --recipe "$recipe" --dir "$dir" \
      --provenance "$helper_dir/provenance.json" >"$output/built/$recipe.json"
    log "vz-runner-macos signed in this run (recipe $recipe)"
  elif cached vz-runner-macos "$recipe" "$dir"; then
    log "vz-runner-macos cached (recipe $recipe)"
  else
    die "the signed VZ helper (recipe $recipe) is not cached; a release signs it in sign-helper and passes --helper"
  fi
}

macos() {
  host_facts
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
  signed_helper "$output/vz-runner-macos"
  python3 "$release_dir/local_runtime_sources.py" fetch --side macos --output "$output/sources"
  # The macOS target, with the aarch64 cw runtime the Linux job built.
  local cw_runtime=()
  [ ! -d "$linux_dir/cw-runtime-aarch64" ] || cw_runtime=(--cw-runtime "$linux_dir/cw-runtime-aarch64")
  python3 "$root/scripts/dev/macos-local-runtime.py" \
    --kernel "$linux_dir/kernel/Image-$(pin sources linux version)-codewire2" \
    --initramfs "$linux_dir/initramfs.cpio" \
    --e2fsprogs "$output/e2fsprogs-macos" --git "$output/git-macos" \
    --helper "$output/vz-runner-macos/codewire-vz-runner" \
    --components "$linux_dir/sources" --components "$output/sources" \
    ${cw_runtime[@]+"${cw_runtime[@]}"} \
    --pack "$work/runtime-macos" --source-revision "$source_sha"
  # The one document every release cw embeds: the macOS target and, from a
  # source that builds it, the Linux job's linux-x86_64 fragment (#2733).
  local fragments=(--dir "$work/runtime-macos")
  [ ! -d "$linux_dir/linux-x86_64" ] || fragments+=(--dir "$linux_dir/linux-x86_64")
  python3 "$release_dir/cw_release.py" merge-local-runtime --output "$output/runtime" "${fragments[@]}"
  cp "$linux_dir"/built/*.json "$output/built/" 2>/dev/null || true
  # The fragment's records name its blobs, which the merged runtime publishes.
  [ ! -d "$linux_dir/linux-x86_64" ] || cp "$linux_dir"/linux-x86_64-built/*.json "$output/built/" 2>/dev/null || true
}

if [ -n "$check" ]; then
  check
  log "$mode side: every slow part is cached"
elif [ "$mode" = helper ]; then
  helper
  log "helper complete: $output"
else
  "$mode"
  log "$mode side complete: $output"
fi
