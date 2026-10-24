#!/usr/bin/env bash
# Compile-once step 1 (infra#1632): build one commit's test archive on the
# pull request build runner, beside the rust-compile lint (clippy and the
# curated workspaces) in a second build folder, upload the archive to the
# archive store and fetch it back as a test job will, and record every time.
#
# The build runner's guest mounts its persistent build disk at /ci-cache and
# keeps it between guests and jobs. Everything that must stay warm lives under
# /ci-cache/pr:
# - src: a persistent clone. The job's own checkout is fetched into it, so git
#   rewrites only the files that changed and Cargo's mtime fingerprints keep
#   every unchanged workspace crate fresh (a new checkout would rebuild them
#   all), and every build sees the same absolute workspace path.
# - targets/archive: the test archive build, line-tables debug info.
# - targets/clippy: compile-all-targets.sh's build folder.
# - cargo-home: the registry index and downloaded crates.
# - tools: the downloads of SHA-256-pinned tools, checked on every use.
# - lock-stamp: the digest of every lockfile and the toolchain file. When it
#   changes, both target folders are wiped; WIPE=true wipes all of /ci-cache/pr
#   for a cold build. The guest also wipes the whole disk on a schedule.
# Anything else under /ci-cache is removed before the build: a previous job
# could have left Cargo configuration in a parent directory of src.
#
# Usage: build-runner.sh CHECKOUT OUT_DIR
#   CHECKOUT is this job's checkout of the commit to build; OUT_DIR receives
#   the archive, the logs, one JSON record per phase and summary.md.
# Environment:
#   WIPE=true|false        wipe /ci-cache/pr first (a cold build)
#   CLIPPY=parallel|serial|off
#   JOBS                   Cargo jobs for each build (default 16)
#   TOUCH                  optional source path (relative to the checkout) to
#                          append a comment line to before building, to
#                          measure a one-file change
#   ARCHIVE_STORE_URL      the store's base URL, or empty to skip the handoff
#   BUILD_RUNNER_ROOT      default /ci-cache (tests point it elsewhere)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SAMPLER="$ROOT/scripts/ci/measure/sample-process-tree.py"
readonly PROTOC_URL='https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip'
readonly PROTOC_SHA256='6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7'

die() {
  echo "build-runner: $*" >&2
  exit 2
}

[ "$#" -eq 2 ] || die 'usage: build-runner.sh CHECKOUT OUT_DIR'
checkout="$(cd "$1" && pwd)"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
readonly cache_root="${BUILD_RUNNER_ROOT:-/ci-cache}"
readonly work="$cache_root/pr"
readonly src="$work/src"
jobs="${JOBS:-16}"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "JOBS must be a positive integer, got: $jobs"
case "${CLIPPY:-parallel}" in parallel|serial|off) ;; *) die "unknown CLIPPY: $CLIPPY" ;; esac
case "${WIPE:-false}" in true|false) ;; *) die "WIPE must be true or false, got: $WIPE" ;; esac
[ "$(git -C "$checkout" rev-parse --show-toplevel 2>/dev/null)" = "$checkout" ] || die "$checkout is not a git checkout"
if [ -z "${BUILD_RUNNER_ROOT:-}" ]; then
  [ "$(stat -f -c %T "$cache_root" 2>/dev/null)" = ext2/ext3 ] ||
    die "$cache_root is not the build runner's build disk"
fi

now() { date +%s.%N; }
seconds() { python3 -I -c 'import sys; print(f"{float(sys.argv[2]) - float(sys.argv[1]):.1f}")' "$1" "$2"; }
record() {
  # record NAME SECONDS [KEY=VALUE...]: one JSON line in records.jsonl.
  python3 -I - "$@" >> "$out/records.jsonl" <<'PY'
import json, sys
name, seconds, *pairs = sys.argv[1:]
print(json.dumps({"phase": name, "seconds": float(seconds), **dict(pair.split("=", 1) for pair in pairs)}))
PY
}
json() {
  python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}
size_gb() {
  if [ -e "$1" ]; then
    du -sb "$1" | awk '{ printf "%.1f", $1 / 1e9 }'
  else
    echo 0
  fi
}
: > "$out/records.jsonl"

# The guest and its disk, for the record.
{
  echo "nproc=$(nproc)"
  awk '$1 == "MemTotal:" || $1 == "MemAvailable:" { printf "%s=%.1fGiB\n", $1, $2 / 1048576 }' /proc/meminfo
  echo "memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)"
  df -h "$cache_root" | tail -n 1
} | tee "$out/guest.txt"

# Only /ci-cache/pr and its known entries persist.
started="$(now)"
mkdir -p "$work"
shopt -s dotglob nullglob
for entry in "$cache_root"/*; do
  [ "$entry" = "$work" ] || [ "$entry" = "$cache_root/lost+found" ] || rm -rf -- "$entry"
done
if [ "${WIPE:-false}" = true ]; then
  echo 'build-runner: cold build, the build folder is wiped'
  rm -rf -- "$work"
  mkdir -p "$work"
fi
for entry in "$work"/*; do
  case "${entry##*/}" in
    src|targets|cargo-home|tools|lock-stamp) ;;
    *) rm -rf -- "$entry" ;;
  esac
done
shopt -u dotglob nullglob
mkdir -p "$work/targets" "$work/cargo-home" "$work/tools"
record prepare "$(seconds "$started" "$(now)")"

# Bring the persistent clone to the commit. git checkout rewrites only the
# files that differ; hooks never run.
started="$(now)"
commit="$(git -C "$checkout" rev-parse HEAD)"
git_quiet=(git -c core.hooksPath=/dev/null -c advice.detachedHead=false -C "$src")
if [ ! -d "$src/.git" ]; then
  rm -rf -- "$src"
  git init -q "$src"
fi
[ "$(git -C "$checkout" rev-parse HEAD)" = "$commit" ] || die 'the checkout moved'
# The job's checkout is shallow (depth 1); without --update-shallow git
# refuses its shallow root and the fetch brings nothing.
"${git_quiet[@]}" fetch -q --no-tags --update-shallow "$checkout" HEAD
[ "$("${git_quiet[@]}" rev-parse FETCH_HEAD)" = "$commit" ] || die 'the fetch did not bring the commit'
"${git_quiet[@]}" checkout -q --force --detach "$commit"
"${git_quiet[@]}" clean -q -ffdx
[ "$("${git_quiet[@]}" rev-parse HEAD)" = "$commit" ] || die 'the persistent clone is not at the commit'
if [ -n "${TOUCH:-}" ]; then
  [ -f "$src/$TOUCH" ] || die "TOUCH names no file: $TOUCH"
  printf '\n// build-runner measurement: one changed file\n' >> "$src/$TOUCH"
  echo "build-runner: changed $TOUCH"
fi
record checkout "$(seconds "$started" "$(now)")" commit="$commit"

# A changed lockfile or toolchain wipes both build folders.
stamp="$(cd "$src" && cat Cargo.lock rust-toolchain.toml deployments/docker/*.Cargo.lock | sha256sum | cut -d' ' -f1)"
if [ "$(cat "$work/lock-stamp" 2>/dev/null || true)" != "$stamp" ]; then
  echo 'build-runner: the lockfiles or toolchain changed; the build folders are wiped'
  rm -rf -- "$work/targets"
  mkdir -p "$work/targets"
  printf '%s\n' "$stamp" > "$work/lock-stamp"
fi
targets_before="$(size_gb "$work/targets")"

# Pinned tools: each download is kept and checked against its pin on every use.
started="$(now)"
tool() {
  local url="$1" digest="$2" file="$work/tools/$2"
  if [ ! -f "$file" ] || [ "$(sha256sum "$file" | cut -d' ' -f1)" != "$digest" ]; then
    rm -f -- "$file"
    "$ROOT/scripts/ci/release/fetch-pinned.sh" "$url" "$digest" "$file"
  fi
  printf '%s\n' "$file"
}
bin="$(mktemp -d "${RUNNER_TEMP:-/tmp}/build-runner-bin.XXXXXX")"
unzip -q -o "$(tool "$PROTOC_URL" "$PROTOC_SHA256")" -d "$bin/protoc"
nextest_url="$(sed -nE "s/^readonly NEXTEST_URL=\"(.*)\"$/\\1/p" "$ROOT/scripts/ci/setup/install-cargo-nextest.sh")"
nextest_version="$(sed -nE "s/^readonly NEXTEST_VERSION='([^']*)'$/\\1/p" "$ROOT/scripts/ci/setup/install-cargo-nextest.sh")"
nextest_sha="$(sed -nE "s/^readonly NEXTEST_SHA256='([0-9a-f]{64})'$/\\1/p" "$ROOT/scripts/ci/setup/install-cargo-nextest.sh")"
nextest_url="${nextest_url//\$\{NEXTEST_VERSION\}/$nextest_version}"
[ -n "$nextest_sha" ] && [[ "$nextest_url" == https://* ]] || die 'cannot read the cargo-nextest pin'
tar -xzf "$(tool "$nextest_url" "$nextest_sha")" -C "$bin" cargo-nextest
"$bin/cargo-nextest" nextest --version | head -n 1
export PATH="$bin/protoc/bin:$bin:$PATH"
protoc --version
record tools "$(seconds "$started" "$(now)")"

export CARGO_HOME="$work/cargo-home"
export CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_BUILD_JOBS="$jobs"
export CODEWIRE_LOCAL_RUST_CACHE=off
export CARGO_TERM_COLOR=never
unset RUSTC_WRAPPER CARGO_TARGET_DIR

archive="$out/tests.tar.zst"
build_archive() {
  cd "$src"
  CARGO_TARGET_DIR="$work/targets/archive" python3 -I "$SAMPLER" "$out/archive.json" -- \
    cargo nextest archive --locked --workspace --archive-file "$archive" > "$out/archive.log" 2>&1
}
build_clippy() {
  cd "$src"
  CARGO_TARGET_DIR="$work/targets/clippy" python3 -I "$SAMPLER" "$out/clippy.json" -- \
    scripts/ci/verify/compile-all-targets.sh > "$out/clippy.log" 2>&1
}

status_archive=0 status_clippy=0
started="$(now)"
case "${CLIPPY:-parallel}" in
  parallel)
    build_clippy & clippy_pid=$!
    build_archive || status_archive=$?
    wait "$clippy_pid" || status_clippy=$?
    ;;
  serial)
    build_archive || status_archive=$?
    build_clippy || status_clippy=$?
    ;;
  off)
    build_archive || status_archive=$?
    ;;
esac
both="$(seconds "$started" "$(now)")"
tail -n 5 "$out/archive.log"
[ "${CLIPPY:-parallel}" = off ] || tail -n 3 "$out/clippy.log"
record builds "$both" clippy="${CLIPPY:-parallel}" archive_status="$status_archive" clippy_status="$status_clippy"
[ "$status_archive" -eq 0 ] || { tail -n 60 "$out/archive.log" >&2; echo 'build-runner: the archive did not build' >&2; exit 1; }
[ "$status_clippy" -eq 0 ] || { tail -n 60 "$out/clippy.log" >&2; echo 'build-runner: compile-all-targets failed' >&2; exit 1; }

digest="$(sha256sum "$archive" | cut -d' ' -f1)"
archive_bytes="$(stat -c %s "$archive")"
upload="" fetch=""
if [ -n "${ARCHIVE_STORE_URL:-}" ]; then
  # The handoff as a test job sees it: upload, then fetch into memory and
  # check the digest the build reported.
  started="$(now)"
  curl -fsS --retry 3 --retry-connrefused -o /dev/null -T "$archive" "$ARCHIVE_STORE_URL/v1/archives/$digest"
  upload="$(seconds "$started" "$(now)")"
  record upload "$upload" bytes="$archive_bytes"
  fetched="$(mktemp -d /dev/shm/build-runner-fetch.XXXXXX 2>/dev/null || mktemp -d)"
  started="$(now)"
  curl -fsS --retry 3 -o "$fetched/tests.tar.zst" "$ARCHIVE_STORE_URL/v1/archives/$digest"
  copied="$(now)"
  [ "$(sha256sum "$fetched/tests.tar.zst" | cut -d' ' -f1)" = "$digest" ] || die 'the fetched archive does not match its digest'
  fetch="$(seconds "$started" "$(now)")"
  record fetch "$fetch" copy_seconds="$(seconds "$started" "$copied")"
  rm -rf -- "$fetched"
fi

{
  echo "## Build runner: ${ROLE:-build} of ${commit:0:12}"
  echo
  echo "Guest: $(tr '\n' ' ' < "$out/guest.txt")"
  echo
  echo "| Phase | Seconds | Peak memory | Peak cores |"
  echo "|---|---:|---:|---:|"
  echo "| archive build | $(json "$out/archive.json" wall_seconds) | $(json "$out/archive.json" peak_rss_gib) GiB | $(json "$out/archive.json" peak_cores) |"
  if [ "${CLIPPY:-parallel}" != off ]; then
    echo "| compile-all-targets ($CLIPPY) | $(json "$out/clippy.json" wall_seconds) | $(json "$out/clippy.json" peak_rss_gib) GiB | $(json "$out/clippy.json" peak_cores) |"
  fi
  echo "| both builds, wall | $both | | |"
  [ -z "$upload" ] || echo "| upload to the store | $upload | | |"
  [ -z "$fetch" ] || echo "| fetch and SHA-256 check | $fetch | | |"
  echo
  echo "Archive: $(awk -v b="$archive_bytes" 'BEGIN { printf "%.2f GB", b / 1e9 }'), sha256 $digest."
  echo "Build folders: $(size_gb "$work/targets/archive") GB archive, $(size_gb "$work/targets/clippy") GB clippy, $(size_gb "$work/cargo-home") GB Cargo home (targets were $targets_before GB before); disk: $(df -h "$cache_root" | awk 'END { print $3 " used of " $2 }')."
  echo "Jobs: $jobs per build. Wipe: ${WIPE:-false}. Changed file: ${TOUCH:-none}."
} > "$out/summary.md"
cat "$out/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$out/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "archive_sha256=$digest"
    echo "archive_bytes=$archive_bytes"
  } >> "$GITHUB_OUTPUT"
fi
