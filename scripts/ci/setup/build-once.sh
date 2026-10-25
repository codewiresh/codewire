#!/usr/bin/env bash
# Compile once per run (infra#1632): the build half, on a build runner, whose
# guest mounts its persistent build disk at /ci-cache and keeps it between
# guests and jobs. A push to main runs on the main build runner and builds in
# /ci-cache/main; every other run, on the pull request build runner, in
# /ci-cache/pr (build-once-tree.sh). A disk that already holds the other
# folder is refused, so a job never builds on, or clears, the other kind's
# runner. That check is advisory, since a pull request can change this
# script; the runners' labels and the archive stores' admission keep the
# kinds apart.
#
#   build-once.sh prepare CHECKOUT  bring the warm build folder to this job's
#                                   commit and set up the pinned tools
#   build-once.sh build OUT         run every wanted leg (LEGS below); a leg
#                                   that produces something for test jobs
#                                   writes OUT/<leg>.<ext>
#   build-once.sh leg NAME OUT      run one leg
#   build-once.sh legs [LANE]       list the wanted legs, in build order
#   build-once.sh publish OUT       upload every OUT/<leg>.* to the archive
#                                   store and report its SHA-256 as the job
#                                   output <leg>_sha256
#   build-once.sh finish            flush the build folder to disk and mark
#                                   it complete (the job's last step, on
#                                   success or failure, never on a cancel)
#
# The build folder, /ci-cache/main or /ci-cache/pr:
# - src: a persistent clone. The job's checkout is fetched into it, so git
#   rewrites only changed files and Cargo's mtime fingerprints keep every
#   unchanged workspace crate fresh (a new checkout rebuilds them all); every
#   build also sees the same absolute workspace path. Hooks never run.
# - targets/archive and targets/clippy: the two Cargo target folders.
# - cargo-home: the registry index and downloaded crates.
# - tools: downloads of SHA-256-pinned tools, checked on every use.
# - lock-stamp: the digest of every lockfile and the toolchain file, and of
#   this folder's layout version. When it changes, the target folders are
#   wiped.
# - unfinished: written by prepare, removed by finish once the folder is on
#   disk. A job that was cancelled or whose guest died leaves it, and the next
#   prepare wipes the target folders: a guest killed mid-build can leave a
#   truncated rlib that Cargo's fingerprint still calls fresh (main run 22374,
#   "Archive::children failed: truncated or malformed archive").
# Anything else under /ci-cache is removed first: a previous job could have
# left Cargo configuration in a parent directory of src. The guest itself
# wipes the whole folder weekly (infra dispatcher, metal_build_disk_prelude).
#
# The archive carries line-tables debug info, as every CI Rust build does.
# prepare exports the build environment to GITHUB_ENV and GITHUB_PATH, so the
# later steps of the same job build from src with it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly PROTOC_URL='https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip'
readonly PROTOC_SHA256='6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7'
readonly cache_root="${BUILD_ONCE_ROOT:-/ci-cache}"
# shellcheck source=scripts/ci/setup/build-once-tree.sh
source "$ROOT/scripts/ci/setup/build-once-tree.sh"
work="$(build_once_tree "$cache_root")"
readonly work
if [ "${work##*/}" = main ]; then other_work="$cache_root/pr"; else other_work="$cache_root/main"; fi
readonly other_work
readonly src="$work/src"

die() {
  echo "build-once: $*" >&2
  exit 2
}

phase() {
  local name="$1" started=$SECONDS status=0
  shift
  echo "[build-once] $name: start"
  "$@" || status=$?
  echo "[build-once] $name: finish (status=$status elapsed_seconds=$((SECONDS - started)))"
  return "$status"
}

pin() {
  sed -nE "s/^readonly $1=['\"]([^'\"]*)['\"]$/\\1/p" "$ROOT/scripts/ci/setup/install-cargo-nextest.sh"
}

tool() {
  # tool URL SHA256: the path of the kept download, fetched when missing or changed.
  local url="$1" digest="$2" file="$work/tools/$2"
  if [ ! -f "$file" ] || [ "$(sha256sum "$file" | cut -d' ' -f1)" != "$digest" ]; then
    rm -f -- "$file"
    "$ROOT/scripts/ci/release/fetch-pinned.sh" "$url" "$digest" "$file" >&2
  fi
  printf '%s\n' "$file"
}

prepare() {
  local checkout commit entry stamp bin nextest_version nextest_url nextest_sha share
  checkout="$(cd "$1" && pwd)"
  [ "$(git -C "$checkout" rev-parse --show-toplevel 2>/dev/null)" = "$checkout" ] ||
    die "$checkout is not a git checkout"
  if [ -z "${BUILD_ONCE_ROOT:-}" ]; then
    [ "$(stat -f -c %T "$cache_root" 2>/dev/null)" = ext2/ext3 ] ||
      die "$cache_root is not the build runner's build disk"
  fi
  [ ! -e "$other_work" ] ||
    die "this build disk holds $other_work; a ${work##*/} run does not build here"
  # The workflow names the same folder for its later steps.
  [ -z "${BUILD_ONCE_TREE:-}" ] || [ "$BUILD_ONCE_TREE" = "$work" ] ||
    die "BUILD_ONCE_TREE=$BUILD_ONCE_TREE, but this run builds in $work"
  : "${GITHUB_ENV:?a Forgejo job environment file is required}"
  # The build runner's share of the host (cpu-share.sh) sets the Cargo jobs.
  # shellcheck source=scripts/ci/setup/cpu-share.sh
  source "$ROOT/scripts/ci/setup/cpu-share.sh"
  share="$(ci_cpu_share)"
  : "${GITHUB_PATH:?a Forgejo job path file is required}"

  mkdir -p "$work"
  shopt -s dotglob nullglob
  for entry in "$cache_root"/*; do
    [ "$entry" = "$work" ] || [ "$entry" = "$cache_root/lost+found" ] || rm -rf -- "$entry"
  done
  for entry in "$work"/*; do
    case "${entry##*/}" in
      src|targets|cargo-home|tools|lock-stamp|unfinished) ;;
      *) rm -rf -- "$entry" ;;
    esac
  done
  shopt -u dotglob nullglob
  mkdir -p "$work/targets" "$work/cargo-home" "$work/tools"

  commit="$(git -C "$checkout" rev-parse HEAD)"
  local git_src=(git -c core.hooksPath=/dev/null -c advice.detachedHead=false -C "$src")
  if [ ! -d "$src/.git" ]; then
    rm -rf -- "$src"
    git init -q "$src"
  fi
  # The checkout is shallow; its root may move the clone's shallow boundary.
  "${git_src[@]}" fetch -q --no-tags --update-shallow "$checkout" HEAD
  [ "$("${git_src[@]}" rev-parse FETCH_HEAD)" = "$commit" ] || die 'the fetch did not bring the commit'
  "${git_src[@]}" checkout -q --force --detach "$commit"
  "${git_src[@]}" clean -q -ffdx
  [ "$("${git_src[@]}" rev-parse HEAD)" = "$commit" ] || die 'the persistent clone is not at the commit'

  # The layout version: raising it wipes every build runner's target folders
  # once (2: folders that a cancelled job may have left truncated).
  stamp="$( (echo 'build-once layout 2'; cd "$src" && cat Cargo.lock rust-toolchain.toml deployments/docker/*.Cargo.lock) | sha256sum | cut -d' ' -f1)"
  if [ "$(cat "$work/lock-stamp" 2>/dev/null || true)" != "$stamp" ]; then
    echo 'build-once: the lockfiles, toolchain or folder layout changed; the target folders are wiped'
    rm -rf -- "$work/targets"
    mkdir -p "$work/targets"
    printf '%s\n' "$stamp" > "$work/lock-stamp"
  elif [ -e "$work/unfinished" ]; then
    echo 'build-once: the previous build did not finish (cancelled, or its guest died); the target folders are wiped'
    rm -rf -- "$work/targets"
    mkdir -p "$work/targets"
  fi
  : > "$work/unfinished"
  sync -f "$work"
  # Tests stop here, before the pinned tools; never on a build runner's disk.
  if [ -n "${BUILD_ONCE_ROOT:-}" ] && [ "${BUILD_ONCE_TEST_STOP_AFTER_TARGETS:-}" = 1 ]; then
    return 0
  fi
  # A cold build (no archive or lint folder yet) builds one folder at a time:
  # two cold builds side by side ran the 17.6 GiB guest out of memory.
  local cold=false
  [ -d "$work/targets/archive" ] && [ -d "$work/targets/clippy" ] || cold=true

  bin="${RUNNER_TEMP:?RUNNER_TEMP is required}/build-once-bin"
  rm -rf -- "$bin"
  mkdir -p "$bin"
  unzip -q -o "$(tool "$PROTOC_URL" "$PROTOC_SHA256")" -d "$bin/protoc"
  nextest_version="$(pin NEXTEST_VERSION)"
  nextest_url="$(pin NEXTEST_URL)"
  nextest_url="${nextest_url//\$\{NEXTEST_VERSION\}/$nextest_version}"
  nextest_sha="$(pin NEXTEST_SHA256)"
  [[ "$nextest_sha" =~ ^[0-9a-f]{64}$ ]] && [[ "$nextest_url" == https://* ]] ||
    die 'cannot read the cargo-nextest pin'
  tar -xzf "$(tool "$nextest_url" "$nextest_sha")" -C "$bin" cargo-nextest
  "$bin/protoc/bin/protoc" --version
  "$bin/cargo-nextest" nextest --version | head -n 1

  {
    echo "BUILD_ONCE_SRC=$src"
    echo "CARGO_HOME=$work/cargo-home"
    echo 'CARGO_PROFILE_DEV_DEBUG=line-tables-only'
    echo "CARGO_BUILD_JOBS=${BUILD_ONCE_JOBS:-${share:-16}}"
    echo 'CODEWIRE_LOCAL_RUST_CACHE=off'
    echo 'CARGO_TERM_COLOR=never'
    echo "BUILD_ONCE_COLD=$cold"
  } >> "$GITHUB_ENV"
  {
    echo "$bin/protoc/bin"
    echo "$bin"
  } >> "$GITHUB_PATH"
  echo "build-once: $src is at $commit; targets $(du -sh "$work/targets" | cut -f1); cold=$cold"
}

in_src() {
  [ -n "${BUILD_ONCE_SRC:-}" ] && [ -d "$BUILD_ONCE_SRC/.git" ] || die 'run prepare first'
  cd "$BUILD_ONCE_SRC"
  unset RUSTC_WRAPPER
  # If the guest still runs out of memory, the kernel kills a compiler, so
  # Cargo fails the job at once, never the job container's own process: a
  # killed job container left its runner reporting the job running for hours
  # (codewire run 21939). Raising one's own score needs no privilege, and
  # every compiler this shell starts inherits it.
  echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true
}

# The legs, in the order a cold build runs them. Each line is
#   NAME LANE WANTED
# - NAME: the leg runs leg_NAME OUT; a leg whose test jobs fetch its output
#   writes OUT/NAME.<ext>, published as the job output NAME_sha256.
# - LANE: "tests" legs build test archives in targets/archive (one Cargo
#   target folder, so they run one after another anyway); "checks" legs build
#   in their own folders and produce nothing to publish.
# - WANTED: "always", or "selected:TOKEN", a verification token in
#   VERIFICATION_SELECTION, or "env:NAME", an environment variable that is
#   "true".
# Warm, the two lanes run side by side and share the job's Cargo jobs, the
# tests lane taking the larger part, since the test jobs wait for it. Cold
# (prepare's BUILD_ONCE_COLD), every leg runs one after another at the full
# Cargo jobs: two cold builds side by side at 16 jobs each ran the 17.6 GiB
# guest out of memory (codewire run 21939).
LEGS=(
  "archive tests always"
  "compile checks always"
  "database tests selected:database"
)

leg_archive() {
  # The workspace test archive: every package's tests, default features.
  local out="$1"
  phase 'test archive' env CARGO_TARGET_DIR="$work/targets/archive" \
    cargo nextest archive --locked --workspace --all-targets --archive-file "$out/archive.tar.zst"
}

leg_compile() {
  # compile-all-targets.sh: clippy with default and all features, every
  # target, and the curated image workspaces.
  phase 'compile-all-targets' env CARGO_TARGET_DIR="$work/targets/clippy" \
    scripts/ci/verify/compile-all-targets.sh
}

leg_database() {
  # The database suites' archives, one per package and feature set, built by
  # run-integration-verification.sh from its own suite list, with the
  # CI-profile migration runner; bundled into one tar.
  local out="$1" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/database-archives.XXXXXX")"
  phase 'database archives' env CARGO_TARGET_DIR="$work/targets/archive" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$work/targets/archive" ARCHIVE_BUILD_DIR="$dir" \
    scripts/ci/verify/run-integration-verification.sh database-archives
  tar -cf "$out/database.tar" -C "$dir" .
  rm -rf -- "$dir"
}

leg_wanted() {
  case "$1" in
    always) return 0 ;;
    selected:*) [[ "${VERIFICATION_SELECTION:-}" == *"|${1#selected:}|"* ]] ;;
    env:*)
      local var="${1#env:}"
      [[ "$var" =~ ^[A-Z_][A-Z0-9_]*$ ]] || die "invalid leg condition: $1"
      [ "${!var:-}" = true ]
      ;;
    *) die "unknown leg condition: $1" ;;
  esac
}

wanted_legs() {
  # wanted_legs LANE: the names of that lane's wanted legs, in table order.
  local entry name lane wanted
  for entry in "${LEGS[@]}"; do
    read -r name lane wanted <<< "$entry"
    [ -z "${1:-}" ] || [ "$lane" = "$1" ] || continue
    if leg_wanted "$wanted"; then
      printf '%s\n' "$name"
    fi
  done
}

run_leg() {
  local name="$1" out="$2"
  declare -F "leg_$name" >/dev/null || die "no leg named $name"
  in_src
  "leg_$name" "$out"
}

# What a corrupt output in a warm target folder looks like: a truncated or
# malformed archive or metadata file, or the link that reads one (main run
# 22374). A failed leg showing it wipes the target folders its log names and
# runs once more in the same job.
# shellcheck disable=SC2016 # The backticks are literal text in the linker message.
readonly CORRUPT_OUTPUT='malformed archive|truncated|Archive::children failed|invalid metadata|E0786|failed to mmap|linking with `cc` failed'

rebuild_corrupt_leg() {
  # rebuild_corrupt_leg NAME OUT LOG: succeeds only when the leg showed a
  # corrupt output in a target folder it names, and its one rebuild passed.
  # Only the named folders are wiped: the other lane may be building in its
  # own folder beside this one.
  local name="$1" out="$2" log="$3" folders folder
  grep -Eq "$CORRUPT_OUTPUT" "$log" || return 1
  folders="$(grep -oE "$work/targets/[A-Za-z0-9_-]+" "$log" | sort -u)"
  [ -n "$folders" ] || return 1
  for folder in $folders; do
    echo "build-once: the $name leg read a corrupt output in $folder; it is wiped and the leg runs once more" | tee -a "$log"
    rm -rf -- "$folder"
  done
  "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" >> "$log" 2>&1
}

run_lane() {
  # run_lane LANE OUT LOGS: the lane's wanted legs one after another, each
  # with its own log; the lane fails when any leg failed.
  local lane="$1" out="$2" logs="$3" name status=0
  while read -r name; do
    [ -n "$name" ] || continue
    "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" > "$logs/$name.log" 2>&1 ||
      rebuild_corrupt_leg "$name" "$out" "$logs/$name.log" ||
      { status=1; echo "$name" >> "$logs/failed"; }
  done < <(wanted_legs "$lane")
  return "$status"
}

build() {
  local out="$1" logs jobs pid status=0 name
  mkdir -p "$out"
  logs="$(mktemp -d "${RUNNER_TEMP:-/tmp}/build-once-logs.XXXXXX")"
  jobs="${CARGO_BUILD_JOBS:-16}"
  if [ "${BUILD_ONCE_COLD:-true}" = true ]; then
    echo 'build-once: cold build folders; every leg runs one after another'
    run_lane tests "$out" "$logs" || status=1
    run_lane checks "$out" "$logs" || status=1
  else
    CARGO_BUILD_JOBS="$(( jobs - jobs * 3 / 8 ))" run_lane tests "$out" "$logs" & pid=$!
    CARGO_BUILD_JOBS="$(( jobs * 3 / 8 ))" run_lane checks "$out" "$logs" || status=1
    wait "$pid" || status=1
  fi
  while read -r name; do
    [ -f "$logs/$name.log" ] || continue
    echo "::group::$name"; cat "$logs/$name.log"; echo '::endgroup::'
  done < <(wanted_legs)
  grep -h '^\[build-once\]' "$logs"/*.log 2>/dev/null || true
  if [ -f "$logs/failed" ]; then
    while read -r name; do
      echo "::error::the $name leg failed"
      tail -n 80 "$logs/$name.log"
    done < "$logs/failed"
  fi
  return "$status"
}

publish() {
  # Every leg output in OUT, by its SHA-256, as the job output <leg>_sha256.
  local out="$1" file name digest bytes started
  : "${ARCHIVE_STORE_URL:?ARCHIVE_STORE_URL is required}"
  for file in "$out"/*; do
    [ -f "$file" ] || continue
    name="${file##*/}"
    name="${name%%.*}"
    [[ "$name" =~ ^[a-z0-9_]+$ ]] || die "invalid leg output name: ${file##*/}"
    digest="$(sha256sum "$file" | cut -d' ' -f1)"
    bytes="$(stat -c %s "$file")"
    started=$SECONDS
    curl -fsS --retry 3 --retry-connrefused --connect-timeout 10 -o /dev/null \
      -T "$file" "$ARCHIVE_STORE_URL/v1/archives/$digest"
    echo "build-once: published $name $digest ($bytes bytes) in $((SECONDS - started)) s"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "${name}_sha256=$digest" >> "$GITHUB_OUTPUT"
    fi
  done
}

finish() {
  # Every write of this job reaches the disk before the folder is called
  # complete; a guest killed before this point leaves the marker.
  sync -f "$work"
  rm -f -- "$work/unfinished"
  sync -f "$work"
}

case "${1:-}" in
  finish) [ "$#" -eq 1 ] || die 'usage: build-once.sh finish'; finish ;;
  prepare) [ "$#" -eq 2 ] || die 'usage: build-once.sh prepare CHECKOUT'; prepare "$2" ;;
  build) [ "$#" -eq 2 ] || die 'usage: build-once.sh build OUT'; build "$2" ;;
  legs) [ "$#" -le 2 ] || die 'usage: build-once.sh legs [LANE]'; wanted_legs "${2:-}" ;;
  leg) [ "$#" -eq 3 ] || die 'usage: build-once.sh leg NAME OUT'; run_leg "$2" "$3" ;;
  publish) [ "$#" -eq 2 ] || die 'usage: build-once.sh publish OUT'; publish "$2" ;;
  *) die 'usage: build-once.sh prepare|build|legs|leg|publish|finish ...' ;;
esac
