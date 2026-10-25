#!/usr/bin/env bash
# Compile once per pull request run (infra#1632): the build half, on the pull
# request build runner, whose guest mounts its persistent build disk at
# /ci-cache and keeps it between guests and jobs.
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
#
# The build folder, under /ci-cache/pr:
# - src: a persistent clone. The job's checkout is fetched into it, so git
#   rewrites only changed files and Cargo's mtime fingerprints keep every
#   unchanged workspace crate fresh (a new checkout rebuilds them all); every
#   build also sees the same absolute workspace path. Hooks never run.
# - targets/archive and targets/clippy: the two Cargo target folders.
# - cargo-home: the registry index and downloaded crates.
# - tools: downloads of SHA-256-pinned tools, checked on every use.
# - lock-stamp: the digest of every lockfile and the toolchain file. When it
#   changes, both target folders are wiped.
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
readonly work="$cache_root/pr"
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
  local checkout commit entry stamp bin nextest_version nextest_url nextest_sha
  checkout="$(cd "$1" && pwd)"
  [ "$(git -C "$checkout" rev-parse --show-toplevel 2>/dev/null)" = "$checkout" ] ||
    die "$checkout is not a git checkout"
  if [ -z "${BUILD_ONCE_ROOT:-}" ]; then
    [ "$(stat -f -c %T "$cache_root" 2>/dev/null)" = ext2/ext3 ] ||
      die "$cache_root is not the build runner's build disk"
  fi
  : "${GITHUB_ENV:?a Forgejo job environment file is required}"
  : "${GITHUB_PATH:?a Forgejo job path file is required}"

  mkdir -p "$work"
  shopt -s dotglob nullglob
  for entry in "$cache_root"/*; do
    [ "$entry" = "$work" ] || [ "$entry" = "$cache_root/lost+found" ] || rm -rf -- "$entry"
  done
  for entry in "$work"/*; do
    case "${entry##*/}" in
      src|targets|cargo-home|tools|lock-stamp) ;;
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

  stamp="$(cd "$src" && cat Cargo.lock rust-toolchain.toml deployments/docker/*.Cargo.lock | sha256sum | cut -d' ' -f1)"
  if [ "$(cat "$work/lock-stamp" 2>/dev/null || true)" != "$stamp" ]; then
    echo 'build-once: the lockfiles or toolchain changed; the target folders are wiped'
    rm -rf -- "$work/targets"
    mkdir -p "$work/targets"
    printf '%s\n' "$stamp" > "$work/lock-stamp"
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
    echo "CARGO_BUILD_JOBS=${BUILD_ONCE_JOBS:-16}"
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

run_lane() {
  # run_lane LANE OUT LOGS: the lane's wanted legs one after another, each
  # with its own log; the lane fails when any leg failed.
  local lane="$1" out="$2" logs="$3" name status=0
  while read -r name; do
    [ -n "$name" ] || continue
    "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" > "$logs/$name.log" 2>&1 || { status=1; echo "$name" >> "$logs/failed"; }
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

case "${1:-}" in
  prepare) [ "$#" -eq 2 ] || die 'usage: build-once.sh prepare CHECKOUT'; prepare "$2" ;;
  build) [ "$#" -eq 2 ] || die 'usage: build-once.sh build OUT'; build "$2" ;;
  legs) [ "$#" -le 2 ] || die 'usage: build-once.sh legs [LANE]'; wanted_legs "${2:-}" ;;
  leg) [ "$#" -eq 3 ] || die 'usage: build-once.sh leg NAME OUT'; run_leg "$2" "$3" ;;
  publish) [ "$#" -eq 2 ] || die 'usage: build-once.sh publish OUT'; publish "$2" ;;
  *) die 'usage: build-once.sh prepare|build|legs|leg|publish ...' ;;
esac
