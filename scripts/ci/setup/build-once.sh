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
#   build-once.sh build OUT         run every wanted leg (LEGS below) at once;
#                                   each writes its test archives to
#                                   OUT/<leg>.<ext>
#   build-once.sh leg NAME OUT      run one leg
#   build-once.sh legs              list the wanted legs
#   build-once.sh publish OUT       upload every OUT/<leg>.* to the archive
#                                   store and report its SHA-256 as the job
#                                   output <leg>_sha256
#
# The build folder, /ci-cache/main or /ci-cache/pr:
# - src: a persistent clone. The job's checkout is fetched into it, so git
#   rewrites only changed files and Cargo's mtime fingerprints keep every
#   unchanged workspace crate fresh (a new checkout rebuilds them all); every
#   build also sees the same absolute workspace path. Hooks never run.
# - targets: one Cargo target folder per leg (targets/<leg>, and the local
#   VMM leg's desktop folder), so the legs build side by side without
#   waiting on each other's folder lock; any other folder there is removed.
# - cargo-home: the registry index and downloaded crates.
# - tools: downloads of SHA-256-pinned tools, checked on every use.
# - lock-stamp: the digest of every lockfile and the toolchain file, and of
#   this folder's layout version. When it changes, the target folders are
#   wiped.
# A job that was cancelled, or whose guest died, keeps its folder: Cargo
# rebuilds what it did not finish. The one thing it can leave is a truncated
# output that Cargo's fingerprint still calls fresh (main run 22374,
# "Archive::children failed: truncated or malformed archive"); the leg that
# reads one wipes the target folder its error names and rebuilds once
# (rebuild_corrupt_leg). Wiping every folder after any cancel instead cost a
# full cold build each time (main run 22574, over 30 min).
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

  # The layout version: raising it wipes every build runner's target folders
  # once (2: folders that a cancelled job may have left truncated).
  stamp="$( (echo 'build-once layout 2'; cd "$src" && cat Cargo.lock rust-toolchain.toml deployments/docker/*.Cargo.lock) | sha256sum | cut -d' ' -f1)"
  if [ "$(cat "$work/lock-stamp" 2>/dev/null || true)" != "$stamp" ]; then
    echo 'build-once: the lockfiles, toolchain or folder layout changed; the target folders are wiped'
    rm -rf -- "$work/targets"
    mkdir -p "$work/targets"
    printf '%s\n' "$stamp" > "$work/lock-stamp"
  fi
  # Only the legs' own target folders stay (the earlier layout's clippy,
  # darwin and desktop folders belong to the Rust checks job now).
  for entry in "$work/targets"/*; do
    [ -e "$entry" ] || continue
    case "${entry##*/}" in
      archive|local_vmm|local_vmm_desktop|features|database|services_control|services_runtime) ;;
      *) echo "build-once: removing the unused target folder ${entry##*/}"; rm -rf -- "$entry" ;;
    esac
  done
  # Tests stop here, before the pinned tools; never on a build runner's disk.
  if [ -n "${BUILD_ONCE_ROOT:-}" ] && [ "${BUILD_ONCE_TEST_STOP_AFTER_TARGETS:-}" = 1 ]; then
    return 0
  fi
  # Whether the archive folder is new, for the log.
  local cold=false
  [ -d "$work/targets/archive" ] || cold=true

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

# The legs: every test archive the test jobs fetch. Each line is
#   NAME WANTED
# - NAME: the leg runs leg_NAME OUT in its own target folder, targets/NAME,
#   and writes OUT/NAME.<ext>, published as the job output NAME_sha256.
# - WANTED: "always", or "selected:TOKEN[,TOKEN...]", any of those
#   verification tokens in VERIFICATION_SELECTION, or "env:NAME", an
#   environment variable that is "true".
# Every wanted leg runs at once, all taking their compilers from one
# jobserver sized to the runner (build), so the one still compiling gets the
# cores the finished ones no longer use. The checks that build no archive
# (clippy, the feature-graph and local-vmm checks, the Darwin cross-checks)
# run in their own job, Rust checks (run-rust-checks.sh).
LEGS=(
  "archive always"
  "local_vmm env:BUILD_ONCE_LOCAL_VMM"
  "features selected:rust"
  "database selected:database"
  "services_control selected:service_idp,service_coordinator,service_billing,service_connectcore"
  "services_runtime selected:service_orchestration,service_nats"
)

leg_archive() {
  # The workspace test archive: every package's tests, default features.
  local out="$1"
  phase 'test archive' env CARGO_TARGET_DIR="$work/targets/archive" \
    cargo nextest archive --locked --workspace --all-targets --archive-file "$out/archive.tar.zst"
}

# The feature-graph and local-vmm shards (run-product-verification.sh's
# RUST_SHARD_STAGE): their own list of steps decides what each leg builds.
shard_stage() {
  # shard_stage FAMILY SHARD STAGE OUT_DIR [ENV...]: one stage of one shard.
  local family="$1" shard="$2" stage="$3" dir="$4"
  shift 4
  env RUST_TRANSPORT_SHARD="$shard" RUST_SHARD_STAGE="$stage" RUST_SHARD_ARCHIVES="$dir" "$@" \
    scripts/ci/verify/run-product-verification.sh "$family"
}

# The desktop package outside the Rust selection, which Rust / transport
# verification checks separately (its artifact-selected desktop step).
artifact_desktop() {
  [ "${DESKTOP_PACKAGE_SELECTED:-}" = true ] &&
    [[ "${VERIFICATION_SELECTION:-}" != *'|rust_pkg_codewire_desktop|'* ]]
}
readonly ARTIFACT_DESKTOP_SELECTION='|valid:v3|rust_pkg_codewire_desktop|complete|'

leg_features() {
  # The feature graphs' test archives, one per package and feature set, in
  # one tar for Rust / transport feature graphs.
  local out="$1" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/features-archives.XXXXXX")"
  phase 'feature-graph archives' shard_stage rust-transport features archives "$dir" \
    CARGO_TARGET_DIR="$work/targets/features"
  tar -cf "$out/features.tar" -C "$dir" .
  rm -rf -- "$dir"
}

leg_local_vmm() {
  # The local-vmm shard's test archives (guest probe kernel fixtures, the
  # desktop) and the DERP server it runs the DERP contract against, in one
  # tar for Rust / transport verification.
  local out="$1" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/local-vmm-archives.XXXXXX")"
  if [[ "${VERIFICATION_SELECTION:-}" == *'|rust|'* || "${VERIFICATION_SELECTION:-}" == *'|transport|'* ]]; then
    phase 'local-vmm archives' shard_stage rust-transport local-vmm archives "$dir" \
      CARGO_TARGET_DIR="$work/targets/local_vmm" \
      CODEWIRE_DESKTOP_CARGO_TARGET_DIR="$work/targets/local_vmm_desktop"
  fi
  if artifact_desktop; then
    phase 'desktop archive' shard_stage rust local-vmm archives "$dir" \
      VERIFICATION_SELECTION="$ARTIFACT_DESKTOP_SELECTION" \
      CARGO_TARGET_DIR="$work/targets/local_vmm" \
      CODEWIRE_DESKTOP_CARGO_TARGET_DIR="$work/targets/local_vmm_desktop"
  fi
  tar -cf "$out/local_vmm.tar" -C "$dir" .
  rm -rf -- "$dir"
}

leg_database() {
  # The database suites' archives, one per package and feature set, built by
  # run-integration-verification.sh from its own suite list, with the
  # CI-profile migration runner; bundled into one tar.
  local out="$1" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/database-archives.XXXXXX")"
  phase 'database archives' env CARGO_TARGET_DIR="$work/targets/database" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$work/targets/database" ARCHIVE_BUILD_DIR="$dir" \
    scripts/ci/verify/run-integration-verification.sh database-archives
  tar -cf "$out/database.tar" -C "$dir" .
  rm -rf -- "$dir"
}

service_plane_leg() {
  # service_plane_leg PLANE OUT: one service plane's archives, one per
  # package and feature set, and the binaries the plane starts, built by
  # run-integration-verification.sh from its own service lists; bundled into
  # one tar. The leg runs when the plane's service tokens are selected, as
  # the plane's job does (ci.yaml, its service scope step).
  local plane="$1" out="$2" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/services-$plane-archives.XXXXXX")"
  phase "services $plane archives" env CARGO_TARGET_DIR="$work/targets/services_$plane" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$work/targets/services_$plane" ARCHIVE_BUILD_DIR="$dir" \
    scripts/ci/verify/run-integration-verification.sh "services-$plane-archives"
  # The binaries shrink about threefold (the archives are compressed
  # already), which the archive store's budget needs: the plane's job unpacks
  # binaries.tar.gz beside the archives.
  local -a binaries
  mapfile -t binaries < <(find "$dir" -maxdepth 1 -type f ! -name '*.tar.zst' -printf '%f\n' | sort)
  [ "${#binaries[@]}" -gt 0 ] || die "the services $plane leg kept no binaries"
  tar -cf - -C "$dir" -- "${binaries[@]}" | gzip -1 > "$dir.binaries.tar.gz"
  (cd "$dir" && rm -f -- "${binaries[@]}")
  mv -- "$dir.binaries.tar.gz" "$dir/binaries.tar.gz"
  tar -cf "$out/services_$plane.tar" -C "$dir" .
  rm -rf -- "$dir"
}

leg_services_control() { service_plane_leg control "$1"; }
leg_services_runtime() { service_plane_leg runtime "$1"; }

leg_wanted() {
  case "$1" in
    always) return 0 ;;
    selected:*)
      # selected:A,B: any of the tokens.
      local token
      local -a tokens
      IFS=, read -r -a tokens <<< "${1#selected:}"
      for token in "${tokens[@]}"; do
        [[ "${VERIFICATION_SELECTION:-}" != *"|$token|"* ]] || return 0
      done
      return 1
      ;;
    env:*)
      local var="${1#env:}"
      [[ "$var" =~ ^[A-Z_][A-Z0-9_]*$ ]] || die "invalid leg condition: $1"
      [ "${!var:-}" = true ]
      ;;
    *) die "unknown leg condition: $1" ;;
  esac
}

wanted_legs() {
  # wanted_legs: the names of the wanted legs, in table order.
  local entry name wanted
  for entry in "${LEGS[@]}"; do
    read -r name wanted <<< "$entry"
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
  # Only the named folders are wiped: the other legs build in their own
  # folders beside this one.
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

run_one_leg() {
  # run_one_leg NAME OUT LOGS: one leg with its own log, rebuilt once when it
  # read a corrupt output; a failed leg is listed in LOGS/failed.
  local name="$1" out="$2" logs="$3"
  "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" > "$logs/$name.log" 2>&1 ||
    rebuild_corrupt_leg "$name" "$out" "$logs/$name.log" ||
    { echo "$name" >> "$logs/failed"; return 1; }
}

run_legs() {
  # run_legs OUT LOGS: every wanted leg at once, under the jobserver build
  # started; it fails when any leg failed.
  local out="$1" logs="$2" name pid status=0
  local -a pids=()
  while read -r name; do
    [ -n "$name" ] || continue
    run_one_leg "$name" "$out" "$logs" & pids+=("$!")
  done < <(wanted_legs)
  for pid in "${pids[@]}"; do
    wait "$pid" || status=1
  done
  return "$status"
}

jobserver_tokens() {
  # The compilers the runner holds: its cores, and one per 2 GiB of available
  # memory (the archive build alone peaked at 25.4 GiB with 16 compilers).
  # BUILD_ONCE_JOBSERVER_TOKENS overrides it.
  if [ -n "${BUILD_ONCE_JOBSERVER_TOKENS:-}" ]; then
    printf '%s\n' "$BUILD_ONCE_JOBSERVER_TOKENS"
    return
  fi
  local tokens available_kib by_memory
  tokens="$(nproc)"
  available_kib="$(awk '$1 == "MemAvailable:" {print $2}' /proc/meminfo)"
  by_memory=$(( available_kib / (2 * 1024 * 1024) ))
  if (( by_memory < tokens )); then tokens="$by_memory"; fi
  if (( tokens < 2 )); then tokens=2; fi
  if (( tokens > 64 )); then tokens=64; fi
  printf '%s\n' "$tokens"
}

build() {
  local out="$1" logs tokens status=0 name
  mkdir -p "$out"
  logs="$(mktemp -d "${RUNNER_TEMP:-/tmp}/build-once-logs.XXXXXX")"
  tokens="$(jobserver_tokens)"
  [[ "$tokens" =~ ^[1-9][0-9]*$ ]] || die "invalid jobserver size: $tokens"
  [ "${BUILD_ONCE_COLD:-false}" = false ] || echo 'build-once: cold build folders'
  echo "build-once: legs $(wanted_legs | tr '\n' ' ')at once, $tokens compilers in all"
  # A Cargo that cannot reach the jobserver falls back to these few jobs.
  CARGO_BUILD_JOBS=4 python3 "$ROOT/scripts/ci/setup/jobserver.py" "$tokens" -- \
    "$ROOT/scripts/ci/setup/build-once.sh" run-legs "$out" "$logs" || status=1
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
  legs) [ "$#" -eq 1 ] || die 'usage: build-once.sh legs'; wanted_legs ;;
  run-legs) [ "$#" -eq 3 ] || die 'usage: build-once.sh run-legs OUT LOGS'; run_legs "$2" "$3" ;;
  leg) [ "$#" -eq 3 ] || die 'usage: build-once.sh leg NAME OUT'; run_leg "$2" "$3" ;;
  publish) [ "$#" -eq 2 ] || die 'usage: build-once.sh publish OUT'; publish "$2" ;;
  *) die 'usage: build-once.sh prepare|build|legs|leg|run-legs|publish ...' ;;
esac
