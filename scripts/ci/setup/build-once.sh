#!/usr/bin/env bash
# Compile once per run (infra#1632): the build half, on a build runner, whose
# guest mounts its persistent build disk at /ci-cache and keeps it between
# guests and jobs. A push to main runs on the main build runner and every
# other run on a pull request build runner, both in /ci-cache/build
# (build-once-tree.sh), so their compiler cache keys match (#5146). Each disk
# records the kind that builds on it (/ci-cache/.build-once-kind), and a run
# of the other kind is refused, so a job never builds on, or clears, the
# other kind's runner. That check is advisory, since a pull request can
# change this script; the runners' labels and the archive stores' admission
# keep the kinds apart.
#
#   build-once.sh prepare CHECKOUT build|checks
#                                   bring the warm build folder to this job's
#                                   commit and set up the pinned tools; build
#                                   or checks names the target folders the
#                                   job is about to use, which the disk bound
#                                   never removes (bound_targets)
#   build-once.sh build OUT         run every wanted leg (LEGS below) at once;
#                                   each writes its test archives to
#                                   OUT/<leg>.<ext>; with BUILD_ONCE_CHECKS=true
#                                   (every CI run) the Rust checks run beside
#                                   them, under the same jobserver
#   build-once.sh leg NAME OUT      run one leg
#   build-once.sh legs              list the wanted legs
#   build-once.sh publish OUT       upload every OUT/<leg>.* to the archive
#                                   store and report its SHA-256 as the job
#                                   output <leg>_sha256
#   build-once.sh finish            put this job's writes on disk, then remove
#                                   the mark prepare left (job-running); runs
#                                   whether the build passed, failed or was
#                                   cancelled
#   build-once.sh checks            run the Rust checks (run-rust-checks.sh)
#                                   at once under one jobserver, each in its
#                                   own target folder, within build
#
# The build folder, /ci-cache/build:
# - src: a persistent clone. The job's checkout is fetched into it, so git
#   rewrites only changed files and Cargo's mtime fingerprints keep every
#   unchanged workspace crate fresh (a new checkout rebuilds them all); every
#   build also sees the same absolute workspace path. Hooks never run.
# - targets: one Cargo target folder per leg (targets/<leg>, and the local
#   VMM leg's desktop folder), so the legs build side by side without
#   waiting on each other's folder lock, and the Rust checks' own
#   (CHECK_FOLDERS); any other folder there is removed. A leg whose builds
#   run in batches at once (the database and service-plane legs,
#   run-integration-verification.sh compile_batches, and the features leg,
#   run-product-verification.sh build_shard_archive_batches) keeps each batch but
#   its first in a folder of its own inside the leg's, targets/<leg>/batch-*,
#   which goes and stays with the leg's folder. Each folder's
#   .build-once-used mark names the last run that used it (GITHUB_RUN_ID),
#   and its time orders the disk bound's removals (bound_targets).
# - cargo-home: the registry index and downloaded crates.
# - tools: downloads of SHA-256-pinned tools, checked on every use.
# - layout: the folder's layout version. Raising it wipes the target folders
#   once. Nothing else does: a lockfile or toolchain change leaves them to
#   Cargo, whose fingerprints rebuild exactly the units it changed (a wipe
#   on every lockfile change cost a 27-33 min cold build; CI compute audit,
#   row 1). Builds are not incremental: each leg builds many feature
#   variants, and their incremental sessions held about 35 GB of slot 61's
#   120 GB disk and filled it mid-build (main run 22822), so prepare removes
#   any that remain.
# A job that was cancelled, or whose guest died, keeps its folder: Cargo
# rebuilds what it did not finish. The one thing it can leave is a truncated
# output that Cargo's fingerprint still calls fresh (main run 22374,
# "Archive::children failed: truncated or malformed archive"); the leg that
# reads one wipes the target folder its error names and rebuilds once
# (rebuild_corrupt_leg). Wiping every folder after any cancel instead cost a
# full cold build each time (main run 22574, over 30 min).
# A dead guest can also leave an output no compiler ever reads: a test binary
# of the right size whose start is zeros, which Cargo calls fresh and the
# archive then carries (run 30126, "Exec format error"). So prepare writes
# job-running, on disk before any compiler starts, and finish removes it once
# the job's writes are on disk. A prepare that finds one deletes only the files
# newer than it, under targets and cargo-home: exactly what the interrupted
# job wrote. Cargo rebuilds those; everything else stays warm.
# Anything else under /ci-cache is removed first: a previous job could have
# left Cargo configuration in a parent directory of src. The guest itself
# wipes the whole folder weekly (infra dispatcher, metal_build_disk_prelude).
#
# Every build here, the legs' and the Rust checks', writes no debug
# information (CARGO_PROFILE_DEV_DEBUG=0; 2026-11-16, infra#1534). Nothing in
# CI read the line tables these builds kept until then (#3093): no job sets
# RUST_BACKTRACE, and a panic's file and line come from the location compiled
# into the code. The workspace archive's binaries lost them after the build
# anyway, since the archive store needs that archive small (infra#2471: at
# 2.4 GB it outran the store under load): a strip-and-repack step (#4312)
# took 121-160 s of a 291-342 s archive leg to cut 2.6 GB to 0.9 GB. They
# are no longer written, so nothing is stripped, the archive is the one
# cargo-nextest writes, and every target folder holds less (193 MB of the
# 502 MB cw test binary was debug sections, #4312). Builds outside this
# folder keep line tables, local-rust-cache.sh's default: the workstation's
# and the other CI jobs', such as a test job's own build after an archive
# miss. They share no cache with these builds, which use no compiler cache
# (in_src) unless their runner turns on the build disk's own (sccache_on).
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
kind="$(build_once_kind)"
readonly kind
if [ "$kind" = main ]; then other_kind='pr'; else other_kind='main'; fi
readonly other_kind
# The kind that builds on this disk, written by its first prepare.
readonly kind_file="$cache_root/.build-once-kind"
readonly src="$work/src"
# A compiler cache on the build disk, shared by every leg, when the runner
# sets CODEWIRE_BUILD_ONCE_SCCACHE=local: a canary on one pull request build
# VM (#5146), whose traces are compared with the other's. It has the target
# folders' trust: only the next build on the same runner reads what this one
# wrote, as with their warm targets, and nothing reaches a remote or protected
# cache (infra docs/ci/runners.md, section 7). Unset or off, nothing is
# cached and prepare removes the folder.
readonly sccache_dir="$work/sccache"
readonly sccache_bin="${BUILD_ONCE_SCCACHE_BIN:-/usr/local/bin/sccache}"
case "${CODEWIRE_BUILD_ONCE_SCCACHE:-off}" in
  off|local) ;;
  *)
    echo "build-once: CODEWIRE_BUILD_ONCE_SCCACHE is off or local, not ${CODEWIRE_BUILD_ONCE_SCCACHE}" >&2
    exit 2
    ;;
esac
sccache_on() { [ "${CODEWIRE_BUILD_ONCE_SCCACHE:-off}" = local ]; }
# The Rust checks' target folders (checks), one per check, since they run at
# once and Cargo locks a target folder for a whole build: clippy for
# compile-all-targets, clippy_features for the feature-graph checks, darwin
# for the local-vmm checks, darwin_cw for the cw Darwin cross-check, desktop
# for the desktop check and package. A new folder is cold on its first run
# on each build runner. The Rust SDK packages in its own job (infra#1534), so
# a build runner's old sdk_package folder is removed as any unlisted one.
readonly CHECK_FOLDERS=(clippy clippy_features darwin darwin_cw desktop)
# Each leg's epoch. Raising a leg's number wipes only that leg's target folder,
# once on each build runner, through this reviewed code rather than a hand in
# a guest. The number is kept in a file inside the leg's own folder, which a
# head without this code leaves alone; a pull request builds with its own
# head's copy of this script, so a change every runner had to agree on, such
# as the layout version, would make old and new heads wipe each other's
# folders in turn. archive 1: one PR build runner's archive folder held 165 GB
# on 2026-11-16, three times the other's, because no disk bound takes a live
# leg's folder (bound_targets).
declare -A LEG_EPOCHS=([archive]=1)
readonly LEG_EPOCHS
readonly LEG_EPOCH_FILE=.build-once-epoch

check_folder() {
  # check_folder NAME: whether NAME is one of the Rust checks' folders.
  local folder
  for folder in "${CHECK_FOLDERS[@]}"; do
    [ "$folder" != "$1" ] || return 0
  done
  return 1
}

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

merge_onto_base() {
  # merge_onto_base HEAD CHECKOUT: the persistent clone at HEAD merged onto
  # BUILD_ONCE_MERGE_ONTO, the base tip selection checked (merge-onto-base.sh,
  # #5146), so the warm folder follows the base branch and a build compiles
  # little more than the pull request's own change. A merge build's checkout
  # has the whole history (ci.yaml), so the clone fetches the head and the
  # base branch from it, with no credential of its own; after its first merge
  # build the clone has the base branch's history and later fetches are small.
  # The commit is made with merge-identity.sh's fixed identity, so the same
  # inputs give the same commit, and it must give the tree selection checked.
  local head="$1" checkout="$2" tip="${BUILD_ONCE_MERGE_ONTO}" tree="${BUILD_ONCE_MERGED_TREE:-}"
  local base="${BUILD_ONCE_BASE_REF:-}"
  [[ "$tip" =~ ^[0-9a-f]{40}$ && "$tree" =~ ^[0-9a-f]{40}$ && "$base" =~ ^[A-Za-z0-9._/-]+$ ]] ||
    die 'BUILD_ONCE_MERGE_ONTO, BUILD_ONCE_MERGED_TREE and BUILD_ONCE_BASE_REF must all be set and valid'
  [ ! -f "$checkout/.git/shallow" ] || die 'a merge build needs a checkout with its whole history'
  local -a fetch=("${git_src[@]}" fetch -q --no-tags)
  [ ! -f "$src/.git/shallow" ] || fetch+=(--unshallow)
  "${fetch[@]}" "$checkout" "+HEAD:refs/ci/pull-head" "+refs/remotes/origin/$base:refs/ci/base" ||
    die 'the persistent clone could not fetch the head and its base branch from the checkout'
  [ "$("${git_src[@]}" rev-parse refs/ci/pull-head)" = "$head" ] || die 'the fetch did not bring the head'
  "${git_src[@]}" merge-base --is-ancestor "$tip" refs/ci/base || die "${tip:0:12} is not on $base"
  # shellcheck source=scripts/ci/setup/merge-identity.sh
  source "$ROOT/scripts/ci/setup/merge-identity.sh"
  ci_merge_commit_env "$head" "$tip"
  "${git_src[@]}" checkout -q --force --detach "$tip"
  # Signing would make the commit differ wherever it is made.
  "${git_src[@]}" -c commit.gpgSign=false merge -q --no-ff --no-edit -m "$CI_MERGE_MESSAGE" "$head" ||
    die "the head does not merge onto ${tip:0:12} here, though selection found it clean"
  [ "$("${git_src[@]}" rev-parse 'HEAD^{tree}')" = "$tree" ] ||
    die 'the merge gives another tree than selection checked'
  echo "build-once: building the head ${head:0:12} merged onto $base ${tip:0:12} ($("${git_src[@]}" rev-parse --short=12 HEAD))"
}

prepare() {
  local checkout commit entry bin nextest_version nextest_url nextest_sha share job="$2"
  case "$job" in build|checks) ;; *) die "prepare is for the build or the checks job, not: $job" ;; esac
  checkout="$(cd "$1" && pwd)"
  [ "$(git -C "$checkout" rev-parse --show-toplevel 2>/dev/null)" = "$checkout" ] ||
    die "$checkout is not a git checkout"
  if [ -z "${BUILD_ONCE_ROOT:-}" ]; then
    [ "$(stat -f -c %T "$cache_root" 2>/dev/null)" = ext2/ext3 ] ||
      die "$cache_root is not the build runner's build disk"
  fi
  # Before #5146 each kind built in its own folder, ROOT/main or ROOT/pr; a
  # disk holding the other kind's, or recording it, is refused.
  [ ! -e "$cache_root/$other_kind" ] ||
    die "this build disk holds $cache_root/$other_kind; a $kind run does not build here"
  if [ -f "$kind_file" ] && [ "$(cat "$kind_file")" != "$kind" ]; then
    die "this build disk is the $(cat "$kind_file") runner's ($kind_file); a $kind run does not build here"
  fi
  # The workflow names the same folder for its later steps.
  [ -z "${BUILD_ONCE_TREE:-}" ] || [ "$BUILD_ONCE_TREE" = "$work" ] ||
    die "BUILD_ONCE_TREE=$BUILD_ONCE_TREE, but this run builds in $work"
  : "${GITHUB_ENV:?a Forgejo job environment file is required}"
  # The build runner's share of the host (cpu-share.sh) sets the Cargo jobs.
  # shellcheck source=scripts/ci/setup/cpu-share.sh
  source "$ROOT/scripts/ci/setup/cpu-share.sh"
  share="$(ci_cpu_share)"
  : "${GITHUB_PATH:?a Forgejo job path file is required}"

  # The folder this kind built in before #5146 becomes the build folder: its
  # clone, Cargo home and tools carry over, its targets do not. Cargo calls a
  # moved target fresh, but what it compiled keeps the old path
  # (env!("CARGO_MANIFEST_DIR"), CARGO_BIN_EXE_*), so the tests would look for
  # their fixtures under a folder the test jobs never create. The first build
  # after the move is cold, once per disk.
  if [ -d "$cache_root/$kind" ] && [ ! -e "$work" ]; then
    mv -- "$cache_root/$kind" "$work"
    rm -rf -- "$work/targets"
    echo "build-once: the build folder moved from $cache_root/$kind to $work; its targets, which name the old path, are dropped"
  fi
  mkdir -p "$work"
  printf '%s\n' "$kind" > "$kind_file.new"
  mv -f -- "$kind_file.new" "$kind_file"
  remove_interrupted_writes
  shopt -s dotglob nullglob
  for entry in "$cache_root"/*; do
    [ "$entry" = "$work" ] || [ "$entry" = "$kind_file" ] || [ "$entry" = "$cache_root/lost+found" ] ||
      rm -rf -- "$entry"
  done
  for entry in "$work"/*; do
    case "${entry##*/}" in
      src|targets|cargo-home|tools|layout|job-running) ;;
      sccache) sccache_on || rm -rf -- "$entry" ;;
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
  if [ -n "${BUILD_ONCE_MERGE_ONTO:-}" ]; then
    merge_onto_base "$commit" "$checkout"
    commit="$("${git_src[@]}" rev-parse HEAD)"
  else
    # The checkout is shallow; its root may move the clone's shallow boundary.
    "${git_src[@]}" fetch -q --no-tags --update-shallow "$checkout" HEAD
    [ "$("${git_src[@]}" rev-parse FETCH_HEAD)" = "$commit" ] || die 'the fetch did not bring the commit'
    "${git_src[@]}" checkout -q --force --detach "$commit"
  fi
  "${git_src[@]}" clean -q -ffdx
  [ "$("${git_src[@]}" rev-parse HEAD)" = "$commit" ] || die 'the persistent clone is not at the commit'

  # The layout version: raising it wipes every build runner's target folders
  # once (2: folders that a cancelled job may have left truncated). A folder
  # with no layout file yet (the lock-stamp layout before it) keeps its
  # targets.
  local layout=2
  if [ -f "$work/layout" ] && [ "$(cat "$work/layout")" != "$layout" ]; then
    echo 'build-once: the folder layout changed; the target folders are wiped'
    rm -rf -- "$work/targets"
    mkdir -p "$work/targets"
  fi
  printf '%s\n' "$layout" > "$work/layout"
  # Only the legs' and the Rust checks' own target folders stay.
  for entry in "$work/targets"/*; do
    [ -e "$entry" ] || continue
    case "${entry##*/}" in
      archive|local_vmm|local_vmm_desktop|features|database|services_control|services_runtime) ;;
      *)
        if ! check_folder "${entry##*/}"; then
          echo "build-once: removing the unused target folder ${entry##*/}"
          rm -rf -- "$entry"
        fi
        ;;
    esac
  done
  bound_targets "$job"
  # After the bound, so a folder it removed is started again with its epoch.
  local leg recorded
  for leg in "${!LEG_EPOCHS[@]}"; do
    { read -r recorded <"$work/targets/$leg/$LEG_EPOCH_FILE"; } 2>/dev/null || recorded=
    [ "$recorded" != "${LEG_EPOCHS[$leg]}" ] || continue
    if [ -d "$work/targets/$leg" ]; then
      echo "build-once: the $leg leg's epoch is now ${LEG_EPOCHS[$leg]}; its target folder is wiped"
      rm -rf -- "$work/targets/$leg"
    fi
    mkdir -p "$work/targets/$leg"
    printf '%s\n' "${LEG_EPOCHS[$leg]}" >"$work/targets/$leg/$LEG_EPOCH_FILE"
  done
  mark_job_running
  # Tests stop here, before the pinned tools; never on a build runner's disk.
  if [ -n "${BUILD_ONCE_ROOT:-}" ] && [ "${BUILD_ONCE_TEST_STOP_AFTER_TARGETS:-}" = 1 ]; then
    return 0
  fi
  # Whether the archive folder is new, for the log.
  # (An archive folder that holds only its epoch file is new.)
  local cold=false
  if ! find "$work/targets/archive" -mindepth 1 -maxdepth 1 ! -name "$LEG_EPOCH_FILE" -print -quit 2>/dev/null | grep -q .; then
    cold=true
  fi

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
  if sccache_on; then
    [ -x "$sccache_bin" ] || die "the compiler cache is on, but $sccache_bin is not in the job image"
    "$sccache_bin" --version
  fi

  {
    echo "BUILD_ONCE_SRC=$src"
    echo "CARGO_HOME=$work/cargo-home"
    echo 'CARGO_PROFILE_DEV_DEBUG=0'
    echo 'CARGO_INCREMENTAL=0'
    echo "CARGO_BUILD_JOBS=${BUILD_ONCE_JOBS:-${share:-16}}"
    echo 'CODEWIRE_LOCAL_RUST_CACHE=off'
    echo 'CARGO_TERM_COLOR=never'
    echo "BUILD_ONCE_COLD=$cold"
    if sccache_on; then
      echo "SCCACHE_DIR=$sccache_dir"
      echo "SCCACHE_CACHE_SIZE=${BUILD_ONCE_SCCACHE_SIZE:-40G}"
    fi
  } >> "$GITHUB_ENV"
  {
    echo "$bin/protoc/bin"
    echo "$bin"
  } >> "$GITHUB_PATH"
  echo "build-once: $src is at $commit; targets $(du -sh "$work/targets" | cut -f1); cold=$cold"
}

remove_interrupted_writes() {
  # A job that never reached finish: delete what it wrote (see job-running in
  # the header). Its mark's time is when it started writing.
  local mark="$work/job-running" count
  local -a roots=()
  [ -f "$mark" ] || return 0
  [ ! -d "$work/targets" ] || roots+=("$work/targets")
  [ ! -d "$work/cargo-home" ] || roots+=("$work/cargo-home")
  [ ! -d "$sccache_dir" ] || roots+=("$sccache_dir")
  count=0
  if [ "${#roots[@]}" -gt 0 ]; then
    count="$(find "${roots[@]}" -type f -newer "$mark" | wc -l)"
    find "${roots[@]}" -type f -newer "$mark" -delete
  fi
  rm -f -- "$mark"
  echo "build-once: the last job here did not finish (cancelled, or its guest died); deleted the $count files it wrote, which Cargo rebuilds"
}

mark_job_running() {
  # On disk before any compiler starts, so no output can outlive its mark.
  local mark="$work/job-running"
  : > "$mark.new"
  mv -f -- "$mark.new" "$mark"
  sync -f "$work"
}

finish() {
  # The writes reach the disk before the mark goes, and its removal after them,
  # so a missing mark always means this job's outputs are durable.
  local mark="$work/job-running" started=$SECONDS
  [ -f "$mark" ] || return 0
  sync -f "$work"
  rm -f -- "$mark"
  sync -f "$work"
  echo "build-once: this job's writes are on disk; sync took $((SECONDS - started)) s"
}

disk_usage() {
  # The build disk's use in percent, its used KiB and its size in KiB, as df
  # reports them; tests name another df.
  "${BUILD_ONCE_DF:-df}" -P "$cache_root" | awk 'NR == 2 { sub("%", "", $5); print $5, $3, $2 }'
}

mark_used() {
  # mark_used FOLDER: this run uses FOLDER. The mark's time orders
  # bound_targets' removals; its content names the run.
  mkdir -p "$1"
  printf '%s\n' "${GITHUB_RUN_ID:-}" > "$1/.build-once-used"
}

job_folders() {
  # job_folders build|checks: the target folders the job is about to use,
  # the wanted legs or the Rust checks' folders, and both for a build that
  # runs the checks beside its legs (BUILD_ONCE_CHECKS). A leg's desktop
  # folder goes and stays with its leg.
  case "$1" in
    build)
      wanted_legs
      if [ "${BUILD_ONCE_CHECKS:-}" = true ]; then printf '%s\n' "${CHECK_FOLDERS[@]}"; fi
      ;;
    checks) printf '%s\n' "${CHECK_FOLDERS[@]}" ;;
  esac
}

bound_targets() {
  # bound_targets build|checks: nothing else bounds the target folders: each
  # leg keeps its own, and a lockfile change no longer wipes them. Above
  # BUILD_ONCE_DISK_PERCENT (65) of the build disk, whole folders go, one at
  # a time, until the disk is back under it:
  # 1. Idle folders, least recently used first: those neither this run nor
  #    the run before it on this disk used (by their marks; a folder with no
  #    run in its mark is idle).
  # 2. When only live folders are left and the disk is still over the bound,
  #    the disk is too small for one run's folders, which is logged with the
  #    size it needs. Live folders then stay, over the bound, until the disk
  #    passes BUILD_ONCE_DISK_LIVE_PERCENT (80); past it the least recently
  #    used live folder goes. Removing a live folder makes the next run build
  #    it cold (main run 24440 removed the archive folder its own build had
  #    just filled at 71%, and the next archive leg took 780 s against 165 s
  #    warm), while a disk over the bound costs nothing until it fills. The
  #    guest wipes the whole folder at 85% (main run 22737: "build folder
  #    wiped: disk 93% used"), which makes every leg cold, so live folders go
  #    before that.
  # 3. A folder this job is about to use never goes (pull request run 24177
  #    removed the archive folder its build was about to use), unless:
  # 4. Past BUILD_ONCE_DISK_FULL_PERCENT (90) with only this job's own folders
  #    left, this run's compile would fill the disk and fail the run (pull
  #    request run 44254: its own folders at 91% of a 235 GB disk before the
  #    build, then "No space left on device" in seven legs at once). This
  #    job's largest folders go then, so those legs build cold, until the disk
  #    is back at or under it. A cold leg costs minutes; a full disk, the run.
  local job="$1" limit="${BUILD_ONCE_DISK_PERCENT:-65}" ceiling="${BUILD_ONCE_DISK_LIVE_PERCENT:-80}"
  local full="${BUILD_ONCE_DISK_FULL_PERCENT:-90}"
  local current="${GITHUB_RUN_ID:-}" previous used used_kib size_kib folder name run swept table warned=false
  local -a idle=() live=()
  local -A uses=()
  # Incremental sessions from the builds that were incremental (#3454).
  find "$work/targets" -xdev -mindepth 3 -maxdepth 3 -type d -name incremental \
    -exec rm -rf -- {} + 2>/dev/null || true
  # First the units no build has read for BUILD_ONCE_SWEEP_DAYS (3): stale
  # artifacts of crates and lockfile versions since replaced, and old
  # incremental sessions. The disk is mounted relatime, so every build that
  # reads an artifact keeps it fresh (cargo-sweep's own signal). A swept unit
  # a later build needs is rebuilt by Cargo.
  #
  # A build script's directory (build/<unit>) is one unit, swept whole. Cargo
  # reads its run's `output` record on every build, but the files the script
  # generated in out/ only when its own crate compiles. A per-file sweep could
  # take out/ and keep the record, and Cargo would then compile the crate
  # without its generated sources, since the script's run still looks fresh
  # (main run 32717, after run 32706's sweep: thiserror's out/private.rs). So
  # such a directory goes, with its fingerprint, only when none of its files
  # was read in the period. One that a per-file sweep already damaged goes the
  # same way, so Cargo runs its script again: it has `output` but no out/, or
  # no invoked.timestamp, which Cargo writes on every run of the script and
  # only a sweep removes. The second catches the out/ that Cargo recreates
  # empty after such a sweep (#3869: a pull request branched before #3850 ran
  # the per-file sweep on the shared cache, and thiserror lost private.rs).
  local days="${BUILD_ONCE_SWEEP_DAYS:-3}" unit units=0
  local -a build_units=()
  local -A read_units=()
  # The build-script patterns start below targets: the build folder is itself
  # named build (/ci-cache/build, #5146).
  swept="$(find "$work/targets" -xdev -type f -atime +"$(( days - 1 ))" -not -path "$work/targets/*/build/*" \
    -print -delete 2>/dev/null | wc -l)"
  # Each build/<unit> directory, by the first build/ under a profile. A unit
  # was read when any file under it was: one find, started at every unit,
  # prints the start (%H) each read file is under, so no unit forks its own
  # and a nested build/ under out/ is never mistaken for a unit.
  mapfile -d '' build_units < <(find "$work/targets" -xdev -mindepth 2 -type d -path "$work/targets/*/build/*" \
    -prune -print0 2>/dev/null)
  if [ "${#build_units[@]}" -gt 0 ]; then
    # shellcheck disable=SC2016 # the inner sh expands $0 and $@
    while IFS= read -r -d '' unit; do
      read_units[$unit]=1
    done < <(printf '%s\0' "${build_units[@]}" |
      xargs -0 -r sh -c 'find "$@" -type f -atime -"$0" -printf "%H\0"' "$days" 2>/dev/null | sort -zu)
  fi
  for unit in "${build_units[@]}"; do
    if { [ -f "$unit/output" ] && { [ ! -d "$unit/out" ] || [ ! -f "$unit/invoked.timestamp" ]; }; } ||
      [ -z "${read_units[$unit]:-}" ]; then
      rm -rf -- "$unit" "${unit%/build/*}/.fingerprint/${unit##*/}"
      units=$(( units + 1 ))
    fi
  done
  find "$work/targets" -xdev -mindepth 2 -type d -empty -not -path "$work/targets/*/build/*" -delete 2>/dev/null || true
  [ "$swept" -eq 0 ] || echo "build-once: removed $swept target files no build read for $days days"
  [ "$units" -eq 0 ] ||
    echo "build-once: removed $units build-script units no build read for $days days or left without out/ or invoked.timestamp"
  read -r used used_kib size_kib < <(disk_usage) || true
  [[ "$used" =~ ^[0-9]+$ && "$used_kib" =~ ^[0-9]+$ && "$size_kib" =~ ^[0-9]+$ ]] ||
    die "cannot read the build disk's use: ${used:-nothing}"
  (( used > limit )) || return 0
  while read -r name; do
    [ -z "$name" ] || uses[$name]=1
  done < <(job_folders "$job")
  # Each folder's mark time, its run (- for none) and its name, least
  # recently used first.
  table="$(for folder in "$work/targets"/*; do
      [ -d "$folder" ] || continue
      case "${folder##*/}" in *_desktop) continue ;; esac
      run="$(head -n 1 "$folder/.build-once-used" 2>/dev/null || true)"
      [[ "$run" =~ ^[0-9]+$ ]] || run=-
      printf '%s %s %s\n' "$(stat -c %Y "$folder/.build-once-used" 2>/dev/null || echo 0)" "$run" "${folder##*/}"
    done | sort -k1,1n -k3,3)"
  # The run before this one: the latest mark of another run.
  previous="$(awk -v current="$current" '$2 != "-" && $2 != current { run = $2 } END { print run }' <<< "$table")"
  while read -r _ run name; do
    [ -n "$name" ] && [ -z "${uses[$name]:-}" ] || continue
    if [ "$run" != - ] && { [ "$run" = "$current" ] || [ "$run" = "$previous" ]; }; then
      live+=("$name")
    else
      idle+=("$name")
    fi
  done <<< "$table"
  while (( used > limit )); do
    if (( ${#idle[@]} > 0 )); then
      name="${idle[0]}"
      idle=("${idle[@]:1}")
      echo "build-once: disk ${used}% used (limit ${limit}%); removing the least recently used idle target folder $name"
    else
      if [ "$warned" = false ]; then
        warned=true
        echo "::warning::build-once: disk too small: $(awk -v k="$used_kib" -v l="$limit" \
          'BEGIN { n = k * 1024 * 100 / l / 1e9; printf "%d", (n > int(n)) ? int(n) + 1 : n }') GB needed to keep this run's and the previous run's target folders under the ${limit}% bound; the $(awk -v k="$size_kib" 'BEGIN { printf "%d", k * 1024 / 1e9 }') GB disk is ${used}% used. They stay over the bound up to ${ceiling}%."
      fi
      (( used > ceiling )) || break
      if (( ${#live[@]} == 0 )); then
        echo "build-once: disk ${used}% used with no target folder left that this job does not use"
        break
      fi
      name="${live[0]}"
      live=("${live[@]:1}")
      echo "build-once: disk ${used}% used, over ${ceiling}%; removing the least recently used live target folder $name, which this job does not use"
    fi
    rm -rf -- "$work/targets/$name" "$work/targets/${name}_desktop"
    read -r used used_kib size_kib < <(disk_usage) || true
    [[ "$used" =~ ^[0-9]+$ && "$used_kib" =~ ^[0-9]+$ ]] || die "cannot read the build disk's use: ${used:-nothing}"
  done
  # Rule 4: this job's own folders, largest first.
  (( used > full )) || return 0
  while read -r _ name; do
    [ -n "$name" ] || continue
    (( used > full )) || break
    echo "::warning::build-once: disk ${used}% used, over ${full}%, with only this job's folders left; removing its largest, $name, which builds cold"
    rm -rf -- "$work/targets/$name" "$work/targets/${name}_desktop"
    read -r used used_kib size_kib < <(disk_usage) || true
    [[ "$used" =~ ^[0-9]+$ && "$used_kib" =~ ^[0-9]+$ ]] || die "cannot read the build disk's use: ${used:-nothing}"
  done < <(for name in "${!uses[@]}"; do
      [ -d "$work/targets/$name" ] || continue
      printf '%s %s\n' "$(du -skx "$work/targets/$name" 2>/dev/null | cut -f1)" "$name"
    done | sort -k1,1nr -k2,2)
}

heavy_unit_wrapper() {
  # One compile of a heavy unit at a time across every leg and check
  # (heavy-unit-rustc.sh), in front of whatever RUSTC_WRAPPER is set.
  local wrapper="$ROOT/scripts/ci/setup/heavy-unit-rustc.sh"
  export BUILD_ONCE_HEAVY_LOCK="$work/heavy-unit.lock"
  if [ "${RUSTC_WRAPPER:-}" = "$wrapper" ]; then
    return 0
  fi
  if [ -n "${RUSTC_WRAPPER:-}" ]; then
    export BUILD_ONCE_HEAVY_NEXT_WRAPPER="$RUSTC_WRAPPER"
  else
    unset BUILD_ONCE_HEAVY_NEXT_WRAPPER
  fi
  export RUSTC_WRAPPER="$wrapper"
}

in_src() {
  [ -n "${BUILD_ONCE_SRC:-}" ] && [ -d "$BUILD_ONCE_SRC/.git" ] || die 'run prepare first'
  cd "$BUILD_ONCE_SRC"
  # BUILD_ONCE_NO_CACHE: a leg whose server did not start, or a rebuild after
  # a corrupt output, compiles without the cache.
  if sccache_on && [ "${BUILD_ONCE_NO_CACHE:-}" != 1 ]; then
    export RUSTC_WRAPPER="$sccache_bin"
  else
    unset RUSTC_WRAPPER
  fi
  heavy_unit_wrapper
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
  "services_runtime selected:service_orchestration"
)

leg_archive() {
  # The workspace test archive: every package's tests, default features,
  # published as cargo-nextest writes it (no debug information: the header).
  # Cargo's timings show which crates hold the leg up (codewire#5311).
  local out="$1"
  phase 'test archive' env CARGO_TARGET_DIR="$work/targets/archive" \
    cargo nextest archive --locked --workspace --all-targets --timings --archive-file "$out/archive.tar.zst"
  python3 -I "$ROOT/scripts/ci/setup/cargo-timings-summary.py" \
    "$work/targets/archive/cargo-timings/cargo-timing.html" '[build-once] timings:' || true
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
  # Only the non-default-feature database archives (enrollment, broker platform
  # and ssh-agent), built in one warm folder; every default-feature database
  # crate and codewire-db-migrate run from archive.tar.zst (infra#1534).
  local out="$1" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/database-archives.XXXXXX")"
  phase 'database archives' env CARGO_TARGET_DIR="$work/targets/database" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$work/targets/database" ARCHIVE_BUILD_DIR="$dir" \
    scripts/ci/verify/run-integration-verification.sh database-archives
  tar -cf "$out/database.tar" -C "$dir" .
  rm -rf -- "$dir"
}

leg_services_runtime() {
  # Only the kind-e2e orchestration wire-contract archive (which carries the
  # kind-e2e orchestration and smoke binaries); every default-feature service
  # crate and binary (including the whole control plane) runs from
  # archive.tar.zst (infra#1534).
  local out="$1" dir
  dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/services-runtime-archives.XXXXXX")"
  phase 'services runtime archives' env CARGO_TARGET_DIR="$work/targets/services_runtime" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$work/targets/services_runtime" ARCHIVE_BUILD_DIR="$dir" \
    scripts/ci/verify/run-integration-verification.sh services-runtime-archives
  tar -cf "$out/services_runtime.tar" -C "$dir" .
  rm -rf -- "$dir"
}

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
# 22374); a broken incremental session or a full disk (22822); a dependency
# rustc can no longer find or load (E0460-E0464, E0514; main run 22975:
# "can't find crate for `sqlx`"). A failed leg showing it wipes the target
# folders its log names, or its own when the log names none, and runs once
# more in the same job.
# shellcheck disable=SC2016 # The backticks are literal text in the linker message.
readonly CORRUPT_OUTPUT='malformed archive|truncated|Archive::children failed|invalid metadata|E0786|failed to mmap|linking with `cc` failed|corrupt incremental compilation artifact|could not load dep-graph|required to be available in rlib format|memory map must have a non-zero length|No space left on device|E046[0-4]|E0514|can.t find crate for|extern location for .* does not exist'

rebuild_corrupt_leg() {
  # rebuild_corrupt_leg NAME OUT LOG: succeeds only when the leg showed a
  # corrupt output in a target folder it names, and its one rebuild passed.
  # Only the named folders are wiped: the other legs build in their own
  # folders beside this one, and a build batch in its own inside its leg's
  # (a batch's folder alone; the leg's own folder with its batches').
  local name="$1" out="$2" log="$3" folders folder
  grep -Eq "$CORRUPT_OUTPUT" "$log" || return 1
  folders="$(grep -oE "$work/targets/[A-Za-z0-9_-]+(/batch-[a-z0-9-]+)?" "$log" | sort -u)"
  # A missing crate (E0463 and its kin) names no folder: the leg's own.
  [ -n "$folders" ] || folders="$work/targets/$name $work/targets/${name}_desktop"
  for folder in $folders; do
    echo "build-once: the $name leg read a corrupt output in $folder; it is wiped and the leg runs once more" | tee -a "$log"
    rm -rf -- "$folder"
  done
  # The cache may hold the corrupt output too: it is emptied, and the rebuild
  # does not read it.
  if sccache_on; then
    echo "build-once: the compiler cache is emptied, and the $name leg rebuilds without it" | tee -a "$log"
    rm -rf -- "$sccache_dir"
  fi
  BUILD_ONCE_NO_CACHE=1 "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" >> "$log" 2>&1
}

start_sccache_server() {
  # start_sccache_server NAME [LABEL]: start a per-task sccache server on its
  # own socket so its stats are isolated and its cache location is verified.
  local name="$1" label="${2:-}" start_output reason=''
  [ -n "$label" ] || label="the $name leg's"
  sccache_selected_only
  export SCCACHE_SERVER_UDS="${RUNNER_TEMP:-/tmp}/build-once-sccache-$name.sock"
  if [ -e "$SCCACHE_SERVER_UDS" ]; then
    reason="a server already held $SCCACHE_SERVER_UDS"
  elif ! start_output="$("$sccache_bin" --start-server 2>&1)"; then
    reason="its server did not start: $(printf '%s' "$start_output" | tail -n 1 | tr -d '\r' | cut -c1-200)"
  elif ! sccache_is_selected; then
    reason="its server reports: $("$sccache_bin" --show-stats 2>/dev/null |
      sed -n '/^Cache location/,/^[A-Z]/p' | sed '$d' | tr -s ' ' | tr '\n' ';' | cut -c1-300)"
  fi
  if [ -n "$reason" ]; then
    echo "::warning::build-once: $label compiler cache is not this build folder's, or the shared one the job selected; it compiles without it ($reason)"
    "$sccache_bin" --stop-server >/dev/null 2>&1 || true
    export BUILD_ONCE_NO_CACHE=1
  fi
}

run_one_leg() {
  # run_one_leg NAME OUT LOGS: one leg with its own log, rebuilt once when it
  # read a corrupt output; a failed leg is listed in LOGS/failed. Its folder's
  # use mark orders bound_targets' removals.
  # Each leg's start and finish reach the job log as they happen, so a run
  # cancelled before the legs all end still shows each finished leg's time.
  local name="$1" out="$2" logs="$3" started=$SECONDS status=0
  mark_used "$work/targets/$name"
  if sccache_on; then
    start_sccache_server "$name"
  fi
  echo "[build-once] leg $name: start"
  python3 "$ROOT/scripts/ci/setup/peak-rss.py" "$logs/$name.rss" -- \
    "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" > "$logs/$name.log" 2>&1 ||
    rebuild_corrupt_leg "$name" "$out" "$logs/$name.log" || status=1
  echo "[build-once] leg $name: finish (status=$status elapsed_seconds=$((SECONDS - started)))"
  echo "[build-once] leg $name: peak_rss_mib=$(cat "$logs/$name.rss" 2>/dev/null || echo unknown)"
  if sccache_on && [ "${BUILD_ONCE_NO_CACHE:-}" != 1 ]; then
    sccache_leg_stats "$name"
  fi
  if [ "$status" -ne 0 ]; then
    echo "$name" >> "$logs/failed"
    return 1
  fi
  # The leg's outputs go to the archive store now; the publish step uploads
  # whatever this missed.
  if [ -n "${ARCHIVE_STORE_URL:-}" ]; then
    local file
    for file in "$out/$name".*; do
      [ -f "$file" ] || continue
      upload_output "$file" ||
        echo "::warning::build-once: ${file##*/} was not uploaded as its leg finished; the publish step uploads it"
    done
  fi
}

# The settings select-untrusted-rust-cache.sh writes for its shared level,
# which a leg keeps only when they name that level exactly (sccache_shared).
readonly SCCACHE_SHARED_KEYS=" SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION SCCACHE_S3_USE_SSL \
SCCACHE_S3_KEY_PREFIX SCCACHE_MULTILEVEL_CHAIN SCCACHE_MULTILEVEL_WRITE_ERROR_POLICY SCCACHE_S3_RW_MODE \
AWS_SHARED_CREDENTIALS_FILE AWS_PROFILE AWS_EC2_METADATA_DISABLED "

sccache_shared() {
  # Whether the job selected the shared R2 level (select-untrusted-rust-cache.sh,
  # the same selector, roles and credential the test jobs use; owner,
  # 2026-11-17, #5146) and its settings name exactly that level: the
  # workflow's bucket and endpoint, the protected prefix behind this build
  # folder's disk, and on anything but a main push the read-only token and
  # mode (OpenBao gives a pull request only protected-read).
  [ "${CODEWIRE_SCCACHE_MODE:-}" = r2 ] || return 1
  local trust=protected-read
  [ "${GITHUB_EVENT_NAME:-}|${GITHUB_REF:-}" != 'push|refs/heads/main' ] || trust=main
  [ -n "${CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED:-}" ] && [ -n "${CODEWIRE_R2_CACHE_ENDPOINT:-}" ] &&
    [ "${SCCACHE_BUCKET:-}" = "$CODEWIRE_CI_SCCACHE_BUCKET_PROTECTED" ] &&
    [ "${SCCACHE_ENDPOINT:-}" = "$CODEWIRE_R2_CACHE_ENDPOINT" ] &&
    [ "${SCCACHE_S3_KEY_PREFIX:-}" = protected/codewire/v1 ] &&
    [ "${SCCACHE_MULTILEVEL_CHAIN:-}" = disk,s3 ] &&
    [ "${CODEWIRE_R2_CACHE_TRUST:-}" = "$trust" ] || return 1
  if [ "$trust" = protected-read ]; then
    [ "${SCCACHE_S3_RW_MODE:-}" = READ_ONLY ] || return 1
  fi
  # The credential is the selector's file below RUNNER_TEMP, never a value in
  # the environment.
  case "${AWS_SHARED_CREDENTIALS_FILE:-}" in
    "${RUNNER_TEMP:?}"/*) [ -f "$AWS_SHARED_CREDENTIALS_FILE" ] && [ ! -L "$AWS_SHARED_CREDENTIALS_FILE" ] ;;
    *) return 1 ;;
  esac
}

sccache_selected_only() {
  # Local must stay local (cw-security, #5231): sccache uses a remote backend
  # whenever its environment or configuration file names one (a bucket, an
  # endpoint, Redis, GCS, Azure, GHA or WebDAV settings, AWS credentials). So
  # a leg drops every other SCCACHE_ and AWS_ variable, keeping the shared
  # level's only when sccache_shared names the job's own, and reads no
  # configuration but its own. Its disk level is always this build folder's.
  local name keep=" "
  if sccache_shared; then
    keep="$SCCACHE_SHARED_KEYS"
  elif [ "${CODEWIRE_SCCACHE_MODE:-}" = r2 ]; then
    echo "::warning::build-once: the job's shared compiler cache does not name its own bucket, prefix and trust; the legs keep only the local one"
  fi
  for name in $(compgen -e); do
    case "$name" in
      SCCACHE_*|AWS_*) [[ "$keep" == *" $name "* ]] || unset "$name" ;;
    esac
  done
  export SCCACHE_DIR="$sccache_dir" SCCACHE_CACHE_SIZE="${BUILD_ONCE_SCCACHE_SIZE:-40G}"
  if [ "$keep" = " " ]; then
    export SCCACHE_CONF=/dev/null
  else
    # The shared level checks its bucket at server start, which can take
    # longer than the client's default 10 s wait.
    printf 'server_startup_timeout_ms = 60000\n' > "${RUNNER_TEMP:-/tmp}/build-once-sccache.conf"
    export SCCACHE_CONF="${RUNNER_TEMP:-/tmp}/build-once-sccache.conf"
  fi
}

sccache_is_selected() {
  # Whether the leg's running server caches in this build folder, on the
  # local disk, and, when the shared level is kept, in the job's bucket and
  # nowhere else, as the server reports itself.
  local bucket=''
  [ -z "${SCCACHE_BUCKET:-}" ] || bucket="$SCCACHE_BUCKET"
  if [ -z "$bucket" ]; then
    "$sccache_bin" --show-stats --stats-format json 2>/dev/null | python3 -c '
import json, sys
try:
    location = json.load(sys.stdin).get("cache_location", "")
except ValueError:
    sys.exit(1)
sys.exit(0 if location == f"Local disk: \"{sys.argv[1]}\"" else 1)
' "$sccache_dir"
    return
  fi
  # A multi-level server's JSON names no level: sccache 0.17 reports only
  # "Multi-level (2 levels)", which refused every leg's cache on every build
  # VM (runs 59311, 59332). Its text report lists each level under "Cache
  # location" on a main build; when it lists them, they must be exactly this
  # folder's disk and the job's bucket under the protected prefix. A pull
  # request's lists none, and two levels are then the settings' own.
  "$sccache_bin" --show-stats 2>/dev/null | python3 -c '
import re, sys
directory, bucket = sys.argv[1], sys.argv[2]
lines = sys.stdin.read().splitlines()
start = next((i for i, line in enumerate(lines) if line.startswith("Cache location")), None)
if start is None or lines[start].split(None, 2)[2:] != ["Multi-level (2 levels)"]:
    sys.exit(1)
levels = []
for line in lines[start + 1:]:
    match = re.match(r"^\s+L(\d+) \((\w+)\)\s{2,}(\S.*)$", line)
    if not match:
        break
    levels.append(match.groups())
expected = [("0", "disk", f"Local disk: \"{directory}\""),
            ("1", "s3", f"s3, name: {bucket}, prefix: /protected/codewire/v1/")]
# A pull request read-only server lists no level (the build of #5281); its
# two levels are then the ones sccache_shared checked in the settings the leg
# started it with, on a socket nothing else held (run_one_leg).
sys.exit(0 if levels == expected or not levels else 1)
' "$sccache_dir" "$bucket"
}

sccache_leg_stats() {
  # sccache_leg_stats NAME: one line with the leg's cache hits and misses,
  # from its own server, which then stops.
  local name="$1" stats
  stats="$("$sccache_bin" --show-stats --stats-format json 2>/dev/null)" || stats=''
  "$sccache_bin" --stop-server >/dev/null 2>&1 || true
  python3 -c '
import json, sys
name = sys.argv[1]
try:
    report = json.loads(sys.stdin.read())
    stats = report["stats"]
except (ValueError, KeyError, TypeError):
    print(f"[build-once] leg {name}: sccache stats unavailable")
    sys.exit(0)
hits = sum(stats.get("cache_hits", {}).get("counts", {}).values())
misses = sum(stats.get("cache_misses", {}).get("counts", {}).values())
rate = f"{100 * hits / (hits + misses):.1f}" if hits + misses else "n/a"
uncacheable = stats.get("non_cacheable_compilations", 0)
size = report.get("cache_size", 0)
location = report.get("cache_location", "")
print(f"[build-once] leg {name}: sccache hits={hits} misses={misses} hit_rate={rate} "
      f"not_cacheable={uncacheable} cache_bytes={size} location={location}")
' "$name" <<<"$stats"
}

run_checks_beside_legs() {
  # run_checks_beside_legs LOGS: the Rust checks (checks below) with their
  # own log, as one more task beside the legs; a failure is listed in
  # LOGS/failed as "checks".
  local logs="$1" started=$SECONDS status=0
  if sccache_on; then
    start_sccache_server checks
  fi
  echo "[build-once] checks: start"
  python3 "$ROOT/scripts/ci/setup/peak-rss.py" "$logs/checks.rss" -- \
    "$ROOT/scripts/ci/setup/build-once.sh" checks > "$logs/checks.log" 2>&1 || status=1
  echo "[build-once] checks: finish (status=$status elapsed_seconds=$((SECONDS - started)))"
  echo "[build-once] checks: peak_rss_mib=$(cat "$logs/checks.rss" 2>/dev/null || echo unknown)"
  if sccache_on && [ "${BUILD_ONCE_NO_CACHE:-}" != 1 ]; then
    sccache_leg_stats checks
  fi
  if [ "$status" -ne 0 ]; then
    echo checks >> "$logs/failed"
    return 1
  fi
}

run_legs() {
  # run_legs OUT LOGS: every wanted leg at once, under the jobserver build
  # started, and the Rust checks beside them (infra#1534
  # lever 3: they started only after the whole build, 51-177 s later, and
  # took about as long as the test jobs after it); it fails when any of them
  # failed.
  local out="$1" logs="$2" name pid status=0
  local -a pids=()
  while read -r name; do
    [ -n "$name" ] || continue
    run_one_leg "$name" "$out" "$logs" & pids+=("$!")
  done < <(wanted_legs)
  if [ "${BUILD_ONCE_CHECKS:-}" = true ]; then
    run_checks_beside_legs "$logs" & pids+=("$!")
  fi
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
  # A merge build's source, as the test jobs extract it to run the archives
  # against exactly what was compiled (#5146); published as source_sha256.
  if [ -n "${BUILD_ONCE_MERGE_ONTO:-}" ]; then
    # shellcheck source=scripts/ci/setup/merge-identity.sh
    source "$ROOT/scripts/ci/setup/merge-identity.sh"
    ci_source_archive "$src" "$out/source.tar.zst"
  fi
  logs="$(mktemp -d "${RUNNER_TEMP:-/tmp}/build-once-logs.XXXXXX")"
  tokens="$(jobserver_tokens)"
  [[ "$tokens" =~ ^[1-9][0-9]*$ ]] || die "invalid jobserver size: $tokens"
  [ "${BUILD_ONCE_COLD:-false}" = false ] || echo 'build-once: cold build folders'
  local beside=''
  [ "${BUILD_ONCE_CHECKS:-}" != true ] || beside='and the Rust checks '
  echo "build-once: legs $(wanted_legs | tr '\n' ' ')${beside}at once, $tokens compilers in all"
  # A Cargo that cannot reach the jobserver falls back to these few jobs.
  # The checks find it in BUILD_ONCE_JOBSERVER and take no other.
  CARGO_BUILD_JOBS=4 BUILD_ONCE_JOBSERVER="$tokens" python3 "$ROOT/scripts/ci/setup/jobserver.py" "$tokens" -- \
    "$ROOT/scripts/ci/setup/build-once.sh" run-legs "$out" "$logs" || status=1
  while read -r name; do
    [ -f "$logs/$name.log" ] || continue
    echo "::group::$name"; cat "$logs/$name.log"; echo '::endgroup::'
  done < <(wanted_legs; [ "${BUILD_ONCE_CHECKS:-}" != true ] || echo checks)
  grep -h '^\[build-once\]' "$logs"/*.log 2>/dev/null || true
  if [ -f "$logs/failed" ]; then
    while read -r name; do
      if [ "$name" = checks ]; then echo '::error::the Rust checks failed'; else echo "::error::the $name leg failed"; fi
      tail -n 80 "$logs/$name.log"
    done < "$logs/failed"
  fi
  return "$status"
}

# upload_output FILE: one leg output to the archive store under its SHA-256,
# recorded in OUT/.published as "FILE DIGEST BYTES". publish hashes every
# output again and trusts a record only for that exact digest, so an output
# rewritten after its upload is uploaded again. A leg uploads its own
# outputs as it finishes, while other legs and the checks still run: one
# after another after every leg and check had ended, the uploads took 21 s of
# pull request run 60663's build job (codewire#5311).
upload_output() {
  local file="$1" name digest bytes started
  name="${file##*/}"
  name="${name%%.*}"
  [[ "$name" =~ ^[a-z0-9_]+$ ]] || die "invalid leg output name: ${file##*/}"
  digest="$(sha256sum "$file" | cut -d' ' -f1)"
  bytes="$(stat -c %s "$file")"
  started=$SECONDS
  curl -fsS --retry 3 --retry-connrefused --connect-timeout 10 -o /dev/null \
    -T "$file" "$ARCHIVE_STORE_URL/v1/archives/$digest" || return 1
  echo "build-once: published $name $digest ($bytes bytes) in $((SECONDS - started)) s"
  printf '%s %s %s\n' "${file##*/}" "$digest" "$bytes" >> "${file%/*}/.published"
}

publish() {
  # Every leg output in OUT, by its SHA-256, as the job output <leg>_sha256.
  # Each output is hashed again here: one whose digest its leg already
  # recorded is reported without a second upload; any other, missing or
  # rewritten since, even at the same size, is uploaded (cw-security, #5329).
  local out="$1" file name digest recorded
  : "${ARCHIVE_STORE_URL:?ARCHIVE_STORE_URL is required}"
  for file in "$out"/*; do
    [ -f "$file" ] || continue
    name="${file##*/}"
    name="${name%%.*}"
    [[ "$name" =~ ^[a-z0-9_]+$ ]] || die "invalid leg output name: ${file##*/}"
    digest="$(sha256sum "$file" | cut -d' ' -f1)"
    recorded="$(awk -v f="${file##*/}" -v d="$digest" '$1 == f && $2 == d { print "yes"; exit }' \
      "$out/.published" 2>/dev/null || true)"
    if [ "$recorded" = yes ]; then
      echo "build-once: $name $digest was published as its leg finished"
    else
      upload_output "$file" || die "could not upload ${file##*/}"
    fi
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "${name}_sha256=$digest" >> "$GITHUB_OUTPUT"
    fi
  done
}

checks() {
  # The Rust checks (run-rust-checks.sh) from src, in their own warm target
  # folders, on the build runner, beside the legs (build). They share the
  # build folder's compiler cache for dependency builds (infra#1534); a check
  # that read a corrupt output wipes the folders its log names (clippy when it
  # names none) and runs once more without the cache, as a leg does.
  local log folder folders=() status=0
  in_src
  for folder in "${CHECK_FOLDERS[@]}"; do
    mark_used "$work/targets/$folder"
  done
  log="$(mktemp "${RUNNER_TEMP:-/tmp}/build-once-checks.XXXXXX")"
  run_checks 2>&1 | tee "$log" || status=$?
  [ "$status" -ne 0 ] || return 0
  grep -Eq "$CORRUPT_OUTPUT" "$log" || return "$status"
  # The check folders the log names: a whole folder name, so darwin_cw never
  # reads as darwin.
  while read -r folder; do
    if check_folder "$folder"; then folders+=("$work/targets/$folder"); fi
  done < <(grep -oE "$work/targets/[A-Za-z0-9_-]+" "$log" | sed 's|.*/||' | sort -u)
  # A missing crate (E0463 and its kin) names no folder: the lints' own.
  [ "${#folders[@]}" -gt 0 ] || folders=("$work/targets/clippy")
  for folder in "${folders[@]}"; do
    echo "build-once: the Rust checks read a corrupt output in $folder; it is wiped and they run once more"
    rm -rf -- "$folder"
    mark_used "$folder"
  done
  if sccache_on; then
    echo "build-once: the compiler cache is emptied, and the Rust checks rebuild without it"
    rm -rf -- "$sccache_dir"
    unset RUSTC_WRAPPER
    heavy_unit_wrapper
  fi
  run_checks
}

run_checks() {
  # Every selected check at once, all taking their compilers from one
  # jobserver sized as the legs' is (jobserver_tokens) and at most the job's
  # CPU share (CARGO_BUILD_JOBS from prepare; 32 on a build runner): the
  # legs' 24 compilers peaked at 32.7 GiB of the build guest's 50 (run
  # 24112), and the checks one after another at 20.4 GiB. A Cargo that
  # cannot reach the jobserver falls back to these few jobs.
  local tokens
  local -a folders=(CARGO_TARGET_DIR="$work/targets/clippy"
    RUST_CHECKS_FEATURES_TARGET_DIR="$work/targets/clippy_features"
    RUST_CHECKS_DARWIN_TARGET_DIR="$work/targets/darwin"
    RUST_CHECKS_CW_DARWIN_TARGET_DIR="$work/targets/darwin_cw"
    CODEWIRE_DESKTOP_CHECK_TARGET_DIR="$work/targets/desktop")
  # Beside the legs (build), the checks take their compilers from the legs'
  # jobserver, which their Cargo finds in CARGO_MAKEFLAGS.
  if [ -n "${BUILD_ONCE_JOBSERVER:-}" ]; then
    echo "build-once: the Rust checks at once, beside the legs, from their $BUILD_ONCE_JOBSERVER compilers"
    env "${folders[@]}" "$BUILD_ONCE_SRC/scripts/ci/verify/run-rust-checks.sh"
    return
  fi
  tokens="$(jobserver_tokens)"
  [[ "$tokens" =~ ^[1-9][0-9]*$ ]] || die "invalid jobserver size: $tokens"
  if [[ "${CARGO_BUILD_JOBS:-}" =~ ^[1-9][0-9]*$ ]] && (( CARGO_BUILD_JOBS < tokens )); then
    tokens="$CARGO_BUILD_JOBS"
  fi
  echo "build-once: the Rust checks at once, $tokens compilers in all"
  env "${folders[@]}" \
    CARGO_BUILD_JOBS=4 python3 "$ROOT/scripts/ci/setup/jobserver.py" "$tokens" -- \
    "$BUILD_ONCE_SRC/scripts/ci/verify/run-rust-checks.sh"
}

case "${1:-}" in
  checks) [ "$#" -eq 1 ] || die 'usage: build-once.sh checks'; checks ;;
  finish) [ "$#" -eq 1 ] || die 'usage: build-once.sh finish'; finish ;;
  prepare) [ "$#" -eq 3 ] || die 'usage: build-once.sh prepare CHECKOUT build|checks'; prepare "$2" "$3" ;;
  build) [ "$#" -eq 2 ] || die 'usage: build-once.sh build OUT'; build "$2" ;;
  legs) [ "$#" -eq 1 ] || die 'usage: build-once.sh legs'; wanted_legs ;;
  run-legs) [ "$#" -eq 3 ] || die 'usage: build-once.sh run-legs OUT LOGS'; run_legs "$2" "$3" ;;
  leg) [ "$#" -eq 3 ] || die 'usage: build-once.sh leg NAME OUT'; run_leg "$2" "$3" ;;
  publish) [ "$#" -eq 2 ] || die 'usage: build-once.sh publish OUT'; publish "$2" ;;
  *) die 'usage: build-once.sh prepare|build|legs|leg|run-legs|publish|checks|finish ...' ;;
esac
