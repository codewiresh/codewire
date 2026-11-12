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
# The build folder, /ci-cache/main or /ci-cache/pr:
# - src: a persistent clone. The job's checkout is fetched into it, so git
#   rewrites only changed files and Cargo's mtime fingerprints keep every
#   unchanged workspace crate fresh (a new checkout rebuilds them all); every
#   build also sees the same absolute workspace path. Hooks never run.
# - targets: one Cargo target folder per leg (targets/<leg>, and the local
#   VMM leg's desktop folder), so the legs build side by side without
#   waiting on each other's folder lock, and the Rust checks' own
#   (CHECK_FOLDERS); any other folder there is removed. A leg whose builds
#   run in batches at once (the database and service-plane legs,
#   run-integration-verification.sh compile_batches) keeps each batch but
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
# The Rust checks' target folders (checks), one per check, since they run at
# once and Cargo locks a target folder for a whole build: clippy for
# compile-all-targets, clippy_features for the feature-graph checks, darwin
# for the local-vmm checks, darwin_cw for the cw Darwin cross-check, desktop
# for the desktop check and package. A new folder is cold on its first run
# on each build runner.
readonly CHECK_FOLDERS=(clippy clippy_features darwin darwin_cw desktop)

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
  remove_interrupted_writes
  shopt -s dotglob nullglob
  for entry in "$cache_root"/*; do
    [ "$entry" = "$work" ] || [ "$entry" = "$cache_root/lost+found" ] || rm -rf -- "$entry"
  done
  for entry in "$work"/*; do
    case "${entry##*/}" in
      src|targets|cargo-home|tools|layout|job-running) ;;
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
  mark_job_running
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
    echo 'CARGO_INCREMENTAL=0'
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

remove_interrupted_writes() {
  # A job that never reached finish: delete what it wrote (see job-running in
  # the header). Its mark's time is when it started writing.
  local mark="$work/job-running" count
  local -a roots=()
  [ -f "$mark" ] || return 0
  [ ! -d "$work/targets" ] || roots+=("$work/targets")
  [ ! -d "$work/cargo-home" ] || roots+=("$work/cargo-home")
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
  swept="$(find "$work/targets" -xdev -type f -atime +"$(( days - 1 ))" -not -path '*/build/*' \
    -print -delete 2>/dev/null | wc -l)"
  # Each build/<unit> directory, by the first build/ under a profile. A unit
  # was read when any file under it was: one find, started at every unit,
  # prints the start (%H) each read file is under, so no unit forks its own
  # and a nested build/ under out/ is never mistaken for a unit.
  mapfile -d '' build_units < <(find "$work/targets" -xdev -mindepth 2 -type d -path '*/build/*' \
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
  find "$work/targets" -xdev -mindepth 2 -type d -empty -not -path '*/build/*' -delete 2>/dev/null || true
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
  lean_archive "$out/archive.tar.zst"
}

lean_archive() {
  # lean_archive FILE: strip the debug information from the archive's ELF
  # files and recompress it at zstd -9, after the build, so no fingerprint in
  # the warm folder changes (infra#2471). A 2.4 GB archive outran the archive
  # store under load; on the 502 MB cw test binary this is 47 MB against 88 MB.
  # The tests are the same code; only backtraces lose their line numbers
  # (panic locations still print). Any failure keeps the archive as built.
  local file="$1" dir started=$SECONDS before after stripped=0 f
  before="$(stat -c %s "$file")"
  dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/lean-archive.XXXXXX")"
  if ! { zstd -dcq "$file" | tar -x -p --no-same-owner -C "$dir"; }; then
    echo "::warning::build-once: the test archive did not unpack for slimming; it is kept as built"
    rm -rf -- "$dir"
    return 0
  fi
  while IFS= read -r -d '' f; do
    [ "$(head -c 4 "$f" | od -An -tx1 | tr -d ' ')" = 7f454c46 ] || continue
    objcopy --strip-debug "$f" || { echo "::warning::build-once: objcopy failed on ${f#"$dir"/}; the archive is kept as built"; rm -rf -- "$dir"; return 0; }
    stripped=$(( stripped + 1 ))
  done < <(find "$dir" -type f -size +0 -print0)
  # The same top-level entries nextest wrote, without a ./ prefix.
  if ! (cd "$dir" && find . -mindepth 1 -maxdepth 1 -printf '%P\0' | sort -z |
      tar -c --null -T - --owner=0 --group=0 --numeric-owner | zstd -9 -T0 -q -o "$file.lean"); then
    echo "::warning::build-once: the slimmed test archive did not pack; it is kept as built"
    rm -rf -- "$dir" "$file.lean"
    return 0
  fi
  mv -- "$file.lean" "$file"
  rm -rf -- "$dir"
  after="$(stat -c %s "$file")"
  echo "build-once: test archive slimmed: $stripped ELF files stripped of debug information, $before -> $after bytes in $(( SECONDS - started )) s"
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
  "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" >> "$log" 2>&1
}

run_one_leg() {
  # run_one_leg NAME OUT LOGS: one leg with its own log, rebuilt once when it
  # read a corrupt output; a failed leg is listed in LOGS/failed. Its folder's
  # use mark orders bound_targets' removals.
  # Each leg's start and finish reach the job log as they happen, so a run
  # cancelled before the legs all end still shows each finished leg's time.
  local name="$1" out="$2" logs="$3" started=$SECONDS status=0
  mark_used "$work/targets/$name"
  echo "[build-once] leg $name: start"
  "$ROOT/scripts/ci/setup/build-once.sh" leg "$name" "$out" > "$logs/$name.log" 2>&1 ||
    rebuild_corrupt_leg "$name" "$out" "$logs/$name.log" || status=1
  echo "[build-once] leg $name: finish (status=$status elapsed_seconds=$((SECONDS - started)))"
  if [ "$status" -ne 0 ]; then
    echo "$name" >> "$logs/failed"
    return 1
  fi
}

run_checks_beside_legs() {
  # run_checks_beside_legs LOGS: the Rust checks (checks below) with their
  # own log, as one more task beside the legs; a failure is listed in
  # LOGS/failed as "checks".
  local logs="$1" started=$SECONDS status=0
  echo "[build-once] checks: start"
  "$ROOT/scripts/ci/setup/build-once.sh" checks > "$logs/checks.log" 2>&1 || status=1
  echo "[build-once] checks: finish (status=$status elapsed_seconds=$((SECONDS - started)))"
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

checks() {
  # The Rust checks (run-rust-checks.sh) from src, in their own warm target
  # folders, on the build runner, beside the legs (build). A check that read a corrupt output in one of them wipes the folders
  # its log names (clippy when it names none) and runs once more, as a leg
  # does (rebuild_corrupt_leg).
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
