#!/usr/bin/env bash
# Focused automatic product-verification families. Toolchain setup belongs to
# the owning workflow job; this script is also callable for local diagnosis.
set -euo pipefail
# No step writes Python bytecode into the source tree, where a __pycache__
# would reach the next image context, which refuses it (#3071). A test of
# default bytecode behaviour clears this for its own child.
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FAMILY="${1:-}"
SELECTION="${VERIFICATION_SELECTION:-|valid:v3|complete|}"
cd "$ROOT"
CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh "$ROOT")"
export CARGO_TARGET_DIR
CARGO_DEBUG_DIR="$CARGO_TARGET_DIR/debug"
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
# shellcheck source=scripts/ci/verify/side-by-side.sh
source "$ROOT/scripts/ci/verify/side-by-side.sh"
# The product removes credential files with `shred -u`. Its default removal,
# wipesync, renames a file once per byte of its name and syncs the directory
# after every rename, so the script tests' synthetic credentials cost about
# 60,000 disk syncs per release family. On a CI disk where a sync is slow,
# those syncs set the release family's wall time: with a 10 ms flush, 464 s
# instead of 165 s. Every step here runs a shred that removes the same
# way without a sync per rename (--remove=wipe). It keeps every overwrite pass
# and its sync, and the name wipe. Tests that fake shred still put their own first.
use_test_shred() {
  local tools="$ROOT/.tmp/test-tools" real='' directory
  local -a directories=()
  IFS=: read -r -a directories <<<"$PATH"
  for directory in "${directories[@]}"; do
    if [ "$directory" != "$tools" ] && [ -x "$directory/shred" ]; then
      real="$directory/shred"
      break
    fi
  done
  [ -n "$real" ] || return 0
  mkdir -p "$tools"
  {
    printf '#!/bin/bash\n# Written by run-product-verification.sh (use_test_shred).\nreal=%q\n' "$real"
    cat <<'SHRED'
arguments=()
files=false
for argument in "$@"; do
  if [ "$files" = false ]; then
    case "$argument" in
      --) files=true ;;
      -u|--remove|--remove=wipesync) argument=--remove=wipe ;;
    esac
  fi
  arguments+=("$argument")
done
exec "$real" "${arguments[@]}"
SHRED
  } >"$tools/shred.$$"
  chmod 0755 "$tools/shred.$$"
  mv -f "$tools/shred.$$" "$tools/shred"
  PATH="$tools:$PATH"
  export PATH
}
use_test_shred
# Composition state is never accepted from a caller's environment.
RUST_COMPOSE_FORMAT=false
RUST_COMPOSE_FORMAT_DONE=false

selected() {
  [[ "$SELECTION" == *"|$1|"* ]]
}

install_bun_dependencies() {
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    bun install --frozen-lockfile --ignore-scripts
}

GO_MODULE_DIRS=(
  libs/gen-go
  libs/sdk-go
  tests/contract
)
GO_PACKAGE_PATTERNS=(
  ./libs/gen-go/...
  ./libs/sdk-go/...
  ./tests/contract/...
)

rust_package_args() {
  local prefix="$1" manifest dir token package
  local found=false
  RUST_PACKAGE_ARGS=()

  if [ "$prefix" = rust_pkg_ ] && selected rust_workspace; then
    RUST_PACKAGE_ARGS=(--workspace)
    return
  fi

  for manifest in crates/*/Cargo.toml; do
    dir="${manifest%/Cargo.toml}"
    token="${dir#crates/}"
    token="${token//-/_}"
    # The desktop crate is intentionally detached from the root workspace and
    # is verified by run_detached_desktop instead of Cargo's workspace runner.
    if [ "$prefix" = rust_pkg_ ] && [ "$token" = codewire_desktop ]; then
      continue
    fi
    if selected "${prefix}${token}"; then
      package="$(sed -nE 's/^name = "([^"]+)"/\1/p' "$manifest" | head -n 1)"
      [ -n "$package" ] || {
        echo "::error file=${manifest}::unable to determine Rust package name"
        exit 1
      }
      RUST_PACKAGE_ARGS+=( -p "$package" )
      found=true
    fi
  done

  if [ "$found" = false ]; then
    echo "::error::Rust verification selected without an affected package token"
    exit 1
  fi
}

# Compile once (infra#1632): with RUST_TEST_ARCHIVE set, the packages shard
# compiles nothing. It runs the selected packages' tests from that verified
# test archive, built by the run kind's build runner, with cargo-nextest:
# one run for the Rust and transport selections together. RUST_TEST_ARCHIVE is
# the archive file, or the folder fetch-test-archive.sh --extract unpacked it
# into while it downloaded.
RUST_ARCHIVE_FILTERS=()

run_rust_packages() {
  local prefix="$1" arg
  rust_package_args "$prefix"
  # The selector gives Rust and transport distinct package/feature graphs.
  # Preserve every generic invocation; only workspace formatting is shared.
  if [[ "$RUST_COMPOSE_FORMAT" != true || "$RUST_COMPOSE_FORMAT_DONE" != true ]]; then
    cargo fmt --all --check || return $?
    RUST_COMPOSE_FORMAT_DONE=true
  fi
  if [ -n "${RUST_TEST_ARCHIVE:-}" ]; then
    for arg in "${RUST_PACKAGE_ARGS[@]}"; do
      case "$arg" in
        --workspace) RUST_ARCHIVE_FILTERS+=('all()') ;;
        -p) ;;
        *) RUST_ARCHIVE_FILTERS+=("package($arg)") ;;
      esac
    done
    return 0
  fi
  # Workspace clippy (default and all features, every target) runs once in the
  # fast compile job, which every Rust or transport selection also runs, and
  # this test build compiles and links each library and test target with the
  # binaries their integration tests run. A separate debug build of the same
  # graph would only repeat that work.
  cargo test --locked "${RUST_PACKAGE_ARGS[@]}" --all-targets || return $?
}

run_rust_archive_tests() {
  [ "${#RUST_ARCHIVE_FILTERS[@]}" -gt 0 ] || return 0
  [ -e "$RUST_TEST_ARCHIVE" ] || {
    echo "::error::the test archive $RUST_TEST_ARCHIVE is missing" >&2
    return 1
  }
  # The build runner's build folder, /ci-cache/main on a push to main and
  # /ci-cache/pr otherwise (build-once-tree.sh). Test binaries carry its paths
  # (the compile-time CARGO_MANIFEST_DIR and CARGO_BIN_EXE_*), so the checkout
  # and the extracted target folder go there. A metal guest runs as many tests
  # at once as its share of the host (cpu-share.sh) times
  # RUST_ARCHIVE_THREADS_PER_CORE (1 unless the job sets it); elsewhere the CI
  # profile's own count applies.
  local nextest="${RUST_TEST_NEXTEST:-cargo-nextest}" root share
  local per_core="${RUST_ARCHIVE_THREADS_PER_CORE:-1}"
  # shellcheck source=scripts/ci/setup/build-once-tree.sh
  source "$ROOT/scripts/ci/setup/build-once-tree.sh"
  root="$(build_once_tree)"
  # shellcheck source=scripts/ci/setup/cpu-share.sh
  source "$ROOT/scripts/ci/setup/cpu-share.sh"
  share="$(ci_cpu_share)"
  [[ "$per_core" =~ ^[1-4]$ ]] || {
    echo "::error::RUST_ARCHIVE_THREADS_PER_CORE=$per_core is not 1 to 4" >&2
    return 2
  }
  [ -z "$share" ] || share=$((share * per_core))
  local filter="" part status=0
  for part in "${RUST_ARCHIVE_FILTERS[@]}"; do
    filter="${filter:+$filter | }$part"
  done
  # The test binaries carry the build folder's paths. The source is a real
  # copy of this checkout there, not a link: many tests check that their
  # paths' ancestry is real and owner-private, and compare canonical paths.
  # The target folder is extracted on the job's disk (a metal guest's
  # /ci-cache is its full warm cache), and the build path's target folder is
  # a real directory with a real tmp (CARGO_TARGET_TMPDIR) whose other
  # entries link into the extraction.
  local extract entry
  rm -rf -- "$root"
  mkdir -p "$root/targets/archive/tmp"
  cp -a "$ROOT/." "$root/src"
  if [ -d "$RUST_TEST_ARCHIVE" ]; then
    # fetch-test-archive.sh --extract unpacked it as it downloaded, and
    # reported it ready only once its bytes hashed to the digest.
    extract="$RUST_TEST_ARCHIVE"
    [ -f "$extract/target/nextest/binaries-metadata.json" ] || {
      echo "::error::$RUST_TEST_ARCHIVE holds no extracted test archive" >&2
      return 1
    }
  else
    extract="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rust-archive-tests.XXXXXX")"
    "$nextest" nextest run --archive-file "$RUST_TEST_ARCHIVE" \
      --workspace-remap "$root/src" --extract-to "$extract" \
      -E 'none()' --no-tests=pass >/dev/null || {
        status=$?
        df -h "$extract" "$root" >&2 || true
        return "$status"
      }
  fi
  for entry in "$extract/target"/*; do
    [ "${entry##*/}" = tmp ] || ln -s "$entry" "$root/targets/archive/${entry##*/}"
  done
  # Write the extraction out before any test runs: tests that sync a
  # filesystem within a deadline (the guest probe's workspace install) would
  # otherwise wait on gigabytes of fresh pages.
  sync
  echo "[rust-archive-tests] filter: $filter${RUST_TEST_PARTITION:+ partition: $RUST_TEST_PARTITION}"
  (
    cd "$root/src"
    "$nextest" nextest run \
      --binaries-metadata "$root/targets/archive/nextest/binaries-metadata.json" \
      --cargo-metadata "$root/targets/archive/nextest/cargo-metadata.json" \
      --target-dir-remap "$root/targets/archive" --workspace-remap "$root/src" \
      --profile ci --no-tests=pass -E "$filter" \
      ${share:+--test-threads "$share"} \
      ${RUST_TEST_PARTITION:+--partition "$RUST_TEST_PARTITION"}
  ) || status=$?
  rm -rf -- "$root" "$extract"
  return "$status"
}

# rust_packages_shard_covers PACKAGE: the Rust / transport packages shard runs
# PACKAGE's tests in this same run. It runs run_rust whenever rust is
# selected, and its packages are rust_package_args': the workspace, or each
# crate whose rust_pkg_ token is selected. A family that would run a package's
# tests again skips them only then (main run 23329: the shard ran every one of
# Standard's codewire-proto, codewire-admin-proto and codewire-dashboard-web
# tests, by name); otherwise it runs them itself.
rust_packages_shard_covers() {
  local token="${1//-/_}"
  selected rust || return 1
  selected rust_workspace || selected "rust_pkg_${token}"
}

# Rust/transport verification runs as parallel CI shards: packages (the
# selected package graphs), features (explicit feature graphs), and local-vmm
# (VM fixtures, guest probe, DERP contract and desktop, which need the extra
# toolchains). "all", the default, runs every shard in order as one job.
rust_shard() {
  [ "${RUST_TRANSPORT_SHARD:-all}" = all ] || [ "${RUST_TRANSPORT_SHARD:-all}" = "$1" ]
}

# Compile once (infra#1632): the features and local-vmm shards split into
# stages, so a pull request compiles them on the build runner and its test
# jobs compile nothing. RUST_SHARD_STAGE:
# - all (the default, and a main push): every step, with Cargo, as one job.
# - checks (build runner): what compiles but tests nothing: feature-graph
#   lints and checks, the Darwin cross-check, the static guest's
#   reproducibility proof, the desktop check and package dry run.
# - archives (build runner): each test step's `cargo test` becomes `cargo
#   nextest archive` of the same package, features and targets, into
#   RUST_SHARD_ARCHIVES/<key>.tar.zst.
# - tests (test job): every test step, each Cargo test run from its archive
#   in RUST_SHARD_ARCHIVES with cargo-nextest (RUST_TEST_NEXTEST); the
#   script and fixture tests that compile no Rust run here as before.
# Nextest runs no doctests; a main push still runs them with cargo test.
RUST_SHARD_STAGE="${RUST_SHARD_STAGE:-all}"

check_shard_stage() {
  case "$RUST_SHARD_STAGE" in
    all) return 0 ;;
    checks|archives|tests) ;;
    *)
      echo "::error::unknown RUST_SHARD_STAGE: $RUST_SHARD_STAGE" >&2
      return 2
      ;;
  esac
  case "${RUST_TRANSPORT_SHARD:-all}" in
    features|local-vmm) ;;
    *)
      echo "::error::RUST_SHARD_STAGE=$RUST_SHARD_STAGE needs RUST_TRANSPORT_SHARD features or local-vmm" >&2
      return 2
      ;;
  esac
  if [ "$RUST_SHARD_STAGE" != checks ] && [ ! -d "${RUST_SHARD_ARCHIVES:-}" ]; then
    echo "::error::RUST_SHARD_STAGE=$RUST_SHARD_STAGE needs the RUST_SHARD_ARCHIVES folder" >&2
    return 2
  fi
}

# shard_stage STAGE: whether this run takes STAGE's steps.
shard_stage() {
  [ "$RUST_SHARD_STAGE" = all ] || [ "$RUST_SHARD_STAGE" = "$1" ]
}

# shard_test KEY NEXTEST_SELECTION BUILD_ARGS... [-- CARGO_TEST_ARGS...]
# One Cargo test step. BUILD_ARGS choose the package, features and targets;
# CARGO_TEST_ARGS are cargo test's name filter and harness arguments, and
# NEXTEST_SELECTION is the same choice for cargo-nextest (split on spaces).
# RUST_SHARD_WORKSPACE names a detached workspace, relative to the root.
# RUST_SHARD_RUN_IN names a command (split on spaces) the tests run inside,
# such as run-in-public-netns.sh ADDRESS --; the build stays outside it.
shard_test() {
  local key="$1" selection="$2" arg
  local -a build=() filter=() selection_args=() run_in=()
  read -r -a run_in <<< "${RUST_SHARD_RUN_IN:-}"
  shift 2
  while [ "$#" -gt 0 ]; do
    arg="$1"
    shift
    if [ "$arg" = -- ]; then
      # Keep the separator: what follows it belongs to the test binary
      # (--ignored, --exact, names), not to cargo.
      filter=(-- "$@")
      break
    fi
    build+=("$arg")
  done
  case "$RUST_SHARD_STAGE" in
    all)
      if [ "${#run_in[@]}" -gt 0 ]; then
        cargo test --locked "${build[@]}" --no-run || return $?
        "${run_in[@]}" cargo test --locked --offline "${build[@]}" "${filter[@]}"
      else
        cargo test --locked "${build[@]}" "${filter[@]}"
      fi
      ;;
    archives)
      [ ! -e "$RUST_SHARD_ARCHIVES/$key.tar.zst" ] || {
        echo "::error::two test steps share the archive $key" >&2
        return 2
      }
      cargo nextest archive --locked "${build[@]}" \
        --archive-file "$RUST_SHARD_ARCHIVES/$key.tar.zst"
      ;;
    tests)
      read -r -a selection_args <<< "$selection"
      run_shard_archive "$key" "${selection_args[@]}"
      ;;
    checks) return 0 ;;
  esac
}

# public_netns_available: this job can make a user and network namespace.
public_netns_available() {
  command -v unshare >/dev/null 2>&1 && unshare -rn true 2>/dev/null
}

# #2614 against a real interface: a broker sent the host's addresses refuses
# a connection to one. The test needs an interface holding a public address,
# which only a private network namespace can give it
# (run-in-public-netns.sh). A job that cannot make one says so; local
# qualification on a host that can runs it.
run_host_interface_refusal() {
  if [ "$RUST_SHARD_STAGE" != archives ] && shard_stage tests && ! public_netns_available; then
    echo '::notice::the egress broker host-interface refusal did not run: this job cannot make a user and network namespace (unshare -rn)'
    return 0
  fi
  RUST_SHARD_RUN_IN="scripts/ci/verify/run-in-public-netns.sh 1.1.1.1 --" \
    shard_test cli-bin-host-interface-refusal \
    '--run-ignored only -E test(=a_connection_to_the_hosts_own_interface_address_is_refused)' \
    -p codewire-cli-bin --test native_egress_broker -- --ignored --exact \
    a_connection_to_the_hosts_own_interface_address_is_refused
}

# The daemon's authenticated credential ingress with the stock gh the
# workspace image ships (fetch-pinned-gh.sh reads the image's pin).
run_daemon_stock_gh() {
  local gh_dir="" status=0
  if shard_stage tests; then
    gh_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/stock-gh.XXXXXX")"
    scripts/ci/setup/fetch-pinned-gh.sh "$gh_dir" || { rm -rf -- "$gh_dir"; return 1; }
  fi
  CODEWIRE_TEST_GH_BIN="${gh_dir:+$gh_dir/gh}" shard_test daemon-stock-gh \
    '--run-ignored only -E test(=credential_bridge::tests::stock_gh_rest_and_graphql_use_authenticated_unix_ingress)' \
    -p codewire-daemon --lib -- --ignored --exact \
    credential_bridge::tests::stock_gh_rest_and_graphql_use_authenticated_unix_ingress || status=$?
  [ -z "$gh_dir" ] || rm -rf -- "$gh_dir"
  return "$status"
}

# The archives' build folder (build-once.sh). As for the packages shard, the
# test binaries carry its paths (CARGO_MANIFEST_DIR, CARGO_BIN_EXE_*,
# CARGO_TARGET_TMPDIR): the source is a real copy of this checkout there, and
# each archive's build target folder links into its extraction.
SHARD_ARCHIVE_SOURCE_READY=false

# The build folder of this run's kind: /ci-cache/main on a push to main,
# /ci-cache/pr otherwise (build-once-tree.sh).
shard_archive_root() {
  # shellcheck source=scripts/ci/setup/build-once-tree.sh
  source "$ROOT/scripts/ci/setup/build-once-tree.sh"
  build_once_tree
}

shard_archive_cleanup() {
  [ "$SHARD_ARCHIVE_SOURCE_READY" = true ] || return 0
  rm -rf -- "$(shard_archive_root)" "${SHARD_ARCHIVE_EXTRACT:-}"
}

# extract_shard_archive KEY: extract one archive and link its build target
# folder to the extraction, whose target folder it sets in
# SHARD_ARCHIVE_TARGET (a variable, not output: the first call also records
# the source copy for cleanup in this shell).
extract_shard_archive() {
  local key="$1" archive="$RUST_SHARD_ARCHIVES/$1.tar.zst" root
  root="$(shard_archive_root)"
  local nextest="${RUST_TEST_NEXTEST:-cargo-nextest}" workspace="${RUST_SHARD_WORKSPACE:-.}"
  local extract target entry
  [ -f "$archive" ] || {
    echo "::error::no $key test archive; the build runner built none for this selection" >&2
    return 1
  }
  if [ "$SHARD_ARCHIVE_SOURCE_READY" != true ]; then
    rm -rf -- "$root"
    mkdir -p "$root"
    cp -a "$ROOT/." "$root/src" || return 1
    SHARD_ARCHIVE_EXTRACT="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rust-shard-archives.XXXXXX")"
    SHARD_ARCHIVE_SOURCE_READY=true
    trap shard_archive_cleanup EXIT
  fi
  extract="$SHARD_ARCHIVE_EXTRACT/$key"
  rm -rf -- "$extract"
  mkdir -p "$extract"
  "$nextest" nextest run --archive-file "$archive" \
    --workspace-remap "$root/src/$workspace" --extract-to "$extract" \
    -E 'none()' --no-tests=pass >/dev/null || return 1
  target="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["target_directory"])' \
    "$extract/target/nextest/cargo-metadata.json")" || return 1
  [[ "$target" == "$root"/targets/* ]] || {
    echo "::error::the $key archive was built in $target, not under $root/targets" >&2
    return 1
  }
  rm -rf -- "$target"
  mkdir -p "$target/tmp" || return 1
  for entry in "$extract/target"/*; do
    [ "${entry##*/}" = tmp ] || ln -s "$entry" "$target/${entry##*/}" || return 1
  done
  # Write the extraction out before any test runs (see run_rust_archive_tests).
  sync
  SHARD_ARCHIVE_TARGET="$extract/target"
}

# run_shard_archive KEY NEXTEST_ARGS...: run one archive's selected tests.
run_shard_archive() {
  local key="$1" root workspace="${RUST_SHARD_WORKSPACE:-.}" target
  root="$(shard_archive_root)"
  local -a profile=(--profile ci)
  shift
  extract_shard_archive "$key" || return 1
  target="$SHARD_ARCHIVE_TARGET"
  # The CI profile (.config/nextest.toml) belongs to the root workspace; a
  # detached workspace runs with nextest's defaults, like cargo test.
  [ "$workspace" = . ] || profile=()
  echo "[rust-shard-archive] $key: $*"
  local -a run_in=()
  read -r -a run_in <<< "${RUST_SHARD_RUN_IN:-}"
  (
    cd "$root/src/$workspace"
    "${run_in[@]}" "${RUST_TEST_NEXTEST:-cargo-nextest}" nextest run \
      --binaries-metadata "$target/nextest/binaries-metadata.json" \
      --cargo-metadata "$target/nextest/cargo-metadata.json" \
      --target-dir-remap "$target" --workspace-remap "$root/src/$workspace" \
      "${profile[@]}" --no-tests=fail "$@"
  )
}

run_rust_transport() {
  if ! selected rust && ! selected transport; then
    echo '::error::Rust/transport composition selected without either capability' >&2
    return 1
  fi
  case "${RUST_TRANSPORT_SHARD:-all}" in
    all|packages|features|local-vmm) ;;
    *)
      echo "::error::unknown RUST_TRANSPORT_SHARD: ${RUST_TRANSPORT_SHARD}" >&2
      return 2
      ;;
  esac
  RUST_COMPOSE_FORMAT=true
  RUST_COMPOSE_FORMAT_DONE=false
  if selected rust; then
    run_rust
  fi
  if selected transport; then
    run_transport
  fi
  if rust_shard packages; then
    run_rust_archive_tests
  fi
}

run_detached_desktop() {
  local manifest="crates/codewire-desktop/Cargo.toml"
  local desktop_target_dir="${CODEWIRE_DESKTOP_CARGO_TARGET_DIR:-$CARGO_TARGET_DIR}"
  check_shard_stage || return $?
  if shard_stage tests; then
    CARGO_TARGET_DIR="$desktop_target_dir" cargo fmt --manifest-path "$manifest" --check
  fi
  if shard_stage checks; then
    CARGO_TARGET_DIR="$desktop_target_dir" cargo check --locked --manifest-path "$manifest"
  fi
  CARGO_TARGET_DIR="$desktop_target_dir" RUST_SHARD_WORKSPACE=crates/codewire-desktop \
    shard_test desktop '' --manifest-path "$manifest"
  if shard_stage checks; then
    CARGO_TARGET_DIR="$desktop_target_dir" \
      scripts/ci/release/package-codewire-desktop.sh --dry-run 0.0.0-ci
  fi
}

has_root_rust_selection() {
  local manifest dir token
  if selected rust_workspace; then
    return 0
  fi
  for manifest in crates/*/Cargo.toml; do
    dir="${manifest%/Cargo.toml}"
    token="${dir#crates/}"
    token="${token//-/_}"
    [ "$token" = codewire_desktop ] && continue
    if selected "rust_pkg_${token}"; then
      return 0
    fi
  done
  return 1
}

run_verification_shell_syntax() {
  local candidate
  for candidate in \
      .githooks/pre-push \
      scripts/dev/preflight.sh \
      scripts/dev/install-hooks.sh \
      scripts/ci/select/select-verification.sh \
      scripts/ci/receipts/verify-release-tag-receipt.sh \
      scripts/ci/tests/test-select-verification.sh \
      scripts/ci/tests/test-verify-release-tag-receipt.sh \
      scripts/ci/tests/test-pre-push-worktree.sh \
      scripts/ci/verify/integration-postgres.sh \
      scripts/ci/verify/run-product-verification.sh \
      scripts/ci/verify/check-darwin-cross.sh \
      scripts/ci/tests/test-darwin-cross-check.sh \
      scripts/ci/verify/check-curated-rust-locks.sh \
      scripts/ci/tests/test-curated-rust-locks.sh \
      scripts/ci/verify/run-integration-verification.sh \
      scripts/ci/tests/test-integration-postgres.sh \
      scripts/ci/verify/rust-stack-rehearsal.sh; do
    if [ -f "$candidate" ]; then
      bash -n "$candidate"
    fi
  done
  if [ -d scripts/runtime ]; then
    find scripts/runtime -type f -name '*.sh' -exec bash -c '
      for candidate; do
        bash -n "$candidate" || exit "$?"
      done
    ' bash {} +
  fi
}

# A pull request names its base, and a push to main the newest main commit
# main CI verified (the base its selection compared with): ShellCheck then
# covers only the scripts changed since. Without a base (an unverified main
# base, a dispatch, local) it covers every script.
run_shell_policy() {
  scripts/ci/verify/check-shell-scripts.sh --self-test
  if [ -n "${CODEWIRE_SHELL_POLICY_BASE:-}" ]; then
    scripts/ci/verify/check-shell-scripts.sh --changed-since "$CODEWIRE_SHELL_POLICY_BASE"
  else
    scripts/ci/verify/check-shell-scripts.sh
  fi
}

isolate_kind_fixture_environment() {
  local key
  # Fixtures own synthetic selectors and endpoints. They must not discover a
  # caller's live profile, private context, artifact paths or lock descriptors.
  # Unsetting descriptor names leaves the parent's open descriptions locked.
  for key in ${!KIND_@}; do
    unset "$key"
  done
  unset CLUSTER KEEP_KIND_CLUSTER KUBECONFIG KUBE_CONTEXT RUN_DIR CARGO_CI_DIR
}

# CI runs the parts side by side, as local merge qualification does. The first
# part streams; the others' output follows as each finishes. The first failed
# part stops the others and fails policy core (owner, 2026-10-25, #3013);
# VERIFICATION_KEEP_GOING=1 lets every part finish and report first.
run_policy_core() {
  local part index first='' status failed='' work ended remaining
  local -a parts=() logs=() pids=()
  local -A ended_parts=()
  while IFS= read -r part; do
    [ "$part" = policy-shell ] || parts+=("$part")
  done < <(policy_parts)
  work="$(mktemp -d)"
  # Each part reports its end on this queue, as run_side_by_side's commands
  # do: the family learns of a failure at once and never waits on a job the
  # shell has already reaped (wait -n -p failed so when a part ended first).
  mkfifo "$work/ended"
  exec {ended}<>"$work/ended"
  for index in "${!parts[@]}"; do
    part="${parts[$index]}"
    if [ -z "$first" ]; then
      first="$part"
      logs+=('')
    else
      logs+=("$work/$index.log")
    fi
    (
      exec {ended}>&-
      # Not a condition: the part keeps errexit.
      set +e
      if [ -z "${logs[$index]}" ]; then
        (set -e; run_policy_part "${parts[$index]}")
      else
        (set -e; run_policy_part "${parts[$index]}") >"${logs[$index]}" 2>&1
      fi
      printf '%s %s\n' "$index" "$?" >"$work/ended"
    ) &
    pids[index]=$!
  done
  remaining="${#parts[@]}"
  while [ "$remaining" -gt 0 ]; do
    read -r index status <&"$ended"
    remaining=$((remaining - 1))
    ended_parts[$index]=1
    if [ -n "${logs[$index]}" ]; then
      printf '=== %s (ran beside %s) ===\n' "${parts[$index]}" "$first"
      cat "${logs[$index]}"
    fi
    [ "$status" -eq 0 ] || failed="${failed} ${parts[$index]} exited ${status};"
    if [ -n "$failed" ] && [ "${VERIFICATION_KEEP_GOING:-0}" != 1 ]; then
      local -a stopping=()
      for index in "${!parts[@]}"; do
        [ -n "${ended_parts[$index]:-}" ] || stopping+=("${pids[$index]}")
      done
      [ "${#stopping[@]}" -eq 0 ] || stop_side_by_side "${stopping[@]}"
      for index in "${!parts[@]}"; do
        [ -n "${ended_parts[$index]:-}" ] || printf '=== %s stopped, when policy core failed ===\n' "${parts[$index]}"
      done
      break
    fi
  done
  # A part that ended while the others stopped still reports on the queue,
  # so it stays open until every part has been waited for.
  wait "${pids[@]}" 2>/dev/null || true
  exec {ended}>&-
  rm -rf -- "$work"
  if [ -n "$failed" ]; then
    printf 'policy core failed:%s\n' "$failed" >&2
    return 1
  fi
}

# Repository rules run on every pull request and every push to main: the
# private-content tree scan, every repo_checks rule and the guards that read
# product source (#3119 A6). Every step is independent and keeps no state
# outside its own scratch directory; run_side_by_side runs them side by side.
# The two slowest repository-check self-tests (#3119 L1) run when the checks
# change, as the selector's repo_check_self_tests says; the checks themselves
# always run. A selection without repo_check_self_tests_omittable keeps them.
repo_check_self_test_flag() {
  if selected repo_check_self_tests || ! selected repo_check_self_tests_omittable; then
    printf '%s\n' --self-test
  fi
}

run_repo_rules() {
  (
  isolate_kind_fixture_environment
  # The steps below read it when run_side_by_side evaluates them.
  # shellcheck disable=SC2034
  repo_check_self_test="$(repo_check_self_test_flag)"
  # The slowest rules come first, so the runner's bound never queues them.
  run_side_by_side <<'STEPS'
  python3 scripts/checks/repo_checks.py permanent-raw-surface $repo_check_self_test
  python3 scripts/checks/repo_checks.py epoch-material-cache-owner $repo_check_self_test
  scripts/ci/tests/test-openbao-only-secret-authority.sh
  run_verification_shell_syntax
  scripts/ci/tests/test-go-source-ownership.sh
  scripts/ci/verify/check-rust-toolchain.sh
  scripts/ci/tests/test-rust-owned-fixtures.sh
  python3 -B scripts/ci/tests/test-runtime-profile.py
  scripts/ci/tests/test-admin-proto-boundary.sh
  python3 scripts/checks/repo_checks.py license-map
  python3 scripts/checks/repo_checks.py kind-suite-rows --self-test
  python3 scripts/checks/repo_checks.py kind-suite-rows
  python3 scripts/checks/repo_checks.py design-tokens --self-test
  python3 scripts/checks/repo_checks.py identity-free-workspace --self-test
  python3 scripts/checks/repo_checks.py workspace-image-pin --self-test
  python3 scripts/checks/repo_checks.py workspace-image-pin
  python3 scripts/checks/repo_checks.py webpki-roots-floor --self-test
  python3 scripts/checks/repo_checks.py webpki-roots-floor
  python3 scripts/checks/repo_checks.py os-splits --self-test
  python3 scripts/checks/repo_checks.py os-splits
  scripts/ci/release/check-mirror-content.sh --tree
  python3 scripts/checks/repo_checks.py mcp-settings --self-test
  python3 scripts/checks/repo_checks.py rust-validation-source
  python3 scripts/checks/repo_checks.py retired-reference-source
  python3 scripts/checks/repo_checks.py public-address-literals --self-test
  python3 scripts/checks/repo_checks.py private-host-literals --self-test
  python3 scripts/checks/repo_checks.py go-source-classification
  python3 scripts/checks/repo_checks.py ses-email-isolation
  python3 scripts/checks/repo_checks.py turnstile-access-projection --self-test
  python3 scripts/checks/repo_checks.py hosted-overlay-contract --self-test
STEPS
  )
}

# The self-tests of the CI, developer and workflow scripts. They run when those
# scripts change: the selector's ci_script_tests (#3119 A6).
run_ci_script_tests() {
  (
  isolate_kind_fixture_environment
  # The slowest tests come first, so the runner's bound never queues them
  # behind the quick ones.
  run_side_by_side <<'STEPS'
  scripts/ci/tests/test-workspace-image-verify-workflow.sh
  scripts/ci/tests/test-integration-postgres.sh
  scripts/ci/tests/test-select-verification.sh
  python3 -I -B scripts/ci/tests/test-ci-workflow-structure.py
  python3 -I -B scripts/ci/tests/test-cw-runtime-source.py
  scripts/ci/tests/test-local-rust-cache.sh
  scripts/ci/tests/test-build-local-image.sh
  python3 -I -B scripts/ci/tests/test-cw-image-consumer.py
  scripts/ci/tests/test-cargo-target-runner-failures.sh
  scripts/ci/tests/test-darwin-cross-check.sh
  scripts/ci/tests/test-resolve-deployed-source.sh
  scripts/ci/tests/test-dev-deployment-smoke-receipt.sh
  scripts/ci/tests/test-run-side-by-side.sh
  scripts/ci/tests/test-standard-families.sh
  scripts/ci/tests/test-warm-rust-cache.sh
  scripts/ci/tests/test-install-cargo-nextest.sh
  scripts/ci/tests/test-load-fixture-images.sh
  scripts/ci/tests/test-build-runner-measure.sh
  scripts/ci/tests/test-bound-cargo-jobs.sh
  scripts/ci/tests/test-build-once.sh
  scripts/ci/tests/test-run-rust-checks.sh
  scripts/ci/tests/test-fetch-test-archive-extract.sh
  python3 -B scripts/ci/tests/test-last-scheduled-run.py
  python3 -I -B scripts/ci/tests/test-ci-done-measures.py
  python3 -I -B scripts/ci/tests/test-ci-job-plan.py
  scripts/ci/tests/test-service-ssh-image-verifier.sh
  scripts/ci/tests/test-shellcheck-policy-domain.sh
  scripts/ci/tests/test-require-verification-results.sh
  scripts/ci/tests/test-verify-tested-tree-receipt.sh
  scripts/ci/tests/test-resolve-cargo-target-dir.sh
  scripts/ci/tests/test-runner-no-bytecode.sh
  scripts/ci/tests/test-package-codewire-desktop.sh
  scripts/ci/tests/test-rust-toolchain.sh
  scripts/ci/tests/test-cargo-cache-capacity.sh
  scripts/ci/tests/test-ci-tool-downloads.sh
  python3 -B scripts/ci/tests/test-linux-vmm-kernel.py
  scripts/ci/tests/test-dashboard-image-network-probe.sh
  scripts/ci/tests/test-build-dashboard-image.sh
  scripts/ci/tests/test-workspace-agent-contract.sh
  python3 -I -B scripts/ci/tests/test-cw-image-context.py
  python3 -I -B scripts/ci/tests/test-cw-image-source.py
  scripts/ci/tests/test-build-kind-smokes.sh
  python3 -B scripts/ci/tests/test-kind-build-artifacts.py
  scripts/ci/tests/test-preflight-openbao-native-secrets.sh
  scripts/ci/tests/test-sync-local-secrets.sh
  scripts/ci/tests/test-kind-runtime-images.sh
  scripts/ci/tests/test-kind-watch-github-app.sh
  scripts/ci/tests/test-source-approval-workflow.sh
  scripts/ci/tests/test-fetch-openbao-sccache-r2-credentials.sh
  scripts/ci/tests/test-select-untrusted-rust-cache.sh
  scripts/ci/tests/test-fetch-openbao-sccache-r2-protected-credentials.sh
  scripts/ci/tests/test-select-protected-rust-cache.sh
  scripts/ci/tests/test-run-host-rust-build.sh
  scripts/ci/tests/test-check-workspace-hack.sh
  scripts/ci/tests/test-free-block-probe.sh
  python3 -B scripts/ci/tests/test-integration-lane.py
  scripts/ci/tests/test-ci-tests-wired.sh
  python3 scripts/dev/test-macos-cli.py
  python3 scripts/dev/test-macos-ext4-tool.py
  python3 scripts/dev/test-macos-git-tool.py
  python3 scripts/dev/test-macos-local-runtime.py
  python3 scripts/dev/test-linux-local-runtime.py
STEPS
  )
}

# The parts of the policy family for this selection, one per line, in order.
# Local merge qualification runs them as parallel lanes; nothing else decides
# what policy consists of.
policy_parts() {
  # A legacy trusted selector does not know when omission is authoritative, so
  # it must retain the historical full ShellCheck behavior. Only a trusted
  # selector that emits policy_shell_omittable may omit the shell domain. The
  # CI-script tests follow the same rule with ci_script_tests_omittable.
  if selected policy_shell || ! selected policy_shell_omittable; then
    printf 'policy-shell\n'
  fi
  printf 'policy-repo-rules\n'
  if selected ci_script_tests || ! selected ci_script_tests_omittable; then
    printf 'policy-ci-script-tests\n'
  fi
  # The artifact planner's suite runs when one of its inputs changes (#3119
  # L3). A selection without ci_plan_tests_omittable runs it with Deploy, as
  # before.
  if selected ci_plan_tests; then
    printf 'policy-planner-tests\n'
  fi
}

run_policy_part() {
  case "$1" in
    policy-shell) run_shell_policy ;;
    policy-repo-rules) run_repo_rules ;;
    policy-ci-script-tests) run_ci_script_tests ;;
    policy-planner-tests) scripts/ci/plan/test.sh ;;
    *) return 2 ;;
  esac
}

# The Tooling job's families for this selection, one per line, under the
# conditions its separate workflow steps had: ShellCheck as Policy decides it
# (policy_parts), each other family on its own token.
tooling_parts() {
  local entry
  if selected policy_shell || { selected policy && ! selected policy_shell_omittable; }; then
    printf 'policy-shell\n'
  fi
  for entry in \
      confidential-script-tests:confidential_script_tests \
      dev-smoke-script-tests:dev_smoke_script_tests \
      release:release \
      deploy:deploy \
      workspace-agents:workspace_agents \
      security:security \
      edge:edge_kind; do
    if selected "${entry#*:}"; then
      printf '%s\n' "${entry%%:*}"
    fi
  done
}

# One Tooling family in its own runner process, with the environment its own
# workflow step gave it: only Security, Edge and Deploy read the trusted
# selection, and only ShellCheck reads the pull request's base. Deploy reads it
# for one decision: whether Policy owns the planner's suite
# (ci_plan_tests_omittable), so the suite runs once, not in both jobs.
run_tooling_family() {
  local -a environment=(env -u VERIFICATION_SELECTION -u CODEWIRE_SHELL_POLICY_BASE
    "VERIFICATION_TEST_JOBS=${TOOLING_FAMILY_JOBS:?}")
  case "$1" in
    security|edge|deploy) environment+=("VERIFICATION_SELECTION=$SELECTION") ;;
    policy-shell) environment+=("CODEWIRE_SHELL_POLICY_BASE=${CODEWIRE_SHELL_POLICY_BASE:-}") ;;
  esac
  "${environment[@]}" "$ROOT/scripts/ci/verify/run-product-verification.sh" "$1"
}

# The Tooling job runs its selected families side by side, so its wall time
# is near its slowest family's rather than their sum (infra#1534), and the
# first failure stops the rest (#3013). Its guest has a share of the host's
# CPUs and a fixed memory (a medium guest: 8 CPUs, 6 GiB), and every family
# runs its own tests side by side, so the families are bounded too: on main
# run 22789, seven families each starting every test at once timed out a
# deadline-bound Dev smoke test.
# - ShellCheck runs first, alone: a full analysis holds 4.4-4.8 GB.
# - The others run at most half the share at once (at most three), longest
#   first, and each runs half the share of its own tests at once.
# VERIFICATION_TEST_JOBS, when the caller sets it, bounds both instead.
run_tooling() {
  local parts share family_limit ordered family
  parts="$(tooling_parts)"
  if [ -z "$parts" ]; then
    echo 'Tooling: no family is selected'
    return 0
  fi
  printf 'Tooling families: %s\n' "$(tr '\n' ' ' <<<"$parts")"
  # The CPU share as cpu-share.sh reads it, else this host's CPUs.
  share="${CODEWIRE_CI_CPU_SHARE:-}"
  [[ "$share" =~ ^[1-9][0-9]{0,3}$ ]] || share="$(nproc)"
  family_limit=$((share / 2))
  [ "$family_limit" -ge 1 ] || family_limit=1
  [ "$family_limit" -le 3 ] || family_limit=3
  family_limit="${VERIFICATION_TEST_JOBS:-$family_limit}"
  TOOLING_FAMILY_JOBS="${VERIFICATION_TEST_JOBS:-$(( share / 2 > 0 ? share / 2 : 1 ))}"
  if grep -qx policy-shell <<<"$parts"; then
    run_side_by_side <<<'run_tooling_family policy-shell' || return
  fi
  ordered=''
  for family in edge deploy release security dev-smoke-script-tests workspace-agents \
      confidential-script-tests; do
    if grep -qx "$family" <<<"$parts"; then
      ordered+="run_tooling_family $family"$'\n'
    fi
  done
  [ -n "$ordered" ] || return 0
  VERIFICATION_TEST_JOBS="$family_limit" run_side_by_side <<<"${ordered%$'\n'}"
}

run_policy() {
  local part
  for part in $(policy_parts); do
    run_policy_part "$part"
  done
}

# buf, from its pinned release binary: building it with go install took 47 s
# of every Contracts run (main run 23329). The SHA-256 is the one the release
# publishes in its sha256.txt. The Makefile's proto-tools target installs the
# same version (test-select-verification.sh keeps the two equal).
readonly BUF_VERSION='1.50.0'
readonly BUF_URL="https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-x86_64"
readonly BUF_SHA256='154ea883ce098eac4fa106ff9ee4e4964bb97f809dd8ec9c34a432b466ce1494'

install_contract_toolchain() {
  [ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || {
    echo '::error::the pinned buf is the x86_64 Linux build' >&2
    return 1
  }
  mkdir -p "$HOME/.proto-tools/bin"
  "$ROOT/scripts/ci/release/fetch-pinned.sh" "$BUF_URL" "$BUF_SHA256" "$HOME/.proto-tools/bin/buf.partial"
  chmod 0755 "$HOME/.proto-tools/bin/buf.partial"
  mv -f -- "$HOME/.proto-tools/bin/buf.partial" "$HOME/.proto-tools/bin/buf"
  [ "$("$HOME/.proto-tools/bin/buf" --version)" = "$BUF_VERSION" ] || {
    echo "::error::the installed buf is not $BUF_VERSION" >&2
    return 1
  }
  # The two plugins publish no checksummed Linux binary (connect-go none at
  # all); go install checks their module sums against the checksum database.
  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5
  go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.18.1
  curl -fsSL -o /tmp/protoc.zip \
    https://github.com/protocolbuffers/protobuf/releases/download/v35.1/protoc-35.1-linux-x86_64.zip
  echo '6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7  /tmp/protoc.zip' \
    | sha256sum -c -
  rm -rf "$HOME/.proto-tools/protoc"
  mkdir -p "$HOME/.proto-tools/protoc"
  unzip -o -q /tmp/protoc.zip -d "$HOME/.proto-tools/protoc"
  local go_bin
  go_bin="$(go env GOPATH)/bin"
  export PATH="$HOME/.proto-tools/protoc/bin:$HOME/.proto-tools/bin:$go_bin:$PATH"
  python3 -m venv .venv-proto
  .venv-proto/bin/python -m pip install --quiet \
    'protobuf==7.35.1' \
    'connectrpc==0.11.1' \
    'protoc-gen-connectrpc==0.11.1'
}

run_contracts_proto() {
  local base_sha="${VERIFICATION_PR_BASE_SHA:-${VERIFICATION_PUSH_BEFORE_SHA:-}}"
  install_contract_toolchain
  if [ -z "$base_sha" ] || [[ "$base_sha" =~ ^0+$ ]]; then
    base_sha="$(git rev-parse HEAD^)"
  fi
  (
    cd proto
    buf lint
  )
  python3 scripts/checks/proto_breaking.py --self-test
  BUF="$(command -v buf)" python3 scripts/checks/proto_breaking.py --base-sha "$base_sha"
  (
    cd proto
    rm -rf \
      ../libs/gen-go/codewire \
      ../libs/gen-python/codewire \
      ../packages/codewire-proto-ts/src/gen/codewire
    buf generate --template buf.gen.codewire.yaml
    buf generate --template buf.gen.google-rpc-ts.yaml
    buf generate --template buf.gen.google-rpc-python.yaml
  )
  scripts/ci/proto/build-rust-descriptors.sh
  git diff --exit-code \
    crates/codewire-proto/codewire_descriptor.bin \
    crates/codewire-admin-proto/codewire_admin_descriptor.bin \
    libs/gen-go libs/gen-python packages/codewire-proto-ts/src/gen
  local generated_untracked
  generated_untracked="$(git ls-files --others --exclude-standard -- \
    crates/codewire-proto/codewire_descriptor.bin \
    crates/codewire-admin-proto/codewire_admin_descriptor.bin libs/gen-go libs/gen-python \
    packages/codewire-proto-ts/src/gen)"
  if [ -n "$generated_untracked" ]; then
    printf '%s\n' "$generated_untracked" >&2
    echo 'generated proto code is untracked; run generation and commit it' >&2
    return 1
  fi

  (cd libs/gen-go && GOWORK=off go build ./... && GOWORK=off go vet ./...)
  bun --filter @codewire/proto-ts typecheck
  python3 scripts/checks/repo_checks.py proto-package-boundaries --self-test
  local -a proto_packages=() package
  for package in codewire-proto codewire-admin-proto; do
    if rust_packages_shard_covers "$package"; then
      echo "Contracts: $package's tests run in the Rust / transport packages shard of this run"
    else
      proto_packages+=(-p "$package")
    fi
  done
  [ "${#proto_packages[@]}" -eq 0 ] || cargo test --locked "${proto_packages[@]}"

  PYTHONPATH=libs/gen-python .venv-proto/bin/python - <<'PY'
import py_compile
from pathlib import Path

root = Path("libs/gen-python")
modules = [
    ".".join(path.relative_to(root).with_suffix("").parts)
    for path in sorted(root.rglob("*.py"))
    if path.name.endswith("_pb2.py")
]
for module in modules:
    __import__(module)
stubs = sorted(root.rglob("*_connect.py"))
for stub in stubs:
    py_compile.compile(str(stub), doraise=True)
print(f"generated Python message imports: {len(modules)}; Connect stubs compiled: {len(stubs)}")
PY
}

run_contracts() {
  if ! selected contracts_proto; then
    echo "::error::Contracts selected without contracts_proto"
    exit 1
  fi

  install_bun_dependencies
  run_contracts_proto
}

run_go_support() {
  if selected go_tailnet; then
    scripts/ci/verify/tailnet-parity.sh
  fi
  if selected go_consumer_interop; then
    cargo test --locked -p codewire-server-core \
      --test go_consumer_interop generated_go_client_consumes_rust_connect \
      -- --exact --ignored --nocapture
  fi
}

run_web() {
  install_bun_dependencies
  if rust_packages_shard_covers codewire-dashboard-web; then
    echo "Web: codewire-dashboard-web's tests run in the Rust / transport packages shard of this run"
  else
    cargo test --locked -p codewire-dashboard-web --lib
  fi
  bun run --cwd apps/dashboard typecheck
  bun run --cwd apps/dashboard test:fixtures
  ./apps/dashboard/node_modules/.bin/playwright test \
    --config apps/dashboard/playwright.config.ts --list
  scripts/ci/tests/test-dashboard-browser-gate.sh
  scripts/ci/tests/test-run-design-fixtures.sh
  scripts/ci/verify/run-design-fixtures.sh
  scripts/checks/security/audit-js-supply-chain.sh
  scripts/checks/security/audit-runtime-images.sh --self-test
  scripts/checks/security/audit-runtime-images.sh
  if selected kind; then
    echo 'dashboard image verification deferred to the exact-image Kind transaction'
  elif [ "${CODEWIRE_DASHBOARD_IMAGE_DEFERRED:-false}" = true ]; then
    echo 'dashboard image verification left to Dev delivery, which builds the exact image'
  else
    run_dashboard_image
  fi
}

# The Zola docs site, built and checked (internal links, deterministic output,
# routes and page contracts) by the dashboard image's own docs stage with its
# checksum-pinned Zola. Nothing is exported; the image build is web's.
run_docs() {
  docker buildx build --file apps/dashboard/Dockerfile --target docs-builder \
    --output type=cacheonly .
}

run_dashboard_image() {
  make verify-dashboard-image \
    DASHBOARD_VERIFY_IMAGE="codewire-dashboard:verification-${GITHUB_RUN_ID:-local}"
}

run_ios_config() {
  python3 - <<'PY'
from pathlib import Path
import plistlib

root = Path("apps/ios")
if "infoPath: Resources/Info.plist" not in (root / "xtool.yml").read_text():
    raise SystemExit("xtool must use the source-owned Info.plist")
with (root / "Resources/Info.plist").open("rb") as stream:
    info = plistlib.load(stream)
schemes = [
    scheme
    for entry in info.get("CFBundleURLTypes", [])
    for scheme in entry.get("CFBundleURLSchemes", [])
]
if schemes != ["sh.codewire.ios"]:
    raise SystemExit("Info.plist must register exactly the iOS OAuth callback scheme")
PY
}

run_ios() {
  run_ios_config
  make ios-test
}

# The iOS package's Swift tests in the pinned Swift image (Standard's ios
# family; make ios-test is the local equivalent).
run_ios_swift_package() {
  run_ios_config
  docker build --file - apps/ios <<'DOCKERFILE'
FROM swift@sha256:0ff707a48519cf1473616c759e019bcff21cfbafa3d2687bf8fd41a2757adc9a
WORKDIR /workspace
COPY . .
RUN swift test --scratch-path /tmp/codewire-ios-build
DOCKERFILE
}

# Standard verification's selected families (infra#1534): Web side by side
# with the others in order, so the job takes the longer of the two (main run
# 23329: 626 s with every family one after another). The first failure stops
# the rest (#3013). Each family keeps the selection condition its own step
# had. Contracts is not one of them: it runs in its own job beside Standard
# (run-product-verification.sh contracts), in its own checkout, and fails when
# the generated code it regenerates differs from the checked-in code these
# families read (main run 23934: Contracts ran alone first for about 175 s).
standard_families() {
  local family token
  for family in go-support:go_support docs:docs sdk-go:sdk_go sdk-ts:sdk_ts \
      sdk-python:sdk_python ios:ios; do
    token="${family#*:}"
    if selected "$token"; then printf '%s\n' "${family%%:*}"; fi
  done
}

run_standard_family() {
  case "$1" in
    go-support) run_go_support ;;
    web) CODEWIRE_DASHBOARD_IMAGE_DEFERRED=true run_web ;;
    docs) run_docs ;;
    sdk-go) run_sdk_go ;;
    sdk-ts) run_sdk_ts ;;
    sdk-python) run_sdk_python ;;
    ios) run_ios_swift_package ;;
    *) echo "::error::unknown Standard family: $1" >&2; return 2 ;;
  esac
}

run_standard_in_order() {
  local family
  for family in "$@"; do
    echo "[standard] $family: start"
    run_standard_family "$family" || return $?
    echo "[standard] $family: finish"
  done
}

run_standard() {
  local -a others=() lanes=()
  mapfile -t others < <(standard_families)
  if selected web; then lanes+=('run_standard_in_order web'); fi
  if [ "${#others[@]}" -gt 0 ]; then lanes+=("run_standard_in_order ${others[*]}"); fi
  if [ "${#lanes[@]}" -eq 0 ]; then
    echo 'Standard: no family is selected (Contracts runs in its own job)'
    return 0
  fi
  printf 'Standard families side by side: %s\n' "${lanes[*]}"
  VERIFICATION_TEST_JOBS="${#lanes[@]}" run_side_by_side < <(printf '%s\n' "${lanes[@]}")
}

run_sdk_go() {
  (cd libs/sdk-go && GOWORK=off go build ./... && GOWORK=off go vet ./... \
    && GOWORK=off go test ./... -count=1 -timeout 60s)
}

run_sdk_ts() {
  make test-sdk-ts
  local package_work
  package_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-ts-package.XXXXXX")"
  scripts/ci/release/package-sdk-ts.sh "$package_work"
  rm -rf -- "$package_work"
  scripts/runtime/tests/test-run-sdk-ts-e2e.sh
}

run_sdk_python() {
  local repository_root="$PWD"
  local package_work sdist wheel
  package_work="$(mktemp -d "${TMPDIR:-/tmp}/codewire-sdk-python-package.XXXXXX")"
  python3 -m venv .venv-sdk
  .venv-sdk/bin/python -m pip install --upgrade pip
  scripts/ci/release/package-sdk-python.sh "$package_work/dist"
  sdist="$(find "$package_work/dist" -maxdepth 1 -type f -name '*.tar.gz' -print -quit)"
  wheel="$(find "$package_work/dist" -maxdepth 1 -type f -name '*.whl' -print -quit)"
  [ -n "$sdist" ]
  [ -n "$wheel" ]
  .venv-sdk/bin/python -m pip install --require-hashes \
    -r libs/sdk-python/requirements.lock
  .venv-sdk/bin/python -m pip install --force-reinstall --no-deps "$wheel"
  local sdk_site_packages forbidden_package
  sdk_site_packages="$(
    .venv-sdk/bin/python -c \
      'import sysconfig; print(sysconfig.get_paths()["purelib"])'
  )"
  [ -d "$sdk_site_packages/codewire/v1" ]
  [ -d "$sdk_site_packages/google/rpc" ]
  for forbidden_package in admin console internal testing; do
    if [ -e "$sdk_site_packages/codewire/$forbidden_package" ]; then
      echo "::error::Python SDK wheel leaked generated codewire/$forbidden_package" >&2
      return 1
    fi
  done
  (cd libs/sdk-python && PYTHONPATH="$repository_root/libs/gen-python${PYTHONPATH:+:$PYTHONPATH}" \
    "$repository_root/.venv-sdk/bin/python" -m unittest test_sdk test_transport test_cw_runtime -v)
  (cd /tmp && "$repository_root/.venv-sdk/bin/python" -c \
    'from codewire._transport import ConnectTransport; from codewire.errors import CodewireError; from codewire.v1.api_key_connect import ApiKeyServiceClientSync; from google.rpc.error_details_pb2 import BadRequest; assert CodewireError and BadRequest and isinstance(ConnectTransport("https://codewire.example", "").client(ApiKeyServiceClientSync), ApiKeyServiceClientSync)')
  scripts/runtime/tests/test-run-sdk-python-e2e.sh
  rm -rf -- "$package_work"
}

run_confidential_script_tests() {
  scripts/runtime/tests/test-resolve-coco-support-lock.sh
  scripts/runtime/tests/test-confidential-snp-smoke-contract.sh
  scripts/runtime/tests/test-confidential-binding-proof.sh
  scripts/runtime/tests/test-confidential-storage-proof.sh
}

# The Dev smoke script tests are independent once the dashboard's
# dependencies are installed; run_side_by_side runs them side by side.
run_dev_smoke_script_tests() {
  install_bun_dependencies
  run_side_by_side <<'STEPS'
  bun test apps/dashboard/scripts/prepare-dev-smoke-browser-auth.test.ts
  bun test apps/dashboard/scripts/dev-ux-ownership.test.ts
  scripts/runtime/tests/test-provision-dev-smoke-user.sh
  scripts/runtime/tests/test-provision-prod-smoke-user.sh
  scripts/runtime/tests/test-smoke-dev-commodity.sh
  scripts/runtime/tests/test-smoke-dev-transport-matrix.sh
  scripts/runtime/tests/test-workspace-binding-proof.sh
  scripts/runtime/tests/test-warm-pool-proof.sh
  scripts/runtime/tests/test-vm-death-recovery-proof.sh
  scripts/runtime/tests/test-sandbox-capacity-load.sh
  scripts/runtime/tests/test-runtime-memory-fill-proof.sh
  scripts/runtime/tests/test-kill-test-overhead-matrix.sh
  scripts/runtime/tests/test-kill-test-round.sh
  scripts/runtime/tests/test-local-platform-sources-smoke.sh
  scripts/runtime/tests/test-private-checkout-smoke.sh
  scripts/runtime/tests/test-dev-initial-private-checkout.sh
  python3 -B scripts/runtime/tests/test-hosted-checkout-fixture.py
  scripts/runtime/tests/test-provider-codex-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-codex-workload.py
  scripts/runtime/tests/test-provider-github-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-github-workload.py
  scripts/runtime/tests/test-provider-anthropic-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-anthropic-workload.py
  scripts/runtime/tests/test-provider-openai-smoke.sh
  python3 -B scripts/runtime/tests/test-provider-openai-workload.py
  scripts/runtime/tests/test-secrets-credentials-acceptance-runner.sh
  python3 -B scripts/runtime/tests/test-native-mesh-listener.py
STEPS
}

run_rust() {
  if rust_shard local-vmm && selected rust_pkg_codewire_desktop; then
    run_detached_desktop
  fi
  if rust_shard packages && has_root_rust_selection; then
    run_rust_packages rust_pkg_
  fi
  rust_shard features || return 0
  check_shard_stage || return $?
  if shard_stage tests && { selected rust_workspace || selected rust_pkg_codewire_cli || selected rust_pkg_codewire_cli_bin; }; then
    python3 -B scripts/ci/tests/test-cli-host-managed.py || return $?
    python3 -B scripts/ci/tests/test-cli-update-mesh-endpoints.py || return $?
    python3 -B scripts/ci/tests/test-build-cw-release-dir.py
  fi
  if shard_stage checks && { selected rust_workspace || selected rust_pkg_codewire_cli \
      || selected rust_pkg_codewire_cli_bin || selected rust_pkg_codewire_admin_proto \
      || selected rust_pkg_codewire_proto; }; then
    scripts/ci/tests/test-admin-proto-boundary.sh --cli-dependencies
  fi
  if shard_stage checks && { selected rust_workspace || selected rust_pkg_codewire_protected_store \
      || selected rust_pkg_codewire_orchestration; }; then
    scripts/ci/tests/test-openbao-only-secret-authority.sh --production-features
  fi
  if selected rust_workspace || selected rust_pkg_codewire_protected_store; then
    # Platform primitives are optional; default workspace/package tests alone
    # do not promise that their tests or warning-denied targets are exercised.
    if shard_stage checks; then
      cargo clippy --locked -p codewire-protected-store --features platform --all-targets -- -D warnings
    fi
    shard_test protected-store-platform '' \
      -p codewire-protected-store --features platform --all-targets
  fi
  if selected rust_workspace || selected rust_pkg_codewire_credential_broker; then
    # Exercise the isolated platform build explicitly; the default local
    # feature cannot qualify platform admission or its production graph.
    if shard_stage checks; then
      scripts/ci/tests/test-openbao-only-secret-authority.sh --production-broker-features
      cargo clippy --locked -p codewire-credential-broker --no-default-features --features platform --all-targets -- -D warnings
    fi
    shard_test credential-broker-platform '' \
      -p codewire-credential-broker --no-default-features --features platform --all-targets
  fi
  if selected rust_workspace || selected rust_pkg_codewire_server_core \
      || selected rust_pkg_codewire_orchestration; then
    # The shared projected-Pod verifier is opt-in. Exercise its real feature
    # and focused identity tests without depending on workspace unification.
    if shard_stage checks; then
      cargo clippy --locked -p codewire-server-core --features kubernetes-identity --all-targets -- -D warnings
    fi
    shard_test server-core-kubernetes-identity '-E test(pod_identity::)' \
      -p codewire-server-core --features kubernetes-identity --lib -- pod_identity::
  fi
  if selected rust_workspace || selected rust_pkg_codewire_credential_service; then
    if shard_stage checks; then
      scripts/ci/tests/test-openbao-only-secret-authority.sh --production-service-features
      cargo clippy --locked -p codewire-credential-service --features enrollment --all-targets -- -D warnings
    fi
    shard_test credential-service-enrollment '' \
      -p codewire-credential-service --features enrollment --all-targets
  fi
  if selected rust_workspace || selected rust_pkg_codewire_cli_bin; then
    run_host_interface_refusal
  fi
  if selected rust_workspace || selected rust_pkg_codewire_daemon; then
    run_daemon_stock_gh
  fi
  if selected rust_pkg_codewire_oidc; then
    if shard_stage checks; then
      cargo check -p codewire-oidc --no-default-features
    fi
    shard_test oidc-axum '' -p codewire-oidc --features axum
    if shard_stage checks; then
      cargo run -p codewire-oidc --example in_memory >/dev/null
    fi
  fi
}

run_rust_curated_locks() {
  scripts/ci/tests/test-curated-rust-locks.sh
}

run_rust_compile() {
  scripts/ci/verify/compile-all-targets.sh
}

# The tailnet client's own proofs against the real relay binary: two Rust
# DERP clients relay a packet through it, and two Conns tunnel through it.
run_tailnet_real_derp() {
  CODEWIRE_DERP_BIN="$(realpath "$1")" shard_test tailnet-real-derp \
    '--run-ignored only -E test(=conn::tests::real_derp_tunnel)|test(=derp::tests::derp_interop_relay_two_rust_clients_via_server_binary)' \
    -p codewire-tailnet --lib -- --ignored --exact \
    conn::tests::real_derp_tunnel derp::tests::derp_interop_relay_two_rust_clients_via_server_binary
}

run_derp_contract() {
  # The packages shard builds this binary in its own job. Build it here so the
  # local-vmm shard stands alone; under "all" the graph already built it.
  # Compile once: the archives stage builds it into RUST_SHARD_ARCHIVES, and
  # the tests stage runs the contract against that build.
  local derp="$CARGO_DEBUG_DIR/codewire-derp"
  case "$RUST_SHARD_STAGE" in
    checks) return 0 ;;
    archives)
      cargo build --locked -p codewire-derp --bin codewire-derp || return $?
      install -m 0755 "$derp" "$RUST_SHARD_ARCHIVES/codewire-derp"
      run_tailnet_real_derp "$derp"
      return
      ;;
    tests)
      derp="$RUST_SHARD_ARCHIVES/codewire-derp"
      [ -x "$derp" ] || {
        echo '::error::no codewire-derp in the shard archives; the build runner built none for this selection' >&2
        return 1
      }
      ;;
    *) cargo build --locked -p codewire-derp --bin codewire-derp || return $? ;;
  esac
  local port=$((61000 + (${GITHUB_RUN_ID:-$$} % 4000)))
  local log_dir="${RUNNER_TEMP:-$ROOT/.tmp}/codewire-derp-contract-${GITHUB_RUN_ID:-$$}"
  mkdir -p "$log_dir"
  (
    PORT="$port" TLS_PORT='' STUN_PORT=-1 RUST_LOG=info \
      "$derp" > "$log_dir/derp.log" 2>&1 &
    local pid=$!
    trap 'kill "$pid" 2>/dev/null || true' EXIT
    local _
    for _ in $(seq 1 45); do
      if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
        break
      fi
      if ! kill -0 "$pid" 2>/dev/null; then
        cat "$log_dir/derp.log" >&2
        exit 1
      fi
      sleep 1
    done
    if ! curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null; then
      cat "$log_dir/derp.log" >&2
      exit 1
    fi
    (
      cd tests/contract
      DERP_BASE_URL="http://127.0.0.1:${port}/derp" GOWORK=off \
        go test -count=1 -v \
          -run '^TestRawHTTPUpgradeRelaysTailscaleGoClients$' ./derp/... \
          | tee "$log_dir/derp-contract.log"
      DERP_BASE_URL="http://127.0.0.1:${port}/derp" DERP_WEBSOCKET=1 \
        GOWORK=off go test -tags ts_debug_websockets -count=1 -v \
        -run '^TestWebSocketFallbackRelaysTailscaleGoClients$' ./derp/... \
        | tee "$log_dir/derp-websocket-contract.log"
    )
    local logfile
    for logfile in "$log_dir/derp-contract.log" \
        "$log_dir/derp-websocket-contract.log"; do
      if grep -Eq -- '--- SKIP' "$logfile" \
        || ! grep -Eq -- '^[[:space:]]*--- PASS:' "$logfile"; then
        echo "::error::DERP contract reported a skip or no executed test: ${logfile}"
        exit 1
      fi
    done
  )
  run_tailnet_real_derp "$derp"
}

privileged_mount_namespace_available() {
  if [[ "$(id -u)" == 0 ]]; then
    unshare --mount true 2>/dev/null
  else
    sudo -n unshare --mount true 2>/dev/null
  fi
}

# The static guest's reproducibility proof (two fresh release musl builds)
# runs for the guest's own build inputs and on every push to main, as the
# selector's static_guest_proof says (infra#1534). A selection without
# static_guest_proof_omittable, from an older selector, keeps it.
static_guest_proof_runs() {
  selected static_guest_proof || ! selected static_guest_proof_omittable
}

run_transport() {
  if rust_shard packages; then
    run_rust_packages transport_pkg_
  fi
  rust_shard local-vmm || return 0
  check_shard_stage || return $?
  if shard_stage tests && { selected transport_pkg_codewire_local_vmm || selected transport_pkg_codewire_vmm_guest_probe; }; then
    python3 -B scripts/dev/test-cw-runtime-image.py
    python3 -B scripts/dev/test-cli-native-managed.py --self-test
    python3 -B scripts/dev/test-cli-native-update.py --self-test
    python3 -B scripts/ci/tests/test-native-managed-update-entrypoint.py
  fi
  if selected transport_pkg_codewire_local_vmm; then
    if shard_stage tests; then
      python3 crates/codewire-local-vmm/macos-vz-runner/Tests/test_static_contract.py
    fi
    if shard_stage checks; then
      scripts/ci/verify/check-darwin-cross.sh
    fi
  fi
  if selected transport_pkg_codewire_vmm_guest_probe; then
    # These kernel fixtures need a private mount namespace, which only root
    # with CAP_SYS_ADMIN (directly or through sudo -n) can create. An
    # unprivileged CI container cannot; it says so instead of passing. Their
    # archives are built whatever the test job's privilege turns out to be.
    if [ "$RUST_SHARD_STAGE" = archives ] || { shard_stage tests && privileged_mount_namespace_available; }; then
      shard_test guest-probe-live-mount \
        '--run-ignored only -E test(=cw_runtime_publisher::tests::live_runtime_readonly_mount_exposes_new_members_without_replacing_old_bytes)' \
        -p codewire-vmm-guest-probe --lib -- --ignored --exact \
        cw_runtime_publisher::tests::live_runtime_readonly_mount_exposes_new_members_without_replacing_old_bytes
      shard_test guest-probe-live-launcher \
        '--run-ignored only -E test(=source_launcher_login_shell_selects_a_b_a_on_readonly_mounts)' \
        -p codewire-vmm-guest-probe --test cw-runtime-live -- --ignored --exact \
        source_launcher_login_shell_selects_a_b_a_on_readonly_mounts
    elif shard_stage tests; then
      echo '::notice::guest-probe kernel fixtures not run: no CAP_SYS_ADMIN here; run this shard on a workstation with sudo'
    fi
    if shard_stage checks && static_guest_proof_runs; then
      scripts/ci/verify/build-local-vmm-initramfs.sh --verify
    fi
  fi
  if selected transport_derp_contract; then
    run_derp_contract
  fi
}

install_caddy() {
  local version="${CADDY_VERSION:-2.10.2}"
  mkdir -p "$HOME/.local/bin"
  (
    cd /tmp
    curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v${version}/caddy_${version}_linux_amd64.tar.gz"
    curl -fsSLO "https://github.com/caddyserver/caddy/releases/download/v${version}/caddy_${version}_checksums.txt"
    grep "caddy_${version}_linux_amd64.tar.gz" \
      "caddy_${version}_checksums.txt" | sha512sum -c -
    tar -xzf "caddy_${version}_linux_amd64.tar.gz" caddy
    install caddy "$HOME/.local/bin/caddy"
  )
  export PATH="$HOME/.local/bin:$PATH"
}

# The cw runtime probe runs in a sandbox as the workspace user (UID and GID
# 1000), and its kernel fixture requires that identity. Hosted jobs run as
# root, where the fixture failed and cancelled every Edge/Kind run. Run it
# there as that user, on a private copy of the committed tree it can write to.
# Like the Pod's home, every directory above the copy must be owned by root or
# that user and writable by neither group nor others; the job's temporary
# directory is world-writable (/tmp is 1777), so the copy goes in a fresh
# root-owned directory directly under PARENT (the filesystem root).
run_kind_cw_runtime_probe_fixture() {
  local parent="${1:-/}"
  if [[ "$(id -u)" != 0 ]]; then
    python3 -B scripts/ci/tests/test-kind-cw-runtime-probe.py
    return
  fi
  local scratch status=0
  scratch="$(mktemp -d "${parent%/}/codewire-cw-probe-fixture.XXXXXX")"
  {
    chmod 0755 "$scratch" \
      && mkdir "$scratch/tree" \
      && git archive --format=tar HEAD | tar -x -C "$scratch/tree" \
      && mkdir "$scratch/tree/.tmp" \
      && chown -R 1000:1000 "$scratch/tree" \
      && (cd "$scratch/tree" && HOME="$scratch/tree/.tmp" setpriv --reuid=1000 --regid=1000 --clear-groups \
            python3 -B scripts/ci/tests/test-kind-cw-runtime-probe.py)
  } || status=$?
  rm -rf -- "$scratch"
  return "$status"
}

run_edge() {
  (
  isolate_kind_fixture_environment
  install_caddy
  caddy validate --config Caddyfile --adapter caddyfile
  caddy validate --config Caddyfile.docker --adapter caddyfile
  local file pattern
  for file in Caddyfile Caddyfile.docker; do
    grep -qF '*.codewire.localhost {' "$file"
    grep -qF '@billing path /api/webhooks/stripe' "$file"
    grep -qF '/codewire.admin.v1.BillingCatalogService/*' "$file"
    grep -qF '/codewire.console.v1.BillingService/*' "$file"
    for pattern in \
        /api/v1/admin/billing /api/v1/billing/plans \
        '/api/v1/organizations/[^/]+/billing' \
        '/api/v1/organizations/[^/]+/environments/usage'; do
      if grep -qF "$pattern" "$file"; then
        echo "::error file=${file}::retired billing REST matcher remains: ${pattern}"
        return 1
      fi
    done
    grep -qF '/api/webhooks/stripe' "$file"
    grep -qF 'handle /api/* {' "$file"
    grep -qE 'reverse_proxy (localhost|127.0.0.1):8084' "$file"
    if grep -qE 'reverse_proxy (localhost|127.0.0.1):8080' "$file"; then
      echo "::error file=${file}::edge routes API traffic to the retired Go server"
      return 1
    fi
  done
  python3 scripts/checks/repo_checks.py connect-edge-routing --self-test
  )
}

# The Kind tool tests run with Edge static verification when the trusted
# selection asks for them (#3119 R8). A selection from an older trusted
# selector has no kind_tools_omittable and keeps them.
kind_tools_selected() {
  selected kind_tools || ! selected kind_tools_omittable
}

run_edge_family() {
  run_edge
  if kind_tools_selected; then
    run_kind_tools
  else
    echo 'Kind tool tests: not selected; no Kind tool or input they read changed'
  fi
}

# The Kind tool tests are independent; run_side_by_side runs them side by
# side. The developer-profile suite, about three minutes of tests in order,
# runs as six disjoint shards that together run every test, longest first.
run_kind_tools() {
  (
  isolate_kind_fixture_environment
  run_side_by_side <<'STEPS'
  CODEWIRE_TEST_SHARD=0/6 python3 -B scripts/ci/tests/test-kind-dev-profile.py
  CODEWIRE_TEST_SHARD=1/6 python3 -B scripts/ci/tests/test-kind-dev-profile.py
  CODEWIRE_TEST_SHARD=2/6 python3 -B scripts/ci/tests/test-kind-dev-profile.py
  CODEWIRE_TEST_SHARD=3/6 python3 -B scripts/ci/tests/test-kind-dev-profile.py
  CODEWIRE_TEST_SHARD=4/6 python3 -B scripts/ci/tests/test-kind-dev-profile.py
  CODEWIRE_TEST_SHARD=5/6 python3 -B scripts/ci/tests/test-kind-dev-profile.py
  scripts/ci/tests/test-kind-e2e-cleanup.sh
  scripts/ci/tests/test-kind-e2e-suites.sh
  run_kind_cw_runtime_probe_fixture
  python3 -B scripts/ci/tests/test-kind-cluster-profiles.py
  python3 -B scripts/ci/tests/test-kind-profile-artifacts.py
  python3 -B scripts/ci/tests/test-kind-profile-gate.py
  scripts/ci/tests/test-kind-forwards.sh
  scripts/ci/tests/test-kind-trust-roots.sh
  python3 -B scripts/ci/tests/test-kind-codex-session.py
  python3 -B scripts/ci/tests/test-kind-codex-login.py
  python3 -B scripts/ci/tests/test-kind-claude-login.py
  python3 -B scripts/ci/tests/test-kind-credentials.py
STEPS
  )
}

run_release() {
  # Every step is independent; run_side_by_side runs them side by side. The
  # image builder's test runs as its four parts, longest first.
  run_side_by_side <<'STEPS'
  scripts/ci/tests/test-build-push-image.sh kind
  scripts/ci/tests/test-build-push-image.sh support
  scripts/ci/tests/test-build-push-image.sh publish
  scripts/ci/tests/test-build-push-image.sh builds
  scripts/ci/tests/test-base-image-source.sh
  scripts/ci/tests/test-apt-get-with-retry.sh
  scripts/ci/tests/test-build-cw-linux.sh
  scripts/ci/tests/test-run-rust-build.sh
  scripts/ci/tests/test-fetch-openbao-ghcr-credentials.sh
  scripts/ci/tests/test-fetch-openbao-harbor-credentials.sh
  scripts/ci/tests/test-fetch-openbao-github-mirror-credentials.sh
  scripts/ci/tests/test-forgejo-action-mirrors.sh
  scripts/ci/tests/test-harbor-runtime-pull-contract.sh
  scripts/ci/tests/test-verify-release-tag-ref.sh
  scripts/ci/tests/test-verify-release-tag-receipt.sh
  scripts/ci/tests/test-require-production-accepted.sh
  scripts/ci/tests/test-deploy-prod-helpers.sh
  scripts/ci/tests/test-find-pending-release.sh
  scripts/ci/tests/test-verify-release-support-pair.sh
  scripts/ci/tests/test-mirror-git-tags.sh
  scripts/ci/tests/test-check-mirror-content.sh
  scripts/ci/tests/test-mint-github-app-token.sh
  scripts/ci/tests/test-copy-image-to-ghcr.sh
  scripts/ci/tests/test-dispatch-deploy-dev.sh
  scripts/ci/tests/test-fetch-forgejo-deploy-dev-token.sh
  scripts/ci/tests/test-dispatch-deploy-prod.sh
  scripts/ci/tests/test-publish-image-to-ghcr.sh
  scripts/ci/tests/test-publish-image-to-harbor.sh
  scripts/ci/tests/test-alias-support-pair.sh
  scripts/ci/tests/test-sign-runtime-image-set.sh
  scripts/ci/tests/test-verify-runtime-image-signatures.sh
  scripts/ci/tests/test-resolve-published-support-pair.sh
  scripts/ci/tests/test-run-skopeo-container.sh
  scripts/ci/tests/test-fetch-pinned.sh
  scripts/ci/tests/test-support-images-workflow.sh
  scripts/ci/tests/test-run-workspace-contract-on-image.sh
  scripts/ci/tests/test-propose-workspace-image-pin.sh
  scripts/ci/tests/test-fetch-openbao-workspace-pin-bot-token.sh
  python3 -B scripts/ci/tests/test-sdk-release-workflow.py
  python3 scripts/ci/tests/test-image-bundle.py
  scripts/ci/tests/test-deploy-prod-workflow.sh
  python3 scripts/checks/repo_checks.py production-source-ownership --self-test
STEPS
}

download_ci_tool() {
  local url="$1" output="$2"
  curl --fail --silent --show-error --location \
    --retry 5 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
    --output "$output" "$url"
}

install_kustomize() {
  local version="${KUSTOMIZE_VERSION:-v5.4.3}" download
  mkdir -p "$HOME/.local/bin"
  # Deploy and Security can install it at once (run_tooling): each downloads
  # into its own directory and replaces the binary in one rename.
  download="$(mktemp -d "${TMPDIR:-/tmp}/kustomize.XXXXXX")"
  (
    cd "$download"
    download_ci_tool \
      "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${version}/kustomize_${version}_linux_amd64.tar.gz" \
      "kustomize_${version}_linux_amd64.tar.gz"
    download_ci_tool \
      "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/${version}/checksums.txt" \
      checksums.txt
    grep "kustomize_${version}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -
    tar -xzf "kustomize_${version}_linux_amd64.tar.gz" kustomize
    install -m 0755 kustomize "$HOME/.local/bin/.kustomize.$$"
    mv -f "$HOME/.local/bin/.kustomize.$$" "$HOME/.local/bin/kustomize"
  ) || { rm -rf -- "$download"; return 1; }
  rm -rf -- "$download"
  export PATH="$HOME/.local/bin:$PATH"
}

install_helm() {
  local version="${HELM_VERSION:-v3.16.4}"
  local installed_version
  command -v helm >/dev/null 2>&1 || {
    echo "::error::CI runner image is missing sealed Helm ${version}" >&2
    return 1
  }
  installed_version="$(helm version --template '{{.Version}}')"
  if [ "$installed_version" != "$version" ]; then
    echo "::error::CI runner image Helm version ${installed_version} differs from ${version}" >&2
    return 1
  fi
}

run_deploy() {
  scripts/ci/tests/test-install-temporal.sh
  # Policy runs the planner's suite for its own inputs (policy-planner-tests).
  # A selection without policy (a deploy dispatch, a release tag) cannot say
  # so, and runs it here.
  if ! selected ci_plan_tests_omittable; then
    scripts/ci/plan/test.sh
  fi
  scripts/ci/tests/test-deploy-dev.sh
  scripts/ci/tests/test-build-push-runtime-images.sh
  python3 -B scripts/ci/tests/test-rerun-dev-publish.py
  python3 -B scripts/ci/tests/test-cancel-superseded-deliveries.py
  install_kustomize
  python3 scripts/checks/repo_checks.py orchestration-authz --self-test

  local overlay
  for overlay in \
      deployments/k8s/base deployments/k8s/coordinator deployments/k8s/idp \
      deployments/k8s/orchestration deployments/k8s/credential-service \
      deployments/k8s/derp \
      deployments/k8s/overlays/local-kind \
      deployments/k8s/overlays/local-kind-static \
      tests/e2e/kind; do
    kustomize build "$overlay" >/dev/null
  done

  local dashboard_manifest dashboard_source
  for dashboard_source in \
      deployments/k8s/dashboard/deployment.yaml \
      deployments/k8s/overlays/local-kind/dashboard.yaml \
      deployments/k8s/overlays/local-kind-static/dashboard.yaml; do
    dashboard_manifest="$(<"$dashboard_source")"
    grep -Fq 'name: CODEWIRE_IDENTITY_ORIGIN' <<<"$dashboard_manifest"
    grep -Fq 'http://codewire-idp:8091' <<<"$dashboard_manifest"
    grep -Fq 'automountServiceAccountToken: false' <<<"$dashboard_manifest"
    grep -Fq 'allowPrivilegeEscalation: false' <<<"$dashboard_manifest"
    grep -Fq 'drop: ["ALL"]' <<<"$dashboard_manifest"
    grep -Fq 'readOnlyRootFilesystem: true' <<<"$dashboard_manifest"
    grep -Fq 'runAsUser: 65532' <<<"$dashboard_manifest"
    grep -Fq 'runAsGroup: 65532' <<<"$dashboard_manifest"
    grep -Fq 'type: RuntimeDefault' <<<"$dashboard_manifest"
  done

  install_helm
  scripts/ci/tests/test-deploy-mesh-ingress-protocol.sh
  local default_mesh_render
  default_mesh_render="$(helm template test apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test)"
  grep -Fq 'command: ["codewire-mesh"]' <<<"$default_mesh_render"
  grep -Fq -- '- "--base-url=https://mesh.test"' <<<"$default_mesh_render"
  if grep -Fq -- '--database-url' <<<"$default_mesh_render" ||
      grep -Fq 'exec codewire-mesh' <<<"$default_mesh_render" ||
      grep -Fq 'command: ["sh"' <<<"$default_mesh_render"; then
    echo "::error::Mesh deployment rendered a shell or database credential argv path"
    return 1
  fi
  if grep -Fq 'prelaunch-retire-legacy-auth' <<<"$default_mesh_render"; then
    echo "::error::retired Mesh legacy-auth command rendered"
    return 1
  fi
  local dev_mesh_render database_reference_canary_render
  dev_mesh_render="$(helm template codewire-mesh-dev apps/cli/charts/codewire-mesh \
    -f deployments/k8s/mesh-dev/values.yaml \
    --set image.repository=registry.test/codewire/mesh --set image.tag=test)"
  grep -q 'mesh.codewire-dev.sh' <<<"$dev_mesh_render"
  grep -Fq 'command: ["codewire-mesh"]' <<<"$dev_mesh_render"
  if grep -Fq -- '--database-url' <<<"$dev_mesh_render" ||
      grep -Fq 'exec codewire-mesh' <<<"$dev_mesh_render" ||
      grep -Fq 'command: ["sh"' <<<"$dev_mesh_render"; then
    echo "::error::hosted Mesh deployment rendered a shell or database credential argv path"
    return 1
  fi
  grep -Fq 'name: DATABASE_URL' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-mesh-db-app' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_URL' <<<"$dev_mesh_render"
  grep -Fq 'https://codewire-orchestration.dev.svc.cluster.local:8088' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_TLS_ROOTS_FILE' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-orchestration-internal-roots' <<<"$dev_mesh_render"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_HMAC_SECRET' <<<"$dev_mesh_render"
  grep -Fq 'name: codewire-mesh-coordinator' <<<"$dev_mesh_render"
  grep -Fq 'nginx.ingress.kubernetes.io/backend-protocol: "GRPC"' <<<"$dev_mesh_render"
  grep -Fq 'path: /codewire\.internal\.v1\.MeshCoordinatorService/' <<<"$dev_mesh_render"
  database_reference_canary_render="$(helm template codewire-mesh-canary \
    apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test \
    --set database.enabled=true \
    --set database.secretName=synthetic-database-credential-canary \
    --set database.uriKey=synthetic-database-uri-key-canary \
    --set meshAuthorization.url=https://authorization.test:8088 \
    --set meshAuthorization.tlsRootsConfigMap=synthetic-internal-roots \
    --set meshAuthorization.hmacSecretRef.name=synthetic-hmac-secret)"
  grep -Fq 'name: synthetic-database-credential-canary' \
    <<<"$database_reference_canary_render"
  grep -Fq 'key: synthetic-database-uri-key-canary' \
    <<<"$database_reference_canary_render"
  if grep -Fq -- '--database-url' <<<"$database_reference_canary_render" ||
      grep -Fq 'exec codewire-mesh' <<<"$database_reference_canary_render" ||
      grep -Fq 'command: ["sh"' <<<"$database_reference_canary_render"; then
    echo "::error::synthetic database reference entered the Mesh argv path"
    return 1
  fi
  if helm template codewire-mesh-tls-canary apps/cli/charts/codewire-mesh \
      --set mesh.baseURL=https://mesh.test \
      --set meshAuthorization.url=https://authorization.test:8088 \
      --set meshAuthorization.hmacSecretRef.name=synthetic-hmac-secret >/dev/null 2>&1; then
    echo "::error::an https Mesh authorization URL rendered without its public roots"
    return 1
  fi
  if helm template codewire-mesh-plaintext-canary apps/cli/charts/codewire-mesh \
      --set mesh.baseURL=https://mesh.test \
      --set meshAuthorization.url=http://authorization.test:8085 \
      --set meshAuthorization.tlsRootsConfigMap=synthetic-internal-roots \
      --set meshAuthorization.hmacSecretRef.name=synthetic-hmac-secret >/dev/null 2>&1; then
    echo "::error::a plaintext Mesh authorization URL rendered"
    return 1
  fi
  local mesh_tls_render
  mesh_tls_render="$(helm template codewire-mesh-tls apps/cli/charts/codewire-mesh \
    --set mesh.baseURL=https://mesh.test \
    --set meshAuthorization.url=https://authorization.test:8088 \
    --set meshAuthorization.tlsRootsConfigMap=synthetic-internal-roots \
    --set meshAuthorization.hmacSecretRef.name=synthetic-hmac-secret)"
  grep -Fq 'name: CODEWIRE_MESH_AUTHORIZATION_TLS_ROOTS_FILE' <<<"$mesh_tls_render"
  grep -Fq 'name: synthetic-internal-roots' <<<"$mesh_tls_render"
  python3 scripts/checks/repo_checks.py production-source-ownership --self-test
}

run_security() {
  if selected security_dev_smoke_auth; then
    scripts/runtime/tests/test-with-dev-smoke-auth.sh
    scripts/runtime/tests/test-with-prod-smoke-auth.sh
  fi
  if selected security_idp_kek; then
    install_kustomize
    python3 scripts/checks/repo_checks.py idp-signing-kek-isolation
  fi
  if selected security_js; then
    scripts/checks/security/audit-js-supply-chain.sh
  fi
  if selected security_go; then
    local module
    for module in "${GO_MODULE_DIRS[@]}"; do
      (cd "$module" && GOWORK=off go mod verify)
    done
    local go_bin
    go_bin="$(go env GOPATH)/bin"
    export PATH="$go_bin:$PATH"
    go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
    go install honnef.co/go/tools/cmd/staticcheck@2026.2.2
    go install github.com/securego/gosec/v2/cmd/gosec@latest
    for module in "${GO_MODULE_DIRS[@]}"; do
      (cd "$module" && GOWORK=off govulncheck ./...)
    done
    staticcheck -checks 'all,-SA1019,-ST1000,-ST1003' \
      "${GO_PACKAGE_PATTERNS[@]}"
    gosec -no-fail -quiet "${GO_PACKAGE_PATTERNS[@]}"
  fi
}

# Families that compile share the workstation's local compiler cache. Policy
# families run cache-selection fixtures and must see the caller's environment.
case "$FAMILY" in
  contracts|go-support|web|rust|rust-transport|rust-compile|transport)
    select_local_rust_cache "$ROOT" || true
    ;;
esac

case "$FAMILY" in
  policy) run_policy ;;
  policy-core) run_policy_core ;;
  policy-repo-rules|policy-ci-script-tests|policy-planner-tests) run_policy_part "$FAMILY" ;;
  policy-parts) policy_parts ;;
  tooling-parts) tooling_parts ;;
  tooling) run_tooling ;;
  policy-shell) run_shell_policy ;;
  standard) run_standard ;;
  contracts) run_contracts ;;
  go-support) run_go_support ;;
  web) run_web ;;
  docs) run_docs ;;
  dashboard-image) run_dashboard_image ;;
  ios) run_ios ;;
  ios-config) run_ios_config ;;
  sdk-go) run_sdk_go ;;
  sdk-ts) run_sdk_ts ;;
  sdk-python) run_sdk_python ;;
  confidential-script-tests) run_confidential_script_tests ;;
  dev-smoke-script-tests) run_dev_smoke_script_tests ;;
  rust) run_rust ;;
  rust-transport) run_rust_transport ;;
  rust-curated-locks) run_rust_curated_locks ;;
  rust-compile) run_rust_compile ;;
  transport) run_transport ;;
  edge) run_edge_family ;;
  kind-tools) run_kind_tools ;;
  release) run_release ;;
  deploy) run_deploy ;;
  workspace-agents) scripts/ci/verify/workspace-agents.sh ;;
  security) run_security ;;
  *)
    echo "usage: run-product-verification.sh standard|tooling|tooling-parts|policy|policy-parts|policy-core|policy-repo-rules|policy-ci-script-tests|policy-shell|contracts|go-support|web|docs|dashboard-image|ios|sdk-go|sdk-ts|sdk-python|confidential-script-tests|dev-smoke-script-tests|rust|rust-transport|rust-curated-locks|rust-compile|transport|edge|kind-tools|release|deploy|workspace-agents|security" >&2
    exit 2
    ;;
esac
