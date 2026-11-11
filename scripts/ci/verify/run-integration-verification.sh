#!/usr/bin/env bash
# Bounded database and per-service verification extracted from the all-up
# Rust stack rehearsal. A reachable disposable Postgres is required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
# shellcheck source=scripts/ci/setup/cpu-share.sh
source "$ROOT/scripts/ci/setup/cpu-share.sh"
MODE="${1:-}"
SELECTION="${VERIFICATION_SELECTION:-|valid:v3|complete|}"
CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
export CARGO_TARGET_DIR
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
select_local_rust_cache "$ROOT" || true
CARGO_CI_TARGET_DIR="${CODEWIRE_CARGO_CI_TARGET_DIR:-$CARGO_TARGET_DIR}"
CARGO_CI_DIR="$CARGO_CI_TARGET_DIR/ci"
# Names below are per process: merge qualification runs several of these
# side by side under one run ID (scripts/dev/preflight.sh --all).
RUN_DIR="${RUN_DIR:-$ROOT/.tmp/codewire-product-integration-${GITHUB_RUN_ID:-local}-$$}"
# Each database suite's listing of its tests (counted_suite).
SUITE_LISTINGS="$RUN_DIR/suite-listings"
DATABASE_URL_EXPLICIT=false
DATABASE_URL_RUST_EXPLICIT=false
[[ -v DATABASE_URL ]] && DATABASE_URL_EXPLICIT=true
[[ -v DATABASE_URL_RUST ]] && DATABASE_URL_RUST_EXPLICIT=true
DATABASE_URL="${DATABASE_URL-}"
DATABASE_URL_RUST="${DATABASE_URL_RUST-}"
SESSION_SECRET="${SESSION_SECRET:-build-test-not-a-real-secret-padded}"
PORT_BASE="${VERIFICATION_PORT_BASE:-62000}"
IDP_PORT=$((PORT_BASE + 1))
COORDINATOR_PORT=$((PORT_BASE + 2))
BILLING_PORT=$((PORT_BASE + 3))
ORCHESTRATION_PORT=$((PORT_BASE + 4))
TEMPORAL_PORT=$((PORT_BASE + 5))
NATS_CLIENT_PORT=$((PORT_BASE + 6))
NATS_MONITOR_PORT=$((PORT_BASE + 7))
ORCHESTRATION_KUBE_STUB_PORT=$((PORT_BASE + 8))
ORCHESTRATION_DAEMON_PORT=$((PORT_BASE + 9))
ORCHESTRATION_UNAVAILABLE_DAEMON_PORT=$((PORT_BASE + 10))
TEMPORAL_HOST_PORT="127.0.0.1:${TEMPORAL_PORT}"
# Lanes on one host share these fixed port ranges (#2755). A real lane, which
# is given VERIFICATION_PORT_BASE, holds a host-wide lock for its range, and
# each service it tests must carry this run's token in its environment.
INTEGRATION_LANE="$ROOT/scripts/ci/verify/integration-lane.py"
CODEWIRE_INTEGRATION_RUN_ID="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
export CODEWIRE_INTEGRATION_RUN_ID
LANE_LOCK_PID=""
INTEGRATION_DOCKER_NETWORK="${INTEGRATION_DOCKER_NETWORK:-}"
INTEGRATION_NATS_HOST="${INTEGRATION_NATS_HOST:-codewire-integration-nats}"
if [ -n "$INTEGRATION_DOCKER_NETWORK" ]; then
  if [[ "$INTEGRATION_DOCKER_NETWORK" =~ [^A-Za-z0-9_.-] ]] \
      || [[ "$INTEGRATION_NATS_HOST" =~ [^A-Za-z0-9_.-] ]]; then
    echo "::error::invalid integration Docker network or NATS alias" >&2
    exit 2
  fi
  NATS_URL="nats://${INTEGRATION_NATS_HOST}:4222"
  NATS_MONITOR_URL="http://${INTEGRATION_NATS_HOST}:8222/healthz"
else
  NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT}"
  NATS_MONITOR_URL="http://127.0.0.1:${NATS_MONITOR_PORT}/healthz"
fi
TEMPORAL_CLI_VERSION="${TEMPORAL_CLI_VERSION:-1.5.0}"
IDP_SIGNING_KEK_DIR=""
BILLING_FIXTURE_LOADED=false

# shellcheck source=scripts/ci/verify/integration-postgres.sh
source "$ROOT/scripts/ci/verify/integration-postgres.sh"
integration_postgres_init
NATS_CONTAINER="$(integration_fixture_name nats)"

mkdir -p "$RUN_DIR/bin"
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-5}" TZ=UTC

log() {
  printf '[product-integration] %s\n' "$*"
}

# Waits, rather than fails, while another run holds this lane's port range.
# Hermetic fixtures set no VERIFICATION_PORT_BASE, so they neither take the
# lock nor wait on it.
acquire_lane_lock() {
  [ -n "${VERIFICATION_PORT_BASE:-}" ] || return 0
  local dir="${CODEWIRE_INTEGRATION_LOCK_DIR:-/tmp/codewire-integration-lanes}"
  local ready="$RUN_DIR/lane-lock.ready"
  rm -f "$ready"
  python3 -B "$INTEGRATION_LANE" lock --file "$dir/ports-${PORT_BASE}.lock" \
    --parent "$$" --label "$MODE in $ROOT" --ready "$ready" &
  LANE_LOCK_PID=$!
  until [ -s "$ready" ]; do
    if ! kill -0 "$LANE_LOCK_PID" 2>/dev/null; then
      echo "::error::the integration lane lock helper exited"
      return 1
    fi
    sleep 1
  done
}

# A healthy answer on the port is not enough: it must come from a process this
# run started, never from another run's service on the same port.
require_own_listener() {
  python3 -B "$INTEGRATION_LANE" owner --name "$1" --port "$2" \
    --token "$CODEWIRE_INTEGRATION_RUN_ID"
}

selected() {
  [[ "$SELECTION" == *"|$1|"* ]]
}

cargo_ci() {
  CARGO_TARGET_DIR="$CARGO_CI_TARGET_DIR" cargo "$@"
}

# Compile once (infra#1632). Two modes replace Cargo for the database suites
# and the service planes, so the lanes below stay the one list of what runs:
# - database-archives (on the pull request build runner): each `cargo test
#   ... --no-run` of DATABASE_BUILD_BATCHES becomes `cargo nextest archive` of
#   the same package and feature set into ARCHIVE_BUILD_DIR, one archive per
#   package and feature set, and the CI-profile migration runner is copied
#   beside them.
# - RUST_DATABASE_ARCHIVES (a test job): every `cargo test` of a lane runs the
#   same tests from those archives with cargo-nextest (RUST_TEST_NEXTEST),
#   and prints cargo's "test result" line, so assert_passed_count and the
#   lanes' output checks read it as before. `cargo build` of the migration
#   runner is a no-op: the archives carry it.
# - services-PLANE-archives and RUST_SERVICE_ARCHIVES do the same for one
#   service plane: service_build_batches lists its tests, and its `cargo
#   build`s build for real, in the archives' profile, with keep_binaries
#   copying the binaries the plane starts beside the archives. From archives,
#   `cargo build` and `cargo test --no-run` are no-ops.
# The helpers serve any family: archive_cargo builds into ARCHIVE_BUILD_DIR
# and runs from the folders extract_archives DIR made. A lane's --profile is
# dropped, so the archives build in the dev profile and share their units
# with the build runner's other archives; ARCHIVE_CARGO_PROFILE=keep builds
# them in the lane's profile instead (--cargo-profile), keyed apart.
# The build runner's build folder, /ci-cache/main on a push to main and
# /ci-cache/pr otherwise (build-once-tree.sh); the archives' test binaries
# carry its paths.
# shellcheck source=scripts/ci/setup/build-once-tree.sh
source "$ROOT/scripts/ci/setup/build-once-tree.sh"
DATABASE_ARCHIVE_BUILD_ROOT="$(build_once_tree)"
readonly DATABASE_ARCHIVE_BUILD_ROOT

archive_key() {
  # archive_key PACKAGE FEATURES NO_DEFAULT [PROFILE]: one archive per set.
  local key="$1"
  [ "$3" = true ] && key+="--no-default"
  [ -z "$2" ] || key+="--features-${2//,/-}"
  [ -z "${4:-}" ] || key+="--profile-$4"
  printf '%s' "$key"
}

archive_cargo() {
  local command="${1:-}"
  shift || true
  if [ "$command" = build ]; then
    # From archives, the binaries come with them (CARGO_CI_DIR).
    [ -n "${ARCHIVE_BUILD_DIR:-}" ] || return 0
    # Building a service plane's archives, its binaries build in the
    # archives' profile.
    local -a build_args=()
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --profile)
          [ "${ARCHIVE_CARGO_PROFILE:-drop}" != keep ] || build_args+=(--profile "$2")
          shift 2
          ;;
        *) build_args+=("$1"); shift ;;
      esac
    done
    command cargo build "${build_args[@]}"
    return
  fi
  [ "$command" = test ] || { echo "::error::archive mode cannot run cargo $command" >&2; return 2; }
  local package="" features="" no_default=false no_run=false name="" exact=false ignored=default
  local threads="" nocapture=false profile="" list=false arg
  local -a binaries=() skips=() cargo_args=()
  while [ "$#" -gt 0 ]; do
    arg="$1"
    shift
    case "$arg" in
      --) break ;;
      --locked) ;;
      -p|--package) package="$1"; cargo_args+=(-p "$1"); shift ;;
      --features) features="$1"; cargo_args+=(--features "$1"); shift ;;
      --no-default-features) no_default=true; cargo_args+=("$arg") ;;
      --lib) binaries+=("binary_id($package)"); cargo_args+=("$arg") ;;
      --test) binaries+=("binary_id($package::$1)"); cargo_args+=(--test "$1"); shift ;;
      --profile)
        if [ "${ARCHIVE_CARGO_PROFILE:-drop}" = keep ]; then
          profile="$1"
          cargo_args+=(--cargo-profile "$1")
        fi
        shift
        ;;
      --no-run) no_run=true ;;
      -*) echo "::error::archive mode does not know cargo test $arg" >&2; return 2 ;;
      *) name="$arg" ;;
    esac
  done
  while [ "$#" -gt 0 ]; do
    arg="$1"
    shift
    case "$arg" in
      --ignored) ignored=only ;;
      --include-ignored) ignored=all ;;
      --exact) exact=true ;;
      --nocapture) nocapture=true ;;
      --list) list=true ;;
      --test-threads=*) threads="${arg#--test-threads=}" ;;
      --skip) skips+=("$1"); shift ;;
      --skip=*) skips+=("${arg#--skip=}") ;;
      *) echo "::error::archive mode does not know test argument $arg" >&2; return 2 ;;
    esac
  done
  [ -n "$package" ] || { echo '::error::archive mode needs -p' >&2; return 2; }
  local key
  key="$(archive_key "$package" "$features" "$no_default" "$profile")"
  if [ "$no_run" = true ]; then
    # From archives, the build is the archive itself.
    [ -n "${ARCHIVE_BUILD_DIR:-}" ] || return 0
    [ ! -e "$ARCHIVE_BUILD_DIR/$key.tar.zst" ] ||
      { echo "::error::two build batches share the archive $key" >&2; return 2; }
    command cargo nextest archive --locked "${cargo_args[@]}" \
      --archive-file "$ARCHIVE_BUILD_DIR/$key.tar.zst"
    return
  fi
  local extracted="$RUN_DIR/archives/$key"
  [ -f "$extracted/target/nextest/binaries-metadata.json" ] ||
    { echo "::error::no extracted archive $key; the build runner built none for it" >&2; return 2; }
  local filter="package($package)" part binary_filter=""
  for part in "${binaries[@]}"; do
    binary_filter="${binary_filter:+$binary_filter | }$part"
  done
  [ -z "$binary_filter" ] || filter+=" & ($binary_filter)"
  if [ -n "$name" ]; then
    if [ "$exact" = true ]; then filter+=" & test(=$name)"; else filter+=" & test($name)"; fi
  fi
  for part in "${skips[@]}"; do
    filter+=" & !test($part)"
  done
  local -a reuse_args=(
    --binaries-metadata "$extracted/target/nextest/binaries-metadata.json"
    --cargo-metadata "$extracted/target/nextest/cargo-metadata.json"
    --target-dir-remap "$extracted/target"
    --workspace-remap "$DATABASE_ARCHIVE_BUILD_ROOT/src")
  if [ "$list" = true ]; then
    # The tests this run would run, as libtest's --list names them.
    "${RUST_TEST_NEXTEST:-cargo-nextest}" nextest list --run-ignored "$ignored" -E "$filter" \
      --message-format oneline "${reuse_args[@]}" | sed -nE 's/^[^ ]+ ([^ ]+)$/\1: test/p'
    return
  fi
  local -a run_args=(--run-ignored "$ignored" -E "$filter" --no-tests=fail --no-fail-fast
    "${reuse_args[@]}")
  [ -z "$threads" ] || run_args+=(--test-threads "$threads")
  # cargo's --nocapture let the lanes read a passing test's output; keep it.
  [ "$nocapture" = false ] || run_args+=(--success-output immediate)
  local output status=0 passed
  output="$(mktemp "$RUN_DIR/nextest.XXXXXX")"
  "${RUST_TEST_NEXTEST:-cargo-nextest}" nextest run "${run_args[@]}" > "$output" 2>&1 || status=$?
  cat "$output"
  passed="$(sed -nE 's/^ *Summary \[.*\] +[0-9]+ tests? run: ([0-9]+) passed.*/\1/p' "$output" | tail -n 1)"
  rm -f -- "$output"
  if [ "$status" -eq 0 ]; then
    echo "test result: ok. ${passed:-0} passed; 0 failed (cargo-nextest from the $key archive)"
  fi
  return "$status"
}

# extract_archives DIR: extract every archive in DIR once, before the lanes
# start. The archives extract side by side: one after another, the nine
# database archives took 16 s, of which the orchestration archive alone took
# 8 s (main run 23934). Each extraction is one zstd stream, and the job's CPU
# share has a core for each.
extract_archives() {
  local dir="$1" archive key binary link target metadata status failed=false
  local -A linked=() named=() extracting=()
  # Test binaries carry the build folder's source paths (CARGO_MANIFEST_DIR):
  # a real copy of this checkout there, not a link, since tests check their
  # paths' ancestry and compare canonical paths.
  rm -rf -- "$DATABASE_ARCHIVE_BUILD_ROOT"
  mkdir -p "$RUN_DIR/archives" "$DATABASE_ARCHIVE_BUILD_ROOT"
  cp -a "$ROOT/." "$DATABASE_ARCHIVE_BUILD_ROOT/src" || return
  for archive in "$dir"/*.tar.zst; do
    key="$(basename "$archive" .tar.zst)"
    # nextest extracts only into an existing, empty folder.
    mkdir -p "$RUN_DIR/archives/$key"
    "${RUST_TEST_NEXTEST:-cargo-nextest}" nextest run --archive-file "$archive" \
      --workspace-remap "$DATABASE_ARCHIVE_BUILD_ROOT/src" \
      --extract-to "$RUN_DIR/archives/$key" -E 'none()' --no-tests=pass \
      >"$RUN_DIR/archives/$key.extract.log" 2>&1 &
    extracting[$key]=$!
  done
  # Every extraction is waited for, so none still writes when this returns;
  # each one's report follows in archive order.
  for archive in "$dir"/*.tar.zst; do
    key="$(basename "$archive" .tar.zst)"
    status=0
    wait "${extracting[$key]}" || status=$?
    cat "$RUN_DIR/archives/$key.extract.log" >&2
    rm -f -- "$RUN_DIR/archives/$key.extract.log"
    if [ "$status" -ne 0 ]; then
      echo "::error::the $key archive did not extract (status $status)" >&2
      failed=true
    fi
  done
  [ "$failed" = false ] || return 1
  for archive in "$dir"/*.tar.zst; do
    key="$(basename "$archive" .tar.zst)"
    # An integration test starts its package's binaries by their build
    # folder path (CARGO_BIN_EXE_*, fixed when it compiled, as idp's
    # rewrap_cli does), and may write to its CARGO_TARGET_TMPDIR: link each
    # archive's binaries into the target folder it was built in, which each
    # build-once leg has of its own (targets/database, targets/services_control
    # and so on; main run 23071), and each of its build batches but the first
    # inside it (targets/database/batch-orchestration; compile_batches), and
    # make its tmp folder. A binary two archives of one folder carry (one
    # package in two feature sets) is linked to neither, so a test that
    # starts it fails rather than start the other build.
    metadata="$RUN_DIR/archives/$key/target/nextest/binaries-metadata.json"
    target="$(jq -r '."rust-build-meta"."target-directory" // empty' "$metadata")"
    [[ "$target" =~ ^"$DATABASE_ARCHIVE_BUILD_ROOT"/targets/[A-Za-z0-9_-]+(/batch-[a-z0-9-]+)?$ ]] ||
      { echo "::error::archive $key was built in ${target:-no recorded folder}, not a target folder of $DATABASE_ARCHIVE_BUILD_ROOT" >&2; return 2; }
    mkdir -p "$target/tmp"
    while read -r binary; do
      # nextest also lists the libraries a build produced (a dependency's
      # static library, such as boringtun's .a in the credential service's
      # enrollment build, main run 22655). Nothing starts one by its path, so
      # it gets no link.
      if [[ "$binary" =~ ^[a-z0-9_-]+(/deps)?/lib[A-Za-z0-9_.-]+\.(a|so|dylib|rlib)$ ]]; then
        continue
      fi
      [[ "$binary" =~ ^[a-z0-9_-]+/[A-Za-z0-9_.-]+$ ]] ||
        { echo "::error::archive $key names an unexpected binary path: $binary" >&2; return 2; }
      link="$target/$binary"
      if [ -n "${linked[$link]:-}" ]; then
        rm -f -- "$link"
        linked[$link]=ambiguous
      else
        linked[$link]="$key"
        mkdir -p "$(dirname "$link")"
        ln -s "$RUN_DIR/archives/$key/target/$binary" "$link"
      fi
      if [ -n "${named[$binary]:-}" ]; then named[$binary]=ambiguous; else named[$binary]="$key"; fi
    done < <(jq -r '."rust-build-meta"."non-test-binaries"[][].path' "$metadata")
  done
  # A binary the run starts by name from DIR (CARGO_CI_DIR) that no build
  # kept there comes from the one archive that carries it: the orchestration
  # wire contract's archive carries the orchestration service and its smokes.
  for binary in "${!named[@]}"; do
    [ "${named[$binary]}" != ambiguous ] || continue
    [ -e "$dir/${binary##*/}" ] ||
      ln -s "$RUN_DIR/archives/${named[$binary]}/target/$binary" "$dir/${binary##*/}"
  done
  log "archives extracted: $(find "$RUN_DIR/archives" -mindepth 1 -maxdepth 1 | wc -l)"
}

# The archives this run tests from: the database job's or a service job's.
RUST_ARCHIVES="${RUST_DATABASE_ARCHIVES:-${RUST_SERVICE_ARCHIVES:-}}"
case "$MODE" in
  *-archives) : "${ARCHIVE_BUILD_DIR:?ARCHIVE_BUILD_DIR is required}" ;;
  *) unset ARCHIVE_BUILD_DIR ;;
esac
if [ -n "$RUST_ARCHIVES" ] || [ -n "${ARCHIVE_BUILD_DIR:-}" ]; then
  cargo() { archive_cargo "$@"; }
fi
if [ -n "$RUST_ARCHIVES" ]; then
  CARGO_CI_DIR="$RUST_ARCHIVES"
fi
case "$MODE" in
  services-*-archives)
    if [ "${ARCHIVE_CARGO_PROFILE:-drop}" = keep ]; then
      CARGO_CI_DIR="$CARGO_CI_TARGET_DIR/ci"
    else
      CARGO_CI_DIR="$CARGO_CI_TARGET_DIR/debug"
    fi
    ;;
esac

# keep_binaries NAME...: building a service plane's archives, copy the named
# binaries, just built, beside them; otherwise nothing.
keep_binaries() {
  case "$MODE" in services-*-archives) ;; *) return 0 ;; esac
  local binary
  for binary in "$@"; do
    install -m 0755 "$CARGO_CI_DIR/$binary" "$ARCHIVE_BUILD_DIR/$binary"
  done
}

dump_logs() {
  local name
  for name in idp coordinator billing orchestration \
      orchestration-daemon orchestration-kube-stub temporal nats; do
    if [ -f "$RUN_DIR/${name}.log" ]; then
      echo "--- ${name}.log ---"
      tail -200 "$RUN_DIR/${name}.log" || true
    fi
  done
}

cleanup() {
  local pidfile
  for pidfile in "$RUN_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    kill "$(cat "$pidfile")" 2>/dev/null || true
  done
  docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  integration_postgres_cleanup
  if [ -n "$RUST_ARCHIVES" ]; then
    rm -rf -- "$DATABASE_ARCHIVE_BUILD_ROOT"
  fi
  # The idp keyring of this run, also when an idp lane prepared it in its
  # own process.
  rm -rf -- "${IDP_SIGNING_KEK_DIR:-$RUN_DIR/idp-signing-keks}"
  # Release the port range only after this run's services have stopped.
  if [ -n "$LANE_LOCK_PID" ]; then
    kill "$LANE_LOCK_PID" 2>/dev/null || true
    wait "$LANE_LOCK_PID" 2>/dev/null || true
  fi
}

on_exit() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    dump_logs
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

assert_passed_count() {
  local label="$1" logfile="$2" expected="$3" count
  count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [ "$count" != "$expected" ]; then
    echo "::error::${label} reported ${count:-no} passing tests; expected ${expected}"
    return 1
  fi
}

# suite_tests COMMAND...: the names of the tests COMMAND, a `cargo test` with
# its filter and test arguments, would run, one per line. libtest's --list
# also names the ignored tests a run without --ignored leaves out, so those
# are listed apart and taken away.
suite_tests() {
  local -a command=("$@")
  local arg separator=false ignored=false
  for arg in "${command[@]}"; do
    if [ "$separator" = true ]; then
      case "$arg" in --ignored|--include-ignored) ignored=true ;; esac
    fi
    [ "$arg" != -- ] || separator=true
  done
  [ "$separator" = true ] || command+=(--)
  local all only
  all="$(mktemp "$RUN_DIR/suite-tests.XXXXXX")"
  only="$(mktemp "$RUN_DIR/suite-tests.XXXXXX")"
  "${command[@]}" --list | sed -nE 's/^(.+): test$/\1/p' | sort -u > "$all"
  if [ "$ignored" = false ]; then
    "${command[@]}" --list --ignored | sed -nE 's/^(.+): test$/\1/p' | sort -u > "$only"
  fi
  comm -23 "$all" "$only"
  rm -f -- "$all" "$only"
}

# counted_suite LABEL NAME [VARIABLE=VALUE...] -- COMMAND...: runs one
# database suite, COMMAND a `cargo test` with the VARIABLEs set, into
# $RUN_DIR/NAME.log. Its count is never kept here: the suite first lists the
# tests its own filter selects (suite_tests), at least one, into
# $SUITE_LISTINGS/NAME.list as PACKAGE<TAB>TEST lines, and must then pass
# exactly that many. database-test-coverage.py reads the listings: every
# database test must be in exactly one. A test that skipped itself for want
# of its database (it prints "DATABASE_URL unset") fails the suite. With
# SUITE_LIST_ONLY=true it only lists, reusing an earlier listing to run.
counted_suite() {
  local label="$1" name="$2" logfile="$RUN_DIR/$2.log" listing package="" arg previous=""
  local expected passed
  shift 2
  local -a variables=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
    variables+=("$1")
    shift
  done
  [ "$#" -gt 1 ] || { echo "::error::${label}: counted_suite needs -- COMMAND" >&2; return 2; }
  shift
  for arg in "$@"; do
    [ "$previous" != -p ] || package="$arg"
    previous="$arg"
  done
  [ -n "$package" ] || { echo "::error::${label}: the suite names no package (-p)" >&2; return 2; }
  listing="$SUITE_LISTINGS/$name.list"
  mkdir -p "$SUITE_LISTINGS"
  if [ ! -f "$listing" ]; then
    (
      for arg in "${variables[@]}"; do export "${arg?}"; done
      suite_tests "$@"
    ) > "$listing.names"
    sed "s/^/$package\t/" "$listing.names" > "$listing"
    rm -f -- "$listing.names"
  fi
  expected="$(wc -l < "$listing")"
  if [ "$expected" -eq 0 ]; then
    rm -f -- "$listing"
    echo "::error::${label} selects no test; its filter matches nothing"
    return 1
  fi
  [ "${SUITE_LIST_ONLY:-false}" != true ] || return 0
  (
    for arg in "${variables[@]}"; do export "${arg?}"; done
    "$@"
  ) | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::${label} skipped: a test found no database"
    return 1
  fi
  # The suite's own result is its last: a test that runs a child test
  # process prints that child's result before it.
  passed="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [ "$passed" != "$expected" ]; then
    echo "::error::${label} passed ${passed:-no} of the ${expected} tests its filter lists"
    return 1
  fi
}

wait_http() {
  local name="$1" url="$2" pidfile="$3"
  local _
  for _ in $(seq 1 45); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "${name} ready"
      return 0
    fi
    if [ -f "$pidfile" ] && ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "::error::${name} exited before ${url} responded"
      return 1
    fi
    sleep 1
  done
  echo "::error::${name} did not become ready at ${url}"
  return 1
}

start_proc() {
  local name="$1" port="$2"
  shift 2
  log "starting ${name}"
  "$@" > "$RUN_DIR/${name}.log" 2>&1 &
  echo $! > "$RUN_DIR/${name}.pid"
  wait_http "$name" "http://127.0.0.1:${port}/healthz" "$RUN_DIR/${name}.pid"
  require_own_listener "$name" "$port"
}

stop_proc() {
  local name="$1"
  if [ -f "$RUN_DIR/${name}.pid" ]; then
    local pid
    pid="$(cat "$RUN_DIR/${name}.pid")"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$RUN_DIR/${name}.pid"
  fi
}

reset_schema() {
  log "resetting Postgres schema"
  BILLING_FIXTURE_LOADED=false
  cargo_ci build --locked --profile ci -p codewire-server-core --bin codewire-db-migrate
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;'
  DATABASE_URL="$DATABASE_URL_RUST" "$CARGO_CI_DIR/codewire-db-migrate"
}

# The database suites run in lanes. Each lane keeps its suites in their
# established order against its own migrated schema; with a database per lane
# (a managed local container, or a container on CI's job network) the lanes
# run side by side on separate PostgreSQL servers, so no lane sees another's
# schema, rows or roles. Against one explicit database they run one after
# another. Every harness compiles first, so a running lane only starts tests.
# Most suites run one test at a time against their server (--test-threads=1),
# so a lane takes the sum of its tests' times. The slow suites are split by
# module across lanes, each with its own server, so that no one lane sets the
# job's time: as one lane, the 50-test broker admission matrix took 246-626 s
# (infra#1534, CI compute audit row 5). The times below are run 22601's
# suites; the broker lanes' are scaled from one local run of each module (the
# whole matrix took 117 s there and 246 s in run 22601).
readonly DATABASE_LANES=(
  core                     # server-core, platform credentials, billing, Mesh: 65 s
  credential-mutations     # credential-service mutations and delegation: 92 s
  credential-service       # credential-service runtime and identity: 69 s
  broker-admission         # broker admission itself, Claude sign-in, gRPC rotation: 70 s
  broker-checked           # broker checked leases: 70 s
  broker-decisions         # broker decisions and Codex login: 70 s
  broker-refresh           # broker keepalive, material cache, subscription, SSH: 65 s
  orchestration            # orchestration preview, access and environments: 66 s
  orchestration-journals   # orchestration cw runtime and managed agent journals: 78 s
  orchestration-workspaces # orchestration sources, workspaces and leases: 50 s
)
# The order lanes start in when not all run at once: the longest first.
readonly DATABASE_LANE_ORDER=(
  credential-mutations orchestration-journals broker-admission broker-checked
  broker-decisions credential-service orchestration core broker-refresh
  orchestration-workspaces
)

# The database suites' builds. Each uses one package and feature set, as its
# lane runs it. DATABASE_BUILD_BATCHES groups them: the builds of one batch
# run in order in one target folder, where they share their units. Here
# they all run one after another in one folder; building archives on the
# build runner, the batches run at once (compile_batches).
database_build_server_core() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --lib --test session_auth \
      --test org_deletion_lifecycle --test oauth_bearer_auth --no-run
}
database_build_platform_credentials() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test storage \
      --test profiles --test refresh --test authority --test owner_sources --no-run
}
database_build_orchestration() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib --test access_profiles \
      --test credentials --test environment_external_cleanup --test environment_sources --no-run
}
database_build_credential_service_enrollment() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --features enrollment --lib --no-run
}
database_build_credential_service() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --lib --no-run
}
database_build_credential_broker() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib --no-run
}
database_build_credential_broker_ssh() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-broker --no-default-features \
      --features platform,ssh-agent --lib --no-run
}
database_build_billing() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-billing --lib --no-run
}
database_build_mesh() {
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-mesh --lib --no-run
}
# The migration runner the database job runs, in the CI profile (archives
# only: the lanes build their own with reset_schema's cargo build).
database_build_migration_runner() {
  command cargo build --locked --profile ci -p codewire-server-core --bin codewire-db-migrate
  install -m 0755 "$CARGO_CI_DIR/codewire-db-migrate" "$ARCHIVE_BUILD_DIR/codewire-db-migrate"
}
# The batches, about evenly long. One after another in one folder, main run
# 27000 took 589 s: server-core 105 s, mesh 11; orchestration 135;
# credential-service with enrollment 32, without 5, credential-broker 64,
# with ssh-agent 19; platform-credentials 56, billing 59; the migration
# runner 88. Each batch is one more target folder on the build disk.
readonly DATABASE_BUILD_BATCHES=(
  'server_core mesh'
  orchestration
  'credential_service_enrollment credential_service credential_broker credential_broker_ssh'
  'platform_credentials billing'
)

build_database_suites() {
  local batch step
  for batch in "${DATABASE_BUILD_BATCHES[@]}"; do
    for step in $batch; do
      "database_build_$step"
    done
  done
}

# compile_batches PREFIX BATCH...: building archives on the build runner, run
# every batch at once. A batch is a list of steps, PREFIX_STEP, which run in
# order. Cargo locks a target folder for a whole build, so each batch builds
# in a folder of its own: the first in this run's folder (CARGO_CI_TARGET_DIR,
# the leg's), each other one in batch-NAME inside it, NAME its first step,
# which stays with the leg's folder (build-once.sh). Every batch takes its
# compilers from the build's one jobserver (build-once.sh build). Each
# batch's output follows in batch order; any batch failing fails the build,
# after every batch has ended.
compile_batches() {
  local prefix="$1" batch step dir status failed=false first=true
  shift
  local logs="$RUN_DIR/batches"
  local -a pids=()
  rm -rf -- "$logs"
  mkdir -p "$logs"
  for batch in "$@"; do
    read -r step _ <<< "$batch"
    # The first batch's folder holds the other batches' folders: its size
    # leaves them out.
    local -a size_args=(--exclude="$CARGO_CI_TARGET_DIR/batch-*")
    if [ "$first" = true ]; then
      dir="$CARGO_CI_TARGET_DIR"
      first=false
    else
      dir="$CARGO_CI_TARGET_DIR/batch-${step//_/-}"
      size_args=()
    fi
    (
      started=$SECONDS
      # The folder by its last name only: a full path in the log reads as a
      # folder to wipe on a corrupt output (build-once.sh).
      echo "[build batch] $step: start (folder ${dir##*/})"
      CARGO_CI_DIR="$dir${CARGO_CI_DIR#"$CARGO_CI_TARGET_DIR"}"
      CARGO_CI_TARGET_DIR="$dir"
      CARGO_TARGET_DIR="$dir"
      export CARGO_TARGET_DIR
      for step in $batch; do
        "${prefix}_$step"
      done
      # Its folder's size sizes the build disk (build-once.sh bound_targets).
      echo "[build batch] ${batch%% *}: finish (elapsed_seconds=$((SECONDS - started)) folder_size=$(
        du -sh "${size_args[@]}" "$dir" 2>/dev/null | cut -f1))"
    ) > "$logs/$step.log" 2>&1 &
    pids+=("$!")
  done
  local index=0
  for batch in "$@"; do
    read -r step _ <<< "$batch"
    status=0
    wait "${pids[$index]}" || status=$?
    index=$((index + 1))
    cat "$logs/$step.log"
    if [ "$status" -ne 0 ]; then
      echo "::error::the $step build batch failed (status $status)"
      failed=true
    fi
  done
  rm -rf -- "$logs"
  [ "$failed" = false ]
}

database_lane_core() {
  counted_suite "server-core migration matrix" server-core-migrate \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-server-core --lib migrate:: -- --ignored --nocapture

  counted_suite "platform credential storage matrix" platform-credential-storage \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-platform-credentials --test storage \
      -- --ignored --nocapture --test-threads=4

  counted_suite "platform access profile matrix" platform-access-profiles \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-platform-credentials --test profiles \
      -- --ignored --nocapture --test-threads=4

  counted_suite "platform owner-source authority matrix" platform-owner-source-authority \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-platform-credentials --test owner_sources \
      -- --ignored --nocapture --test-threads=1

  counted_suite "platform credential refresh matrix" platform-credential-refresh \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-platform-credentials --test refresh \
      -- --ignored --nocapture --test-threads=4

  counted_suite "platform credential restricted-role matrix" platform-credential-authority \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-platform-credentials --test authority \
      -- --ignored --nocapture --test-threads=4

  counted_suite "OAuth-only restricted identity matrix" oauth-bearer-identity \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-server-core --test oauth_bearer_auth \
      -- --ignored --nocapture

  counted_suite "session hash-only matrix" session-hash-only \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-server-core --test session_auth -- --nocapture

  counted_suite "organization deletion lifecycle matrix" organization-deletion-lifecycle \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-server-core --test org_deletion_lifecycle \
      -- --nocapture

  counted_suite "organization billing teardown matrix" organization-billing-teardown \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-billing --lib 'billing_teardown::tests::db_' \
      -- --nocapture

  counted_suite "credit metering matrix" credit-metering \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-billing --lib 'credit::tests::db_' \
      -- --nocapture

  counted_suite "billing settings audit" billing-settings-audit \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-billing --lib 'catalog_admin::tests::db_' \
      -- --nocapture

  counted_suite "Mesh migration ledger" mesh-migration-ledger \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-mesh --lib 'store::migration_tests::' \
      -- --ignored --nocapture

  counted_suite "server-core pool health matrix" server-core-pool-health \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-server-core --lib db:: -- --ignored --nocapture --test-threads=1
}

database_lane_credential_mutations() {
  counted_suite "public credential mutation matrix" public-credential-mutations \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib mutation::tests:: -- --ignored --nocapture --test-threads=1

  counted_suite "owner-local delegation authority matrix" owner-local-delegation-authority \
    TMPDIR="$RUN_DIR" TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib delegation::authority::tests:: \
      -- --ignored --nocapture --test-threads=1
}

database_lane_credential_service() {
  counted_suite "isolated credential runtime matrix" isolated-credential-runtime \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib runtime::tests:: -- --ignored --nocapture --test-threads=1

  counted_suite "GitHub repository discovery matrix" github-repository-discovery \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib repositories::tests::integration:: -- --ignored --nocapture --test-threads=1

  counted_suite "Kind credential effective ACL matrix" kind-credential-effective-acl \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib runtime::kind::config::tests::effective_acl_guard_rejects_direct_column_and_membership_authority \
      -- --exact --ignored --nocapture --test-threads=1

  counted_suite "platform runtime restricted identity matrix" platform-runtime-identity \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service \
      --lib tests::database:: -- --ignored \
      --skip tests::database::projection:: \
      --nocapture --test-threads=1

  counted_suite "platform runtime projection matrix" platform-runtime-projection \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-service \
      --lib tests::database::projection:: \
      -- --ignored --nocapture --test-threads=1
}

# The broker admission matrix (platform::tests, 50 tests) runs in four lanes:
# this one runs the tests of platform::tests itself, and the other broker
# lanes its modules. A new module runs here until it is given a lane.
database_lane_broker_admission() {
  counted_suite "platform broker admission matrix" platform-broker-admission \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests:: -- --ignored \
      --skip platform::tests::checked:: --skip platform::tests::claude_sign_in:: \
      --skip platform::tests::codex_login:: --skip platform::tests::decision:: \
      --skip platform::tests::keepalive:: --skip platform::tests::material_cache:: \
      --skip platform::tests::subscription:: \
      --nocapture --test-threads=1

  counted_suite "platform broker Claude sign-in matrix" platform-broker-claude-sign-in \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::claude_sign_in:: -- --ignored --nocapture --test-threads=1

  counted_suite "platform broker gRPC rotation drain matrix" platform-broker-grpc-rotation \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::bridge::tests::rotation:: -- --ignored --nocapture --test-threads=1
}

database_lane_broker_checked() {
  counted_suite "platform broker checked lease matrix" platform-broker-checked \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::checked:: -- --ignored --nocapture --test-threads=1
}

database_lane_broker_decisions() {
  counted_suite "platform broker decision matrix" platform-broker-decision \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::decision:: -- --ignored --nocapture --test-threads=1

  counted_suite "platform broker Codex login matrix" platform-broker-codex-login \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::codex_login:: -- --ignored --nocapture --test-threads=1
}

database_lane_broker_refresh() {
  counted_suite "platform broker keepalive matrix" platform-broker-keepalive \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::keepalive:: -- --ignored --nocapture --test-threads=1

  counted_suite "platform broker material cache matrix" platform-broker-material-cache \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::material_cache:: -- --ignored --nocapture --test-threads=1

  counted_suite "platform broker subscription matrix" platform-broker-subscription \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests::subscription:: -- --ignored --nocapture --test-threads=1

  counted_suite "platform broker SSH matrix" platform-broker-ssh \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-credential-broker --no-default-features \
      --features platform,ssh-agent --lib platform::tests::ssh:: \
      -- --ignored --nocapture --test-threads=1
}

database_lane_orchestration() {
  counted_suite "preview browser authorization matrix" preview-browser-authorization \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      api::preview::authorization::database_tests:: -- --ignored --nocapture

  counted_suite "public access profile restricted API matrix" public-access-profiles \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --test access_profiles \
      -- --ignored --nocapture --test-threads=4

  counted_suite "public credential metadata matrix" public-credential-metadata \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --test credentials \
      -- --ignored --nocapture --test-threads=3

  # The orchestration batch already built this harness; a CI-profile build
  # compiled the crate again for one test.
  counted_suite "Mesh authorization receiver matrix" mesh-authorization-receiver \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      connect::mesh_authorization::tests::generated_mesh_authorization_service_enforces_the_canonical_matrix \
      -- --ignored --exact --nocapture

  counted_suite "environment external cleanup matrix" environment-external-cleanup \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-orchestration --test environment_external_cleanup \
      -- --nocapture

  counted_suite "environment session admission matrix" environment-session-admission \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environment_daemon::session_mutation::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment destroy template hint matrix" environment-destroy-template-hint \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      worker::lifecycle::tests::destroy_template_hint_allows_missing_creation_config_but_not_database_failure \
      -- --ignored --exact --nocapture

  counted_suite "environment projection capture matrix" environment-projection-capture \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::create::projection_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "stopped sandbox notice matrix" sandbox-stopped-notice \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::sandbox_stopped_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "no capacity outcome matrix" no-capacity-outcome \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::create::no_capacity_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "warm Pod start marks matrix" warm-pod-start-marks \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::create::pod_marks_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "terminal Pod replacement order matrix" terminal-pod-replacement-order \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::create::replacement_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "organization tenant secret teardown matrix" organization-tenant-secret-teardown \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-orchestration --lib \
      'worker::tenant_secret_teardown::tests::db_' \
      -- --nocapture

  counted_suite "encrypted tenant secret store matrix" encrypted-tenant-secret-store \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test -p codewire-orchestration --lib \
      'worker::postgres_secrets::tests::encrypted_store_reencrypts_renames_and_deletes_final_dek' \
      -- --ignored --exact --nocapture
}

database_lane_orchestration_journals() {
  counted_suite "platform cw runtime journal matrix" platform-cw-runtime-journal \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::cw_runtime::owner::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "platform managed agent journal matrix" platform-managed-agent-journal \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::platform_agents::journal::database_tests::db_' \
      -- --ignored --nocapture --test-threads=1
}

database_lane_orchestration_workspaces() {
  counted_suite "environment source admission matrix" environment-source-admission \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --test environment_sources \
      -- --ignored --nocapture --test-threads=1

  counted_suite "admin startup summary matrix" admin-startup-summary \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::admin::startup_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "admin environment quota matrix" admin-environment-quota \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::admin::quota_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "admin organization credit matrix" admin-organization-credit \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::admin::credit_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "credit exhausted stop matrix" credit-exhausted-stop \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::credit_stop::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "admin organization dedicated CPU matrix" admin-organization-dedicated-cpu \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::admin::dedicated_cpu_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "workspace binding recorder matrix" workspace-binding-recorder \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::workspace_binding::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "workspace binding access store matrix" workspace-binding-access-store \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'workspace_binding::store::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment Mesh membership matrix" environment-mesh-membership \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'environment_mesh::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment resize admission matrix" environment-resize-admission \
    DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environment_resize::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment create capacity matrix" environment-create-capacity \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::create::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "SSH proxy runtime lease matrix" ssh-proxy-runtime-lease \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::ssh_proxy::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment daemon repair lease matrix" environment-daemon-repair-lease \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environment_daemon::repair_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment membership access matrix" environment-membership-access \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environments::access_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment rate limit" environment-rate-limit \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environments::rate_limit_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "CLI feedback limits and admin list" cli-feedback \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::feedback::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "host enrollment, grants and revocation" hosts \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::hosts::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "host session attach, proof and liveness" host-session \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'connect::host_agent::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "organization membership credential matrix" organization-membership-credentials \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::organizations::membership_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "organization sign-up credit" organization-signup-credit \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::organizations::signup_credit_database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "billing session bind matrix" billing-session-bind \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::billing_sessions::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "credential relay target matrix" credential-relay-targets \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::credential_relay::database_tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "preset projection matrix" preset-projection \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::presets::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "hosted snapshot API matrix" hosted-snapshots-api \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'api::snapshots::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "hosted snapshot worker matrix" hosted-snapshots-worker \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::snapshots::tests::db_' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "confidential environment access matrix" confidential-environment-access \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'confidential_storage::tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "orchestration activity fencing matrix" orchestration-activity-fencing \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::activity_authority::tests::' \
      -- --ignored --nocapture --test-threads=1

  counted_suite "environment setup lease matrix" environment-setup-lease \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" -- \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::setup_lease::tests::db_' \
      -- --ignored --nocapture --test-threads=1
}

run_database_lane() {
  case "$1" in
    core) database_lane_core ;;
    credential-mutations) database_lane_credential_mutations ;;
    credential-service) database_lane_credential_service ;;
    broker-admission) database_lane_broker_admission ;;
    broker-checked) database_lane_broker_checked ;;
    broker-decisions) database_lane_broker_decisions ;;
    broker-refresh) database_lane_broker_refresh ;;
    orchestration) database_lane_orchestration ;;
    orchestration-journals) database_lane_orchestration_journals ;;
    orchestration-workspaces) database_lane_orchestration_workspaces ;;
    *) echo "::error::unknown database lane: $1"; return 2 ;;
  esac
}

# At most this many database lanes run at once on a metal guest: all ten.
# With all ten running (measured locally, 2026-10-26), their ten PostgreSQL
# servers held 0.86-0.90 GiB and the runner with its test processes 1.2 GiB,
# about 2.1 GiB of a heavy guest's 11.7; five at once held 1.1 GiB on CI
# (main run 23934). A finished lane's PostgreSQL is removed, so only running
# lanes hold memory.
readonly DATABASE_LANES_MEMORY_BOUND=10

# start_lane_databases LANE...: the first lane uses the job's own database;
# every other lane gets its own PostgreSQL beside it (on CI's job network, or
# as another managed container locally), so no lane sees another's schema,
# rows or roles. Their servers start at once and migrate at once. Sets the
# caller's lane_url and lane_rust_url for each lane.
start_lane_databases() {
  local lane status failed=false
  local -A setup_pid=()
  lane_url[$1]="$DATABASE_URL"
  lane_rust_url[$1]="$DATABASE_URL_RUST"
  # One after another, then waiting, the database job's nine took 24 s (main
  # run 23329). Started before the extraction instead, their initialization
  # slowed it from 41 to 68 s (PR run 23437), so they start after it.
  for lane in "${@:2}"; do
    integration_postgres_start_lane "$lane" background
    lane_url[$lane]="$INTEGRATION_POSTGRES_LANE_URL"
    lane_rust_url[$lane]="$INTEGRATION_POSTGRES_LANE_URL_RUST"
  done
  integration_postgres_wait_started
  # One after another, the migrations took about 1.5 s each (run 22601).
  for lane in "${@:2}"; do
    (
      integration_postgres_wait_ready "${lane_url[$lane]}" "lane $lane" \
        "${INTEGRATION_POSTGRES_CONTAINER}-lane-$lane"
      DATABASE_URL="${lane_url[$lane]}"
      DATABASE_URL_RUST="${lane_rust_url[$lane]}"
      reset_schema
    ) >"$RUN_DIR/lane-$lane-setup.log" 2>&1 &
    setup_pid[$lane]=$!
  done
  for lane in "${@:2}"; do
    status=0
    wait "${setup_pid[$lane]}" || status=$?
    cat "$RUN_DIR/lane-$lane-setup.log"
    if [ "$status" -ne 0 ]; then
      echo "::error::lane $lane did not migrate its PostgreSQL (status $status)"
      failed=true
    fi
  done
  [ "$failed" = false ]
}

# run_lanes KIND AT_ONCE THREADS LANE...: runs run_KIND_lane LANE for every
# lane, each in its own process against its own database (the caller's
# lane_url and lane_rust_url), at most AT_ONCE at a time in the order given,
# and with THREADS test threads each when THREADS is set. A lane's output
# follows its end, under "=== KIND lane LANE ===", with its time as a
# CODEWIRE_CI_PHASE line, and its own PostgreSQL is removed then, so it holds
# no memory while the others run. Every lane runs to its end; this fails when
# any lane failed.
run_lanes() {
  local kind="$1" at_once="$2" lane_threads="$3" lane started status failed=false
  local next=0 running=0 queue ended
  local -A lane_pid=() lane_started=()
  shift 3
  local -a order=("$@")
  # Each lane reports its name and status on this queue when it ends, so the
  # scheduler never waits on a lane the shell has already reaped: on Bash
  # 5.2, wait -n -p refused such a lane ("no such job") and named none.
  queue="$(mktemp -d "$RUN_DIR/$kind-lanes.XXXXXX")"
  mkfifo "$queue/ended"
  exec {ended}<>"$queue/ended"
  log "$kind lanes: ${at_once} at a time${lane_threads:+, ${lane_threads} test threads each}: ${order[*]}"
  while ((next < ${#order[@]} || running > 0)); do
    while ((running < at_once && next < ${#order[@]})); do
      lane="${order[$next]}"
      next=$((next + 1))
      lane_started[$lane]="$SECONDS"
      (
        exec {ended}>&-
        # Not a condition: the lane keeps errexit.
        set +e
        (
          set -e
          DATABASE_URL="${lane_url[$lane]}"
          DATABASE_URL_RUST="${lane_rust_url[$lane]}"
          if [ -n "$lane_threads" ]; then
            export RUST_TEST_THREADS="$lane_threads" NEXTEST_TEST_THREADS="$lane_threads"
          fi
          "run_${kind}_lane" "$lane"
        ) >"$RUN_DIR/$kind-lane-$lane.log" 2>&1
        printf '%s %s\n' "$lane" "$?" >"$queue/ended"
      ) &
      lane_pid[$lane]=$!
      running=$((running + 1))
    done
    read -r lane status <&"$ended"
    [ -n "${lane_pid[$lane]:-}" ] || {
      echo "::error::a $kind lane ended that this run did not start: $lane" >&2
      return 2
    }
    wait "${lane_pid[$lane]}" 2>/dev/null || true
    unset 'lane_pid[$lane]'
    running=$((running - 1))
    [ "${lane_url[$lane]}" = "$DATABASE_URL" ] || integration_postgres_stop_lane "$lane"
    started="${lane_started[$lane]}"
    echo "=== $kind lane $lane ==="
    cat "$RUN_DIR/$kind-lane-$lane.log"
    printf 'CODEWIRE_CI_PHASE name=%s-lane-%s seconds=%s status=%s\n' \
      "$kind" "$lane" "$((SECONDS - started))" "$status"
    if [ "$status" -ne 0 ]; then
      echo "::error::$kind lane $lane failed with status $status"
      failed=true
    fi
  done
  exec {ended}>&-
  rm -rf -- "$queue"
  [ "$failed" = false ]
}

# list_database_suites: every database lane's suites list their tests, and
# each database test must be in exactly one listing, before any lane runs.
list_database_suites() {
  local lane
  for lane in "${DATABASE_LANES[@]}"; do
    SUITE_LIST_ONLY=true run_database_lane "$lane"
  done
  python3 -B "$ROOT/scripts/ci/verify/database-test-coverage.py" \
    --root "${DATABASE_TEST_SOURCE_ROOT:-$ROOT}" --listings "$SUITE_LISTINGS"
}

run_database() {
  local lane
  local -A lane_url=() lane_rust_url=()
  if [ -n "${RUST_DATABASE_ARCHIVES:-}" ]; then
    extract_archives "$RUST_DATABASE_ARCHIVES"
  else
    build_database_suites
  fi
  list_database_suites
  reset_schema
  if ! integration_postgres_lanes_available; then
    log "database lanes run one after another against the explicit database"
    for lane in "${DATABASE_LANES[@]}"; do
      run_database_lane "$lane"
    done
    return 0
  fi
  start_lane_databases "${DATABASE_LANES[@]}"
  # On a metal guest, the lanes share the job's part of the host
  # (CODEWIRE_CI_CPU_SHARE, cpu-share.sh): each lane is a test process and
  # its own PostgreSQL, which creates and migrates a database for each test.
  # A lane mostly waits on its server: five at once averaged 2 cores of the
  # heavy share of 16 and peaked at 5.1 (main runs 23934 and 23971), about
  # one core per lane at its peak. So one lane per core of the share runs at
  # once, at most DATABASE_LANES_MEMORY_BOUND, longest first, each with its
  # part of the share (at least two) as its test threads;
  # CODEWIRE_CI_DATABASE_LANES_AT_ONCE sets the count instead. Elsewhere all
  # lanes run at once.
  local share at_once="${#DATABASE_LANES[@]}" lane_threads=""
  share="$(ci_cpu_share)"
  if [ -n "$share" ]; then
    if [ -n "${CODEWIRE_CI_DATABASE_LANES_AT_ONCE:-}" ]; then
      at_once="$CODEWIRE_CI_DATABASE_LANES_AT_ONCE"
      if ! [[ "$at_once" =~ ^[1-9][0-9]?$ ]] || ((at_once > ${#DATABASE_LANES[@]})); then
        echo "::error::CODEWIRE_CI_DATABASE_LANES_AT_ONCE must be 1 to ${#DATABASE_LANES[@]}, not $at_once" >&2
        return 2
      fi
    else
      ((share >= at_once)) || at_once="$share"
      ((at_once <= DATABASE_LANES_MEMORY_BOUND)) || at_once="$DATABASE_LANES_MEMORY_BOUND"
    fi
    lane_threads=$((share / at_once))
    ((lane_threads >= 2)) || lane_threads=2
  fi
  [ "$(printf '%s\n' "${DATABASE_LANE_ORDER[@]}" | sort)" = "$(printf '%s\n' "${DATABASE_LANES[@]}" | sort)" ] || {
    echo '::error::DATABASE_LANE_ORDER must name every database lane once' >&2
    return 2
  }
  run_lanes database "$at_once" "$lane_threads" "${DATABASE_LANE_ORDER[@]}"
}

prepare_idp_keyring() {
  IDP_SIGNING_KEK_DIR="$RUN_DIR/idp-signing-keks"
  local revision=..synthetic
  install -d -m 1777 "$IDP_SIGNING_KEK_DIR"
  install -d -m 755 "$IDP_SIGNING_KEK_DIR/$revision"
  printf '%s' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
    > "$IDP_SIGNING_KEK_DIR/$revision/v1"
  chmod 644 "$IDP_SIGNING_KEK_DIR/$revision/v1"
  ln -s "$revision" "$IDP_SIGNING_KEK_DIR/..data"
  ln -s ..data/v1 "$IDP_SIGNING_KEK_DIR/v1"
}

install_temporal() {
  if [ -x "$RUN_DIR/bin/temporal" ]; then
    return
  fi
  (
    cd "$RUN_DIR"
    curl -fsSLO "https://github.com/temporalio/cli/releases/download/v${TEMPORAL_CLI_VERSION}/temporal_cli_${TEMPORAL_CLI_VERSION}_linux_amd64.tar.gz"
    curl -fsSLO "https://github.com/temporalio/cli/releases/download/v${TEMPORAL_CLI_VERSION}/checksums.txt"
    grep "temporal_cli_${TEMPORAL_CLI_VERSION}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -
    tar -xzf "temporal_cli_${TEMPORAL_CLI_VERSION}_linux_amd64.tar.gz" temporal
    install temporal "$RUN_DIR/bin/temporal"
  )
}

start_temporal() {
  if [ -f "$RUN_DIR/temporal.pid" ]; then
    return
  fi
  install_temporal
  # The store stays in memory. With --db-filename every write fsyncs a SQLite
  # file behind a single connection, so on a guest with slow shared storage
  # every store call queues past its deadline ("context deadline exceeded",
  # then "Namespace default is not found").
  "$RUN_DIR/bin/temporal" server start-dev --headless --ip 127.0.0.1 \
    --port "$TEMPORAL_PORT" > "$RUN_DIR/temporal.log" 2>&1 &
  echo $! > "$RUN_DIR/temporal.pid"
  local _
  for _ in $(seq 1 45); do
    # Ready means the namespace the services use answers from the store, not
    # only that the frontend accepts connections.
    if timeout 5 "$RUN_DIR/bin/temporal" operator namespace describe default \
        --address "$TEMPORAL_HOST_PORT" >/dev/null 2>&1; then
      log "Temporal ready"
      require_own_listener temporal "$TEMPORAL_PORT"
      return
    fi
    if ! kill -0 "$(cat "$RUN_DIR/temporal.pid")" 2>/dev/null; then
      echo "::error::Temporal dev server exited before becoming ready"
      return 1
    fi
    sleep 1
  done
  echo "::error::Temporal did not become ready"
  return 1
}

start_nats() {
  if [ -f "$RUN_DIR/nats.started" ]; then
    return
  fi
  local docker_network_args=()
  if [ -n "$INTEGRATION_DOCKER_NETWORK" ]; then
    docker_network_args=(
      --network "$INTEGRATION_DOCKER_NETWORK"
      --network-alias "$INTEGRATION_NATS_HOST"
    )
  else
    docker_network_args=(
      -p "127.0.0.1:${NATS_CLIENT_PORT}:4222"
      -p "127.0.0.1:${NATS_MONITOR_PORT}:8222"
    )
  fi
  docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$NATS_CONTAINER" --pids-limit 2048 \
    "${docker_network_args[@]}" "${INTEGRATION_FIXTURE_LABELS[@]}" \
    "${INTEGRATION_NATS_IMAGE:-$INTEGRATION_NATS_PINNED_IMAGE}" -js -m 8222 > "$RUN_DIR/nats.container"
  touch "$RUN_DIR/nats.started"
  local _
  for _ in $(seq 1 30); do
    if curl -fsS "$NATS_MONITOR_URL" >/dev/null 2>&1; then
      log "NATS ready"
      return
    fi
    sleep 1
  done
  docker logs "$NATS_CONTAINER" > "$RUN_DIR/nats.log" 2>&1 || true
  echo "::error::NATS did not become ready"
  return 1
}

probe_connect_surface() {
  local name="$1" port="$2" body
  body="$(curl -fsS -X POST -H 'content-type: application/json' -d '{}' \
    "http://127.0.0.1:${port}/codewire.testing.v1.PingService/PublicPing")"
  [ "$body" = '{"message":"public pong"}' ] || {
    echo "::error::${name} returned unexpected PublicPing body: ${body}"
    return 1
  }
}

build_selected_services() {
  local packages=() binary
  selected service_idp && packages+=( -p codewire-idp )
  selected service_coordinator && packages+=( -p codewire-coordinator )
  selected service_billing && packages+=( -p codewire-billing )
  selected service_nats && packages+=( -p codewire-coordinator )
  if [ "${#packages[@]}" -eq 0 ] \
      && ! selected service_orchestration \
      && ! selected service_connectcore; then
    echo "::error::service integration selected without a service scope"
    return 1
  fi
  log "Cargo target directory: $CARGO_TARGET_DIR"
  if [ "${#packages[@]}" -gt 0 ]; then
    cargo_ci build --locked --profile ci "${packages[@]}"
    # Before any test build of these packages rebuilds their binaries with
    # the tests' features.
    selected service_idp && keep_binaries codewire-idp
    selected service_coordinator && keep_binaries codewire-coordinator
    selected service_billing && keep_binaries codewire-billing
  fi
  if selected service_orchestration; then
    cargo_ci build --locked --profile ci -p codewire-cli-bin --bin cw
    keep_binaries cw
    # One build for the wire contract and the service: an integration test
    # also builds every binary of its package, with the test's features, into
    # the profile directory. A separate `cargo build` of the binaries resolves
    # features without dev-dependencies and compiled the crate once more.
    cargo_ci test --locked --profile ci -p codewire-orchestration \
      --features kind-e2e --test wire_contract --no-run
    for binary in codewire-orchestration log-stream-smoke temporal-smoke; do
      [ -x "$CARGO_CI_DIR/$binary" ] || {
        echo "::error::the orchestration test build produced no $binary"
        return 1
      }
    done
    # The wire contract's archive carries these binaries (extract_archives).
  fi
}

# Building a service plane's archives (compile once, infra#1632): every test
# the run_* functions below run, one build per package and feature set, as
# they run it, in batches (compile_batches). The first batch builds the
# binaries the plane starts, the migration runner first, and with them the
# orchestration wire contract (build_selected_services); each other batch
# one package's tests. A test missing here fails its run, which finds no
# archive, or no test, for it.
service_build_binaries() {
  cargo_ci build --locked --profile ci -p codewire-server-core --bin codewire-db-migrate
  keep_binaries codewire-db-migrate
  build_selected_services
}
service_build_idp() {
  if selected service_idp; then
    cargo_ci test --locked --profile ci -p codewire-idp --test db_flow \
      --test session_inventory --test two_factor_replacement --test rewrap_cli \
      --test oauth_sign_in --no-run
  fi
}
service_build_coordinator() {
  local -a coordinator=(--lib)
  if selected service_coordinator; then coordinator+=(--test wire_contract); fi
  if selected service_coordinator || selected service_nats; then
    cargo_ci test --locked --profile ci -p codewire-coordinator "${coordinator[@]}" --no-run
  fi
}
service_build_billing() {
  if selected service_billing; then
    cargo_ci test --locked --profile ci -p codewire-billing --test wire_contract --no-run
  fi
}
service_build_connectcore() {
  if selected service_connectcore; then
    cargo_ci test --locked --profile ci -p codewire-server-core --test connect_auth --no-run
  fi
}
# service_build_batches PLANE: the plane's batches, one per line. One after
# another in one folder, the control plane took 371 s in main run 26920 (the
# migration runner 89 s, the binaries 80, idp 74, coordinator 52, billing
# 62, connect_auth 2), and the runtime plane 194 s in main run 27000 (the
# orchestration wire contract 92 s, the orchestration library 85; the
# library's database tests now run in the database lanes, which build it
# anyway). A step whose service is not selected builds nothing.
service_build_batches() {
  case "$1" in
    control) printf '%s\n' 'binaries connectcore' idp coordinator billing ;;
    runtime) printf '%s\n' 'binaries coordinator' ;;
    *) echo "::error::unknown service plane: $1" >&2; return 2 ;;
  esac
}

# The idp suites, in the order run_idp runs them against one database. In
# lanes, each of the three idp lanes runs part of them against its own.
run_idp_flow() {
  local logfile="$RUN_DIR/idp-db-flow.log"
  prepare_idp_keyring

  # Start from the freshly migrated schema before any token-flow test can
  # populate jwks. An issuer must publish the active Ed25519 key before a
  # relying party fetches discovery/JWKS or any user exchanges a code.
  start_proc idp "$IDP_PORT" env \
    DATABASE_URL="$DATABASE_URL_RUST" SESSION_SECRET="$SESSION_SECRET" \
    IDP_PORT="$IDP_PORT" PUBLIC_OIDC_ISSUER_URL="http://127.0.0.1:${IDP_PORT}" \
    FRONTEND_URL="http://127.0.0.1:${IDP_PORT}" \
    IDP_SIGNING_KEK_DIR="$IDP_SIGNING_KEK_DIR" IDP_SIGNING_ACTIVE_KEK_ID=v1 \
    "$CARGO_CI_DIR/codewire-idp"
  curl -fsS "http://127.0.0.1:${IDP_PORT}/.well-known/jwks.json" \
    | jq -e '
      (.keys | length == 1)
      and (.keys[0].kty == "OKP")
      and (.keys[0].crv == "Ed25519")
      and (.keys[0].alg == "EdDSA")
      and (.keys[0].use == "sig")
      and (.keys[0].kid | type == "string" and length > 0)
      and (.keys[0].x | type == "string" and length > 0)
    ' >/dev/null
  stop_proc idp

  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test db_flow -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp db_flow skipped"
    return 1
  fi
  assert_passed_count "idp db_flow" "$logfile" 13
}

run_idp_session_inventory() {
  local logfile="$RUN_DIR/idp-session-inventory.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test session_inventory -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp session inventory DB tests skipped"
    return 1
  fi
  assert_passed_count "idp session inventory" "$logfile" 7
}

run_idp_two_factor() {
  local logfile="$RUN_DIR/idp-two-factor-replacement.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test two_factor_replacement -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp two-factor replacement DB tests skipped"
    return 1
  fi
  assert_passed_count "idp two-factor replacement" "$logfile" 11
}

run_idp_rewrap_cli() {
  local logfile="$RUN_DIR/idp-rewrap-cli.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test rewrap_cli -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp rewrap CLI DB test skipped"
    return 1
  fi
  assert_passed_count "idp rewrap CLI" "$logfile" 2
}

# Sign in with GitHub or Google (#4062), against in-process fake providers.
run_idp_oauth_sign_in() {
  local logfile="$RUN_DIR/idp-oauth-sign-in.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test oauth_sign_in -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp OAuth sign-in DB tests skipped"
    return 1
  fi
  assert_passed_count "idp OAuth sign-in" "$logfile" 18
}

run_idp() {
  run_idp_flow
  run_idp_session_inventory
  run_idp_two_factor
  run_idp_rewrap_cli
  run_idp_oauth_sign_in
}

run_coordinator() {
  local logfile="$RUN_DIR/coordinator-protocol-auth.log"
  DATABASE_URL="$DATABASE_URL_RUST" cargo_ci test --profile ci \
    -p codewire-coordinator --lib \
    connect::tests::production_user_credentials_match_for_connect_and_grpc \
    -- --exact --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::coordinator protocol auth matrix skipped"
    return 1
  fi
  assert_passed_count "coordinator protocol auth matrix" "$logfile" 1

  # #3828: a client loses its session when a re-check refuses its access.
  logfile="$RUN_DIR/coordinator-client-recheck.log"
  DATABASE_URL="$DATABASE_URL_RUST" cargo_ci test --profile ci \
    -p codewire-coordinator --lib \
    connect::tests::production_client_session_ends_when_its_access_is_revoked \
    -- --exact --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::coordinator client re-check skipped"
    return 1
  fi
  assert_passed_count "coordinator client re-check" "$logfile" 1

  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -f "$ROOT/tests/fixtures/coordinator/seed.sql"
  start_proc coordinator "$COORDINATOR_PORT" env \
    DATABASE_URL="$DATABASE_URL_RUST" SESSION_SECRET="$SESSION_SECRET" \
    COORDINATOR_PORT="$COORDINATOR_PORT" \
    CODEWIRE_API_URL="http://127.0.0.1:${COORDINATOR_PORT}" NATS_URL= \
    ENVIRONMENT=local "$CARGO_CI_DIR/codewire-coordinator"
  wait_http coordinator-ready "http://127.0.0.1:${COORDINATOR_PORT}/readyz" \
    "$RUN_DIR/coordinator.pid"
  COORDINATOR_BASE_URL="http://127.0.0.1:${COORDINATOR_PORT}" \
    COORDINATOR_SEEDED=1 \
    COORDINATOR_USER_SESSION_TOKEN=coordinator-contract-session-token \
    COORDINATOR_SESSION_SECRET="$SESSION_SECRET" \
    cargo_ci test --locked --profile ci -p codewire-coordinator \
      --test wire_contract configured_coordinator_wire_contract -- \
      --ignored --exact --nocapture | tee "$RUN_DIR/coordinator-contract.log"
  assert_passed_count \
    "Rust coordinator wire contract" "$RUN_DIR/coordinator-contract.log" 1
  stop_proc coordinator
}

ensure_billing_fixture() {
  if [ "$BILLING_FIXTURE_LOADED" = true ]; then
    log "billing contract fixture already loaded"
    return
  fi

  log "loading billing contract fixture"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -f "$ROOT/tests/fixtures/billing/seed.sql"
  BILLING_FIXTURE_LOADED=true
}

# STRIPE_WEBHOOK_URL=off turns off billing's startup check of its Stripe
# webhook endpoint, so a test run never contacts Stripe with the dummy key.
start_billing() {
  ensure_billing_fixture
  start_temporal
  start_proc billing "$BILLING_PORT" env \
    DATABASE_URL="$DATABASE_URL_RUST" SESSION_SECRET="$SESSION_SECRET" \
    BILLING_PORT="$BILLING_PORT" BILLING_LOOPS= \
    FRONTEND_URL="http://127.0.0.1:${BILLING_PORT}" \
    STRIPE_SECRET_KEY=sk_test_buildtest_dummy \
    STRIPE_WEBHOOK_SECRET=whsec_test_secret STRIPE_WEBHOOK_URL=off \
    TEMPORAL_HOST_PORT="$TEMPORAL_HOST_PORT" CONNECT_TESTING_SURFACE=1 \
    "$CARGO_CI_DIR/codewire-billing"
  probe_connect_surface billing "$BILLING_PORT"
}

run_billing() {
  start_billing
  (
    cd "$ROOT"
    BILLING_BASE_URL="http://127.0.0.1:${BILLING_PORT}" \
      BILLING_ADMIN_SESSION_TOKEN=contract-admin-session-token \
      BILLING_USER_SESSION_TOKEN=contract-user-session-token BILLING_SEEDED=1 \
      cargo_ci test --locked --profile ci -p codewire-billing \
        --test wire_contract configured_billing_wire_contract \
        -- --ignored --exact --nocapture | tee "$RUN_DIR/billing-contract.log"
    assert_passed_count \
      "configured Rust billing Connect contract" "$RUN_DIR/billing-contract.log" 1
  )
  stop_proc billing
}

write_orchestration_kubeconfig() {
  local kubeconfig="$RUN_DIR/orchestration-exec-contract-kubeconfig"
  umask 077
  {
    printf '%s\n' \
      'apiVersion: v1' \
      'kind: Config' \
      'current-context: exec-contract' \
      'clusters:' \
      '- name: exec-contract' \
      '  cluster:' \
      "    server: http://127.0.0.1:${ORCHESTRATION_KUBE_STUB_PORT}" \
      'contexts:' \
      '- name: exec-contract' \
      '  context:' \
      '    cluster: exec-contract' \
      '    user: exec-contract' \
      'users:' \
      '- name: exec-contract' \
      '  user: {}'
  } > "$kubeconfig"
  printf '%s\n' "$kubeconfig"
}

start_orchestration_kube_stub() {
  start_proc orchestration-kube-stub "$ORCHESTRATION_KUBE_STUB_PORT" \
    python3 -u -c '
import base64
import hashlib
import http.server
import json
import struct
import sys
import time

port = int(sys.argv[1])

runtimes = {
    "env_exec_contract_backend": {
        "pod_name": "exec-contract-pod",
        "pod_uid": "exec-contract-pod-uid",
        "pod_ip": "10.244.0.21",
    },
    "env_exec_contract_unavailable": {
        "pod_name": "exec-contract-unavailable-pod",
        "pod_uid": "exec-contract-unavailable-pod-uid",
        "pod_ip": "10.244.0.22",
    },
}

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def empty_response(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def json_response(self, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def runtime_response(self):
        path = self.path.split("?", 1)[0]
        namespace = "exec-contract"
        for environment_id, runtime in runtimes.items():
            claim_name = "sandbox-" + environment_id
            if path == (
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/"
                + namespace + "/sandboxclaims/" + claim_name
            ):
                self.json_response({
                    "apiVersion": "extensions.agents.x-k8s.io/v1beta1",
                    "kind": "SandboxClaim",
                    "metadata": {
                        "name": claim_name,
                        "namespace": namespace,
                        "uid": claim_name + "-uid",
                    },
                    "status": {
                        "conditions": [{
                            "type": "Ready",
                            "status": "True",
                            "reason": "ContractReady",
                        }],
                        "sandbox": {"name": runtime["pod_name"]},
                    },
                })
                return True
            if path == (
                "/apis/agents.x-k8s.io/v1beta1/namespaces/"
                + namespace + "/sandboxes/" + runtime["pod_name"]
            ):
                self.json_response({
                    "apiVersion": "agents.x-k8s.io/v1beta1",
                    "kind": "Sandbox",
                    "metadata": {
                        "name": runtime["pod_name"],
                        "namespace": namespace,
                        "uid": runtime["pod_uid"] + "-sandbox",
                    },
                    "spec": {"operatingMode": "Running"},
                })
                return True
            if path == (
                "/api/v1/namespaces/" + namespace
                + "/pods/" + runtime["pod_name"]
            ):
                # A legacy (environment-token) workspace Pod controlled by its
                # Sandbox: with no live binding, orchestration presents the
                # environment daemon token only to a Pod rendered with it.
                self.json_response({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": runtime["pod_name"],
                        "namespace": namespace,
                        "uid": runtime["pod_uid"],
                        "ownerReferences": [{
                            "apiVersion": "agents.x-k8s.io/v1beta1",
                            "kind": "Sandbox",
                            "name": runtime["pod_name"],
                            "uid": runtime["pod_uid"] + "-sandbox",
                            "controller": True,
                        }],
                    },
                    "spec": {
                        "containers": [{
                            "name": "workspace",
                            "image": "exec-contract-workspace",
                            "env": [{
                                "name": "CODEWIRE_DAEMON_AUTH_TOKEN",
                                "value": "exec-contract-fixture",
                            }],
                        }],
                        "nodeName": "exec-contract-node",
                    },
                    "status": {
                        "phase": "Running",
                        "podIP": runtime["pod_ip"],
                    },
                })
                return True
        return False

    def send_ws_frame(self, channel, payload):
        body = bytes([channel]) + payload
        length = len(body)
        if length < 126:
            header = bytes([0x82, length])
        elif length <= 0xffff:
            header = bytes([0x82, 126]) + struct.pack("!H", length)
        else:
            header = bytes([0x82, 127]) + struct.pack("!Q", length)
        self.wfile.write(header + body)
        self.wfile.flush()

    def exec_contract_success(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self.empty_response(400)
            return
        # RFC 6455 requires SHA-1 for the websocket handshake; this is not
        # credential hashing.
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest()).decode()
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.send_header("Sec-WebSocket-Protocol", "v4.channel.k8s.io")
        self.end_headers()

        status = json.dumps({
            "apiVersion": "v1",
            "kind": "Status",
            "metadata": {},
            "status": "Failure",
            "message": "command terminated with exit code 17",
            "reason": "NonZeroExitCode",
            "details": {
                "causes": [{"reason": "ExitCode", "message": "17"}],
            },
        }, separators=(",", ":")).encode()
        try:
            self.send_ws_frame(1, b"stdout-one\n")
            time.sleep(0.05)
            self.send_ws_frame(2, b"stderr-one\n")
            time.sleep(0.05)
            self.send_ws_frame(1, b"stdout-two\n")
            time.sleep(0.05)
            self.send_ws_frame(3, status)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def do_GET(self):
        if self.path == "/healthz":
            self.empty_response(200)
            return
        if self.runtime_response():
            return
        if (
            "codewire-contract-exec-happy" in self.path
            and self.headers.get("Upgrade", "").lower() == "websocket"
        ):
            # WI-8 reserves one marker command for deterministic Kubernetes
            # remotecommand frames. Every other request retains the failure
            # behavior used by the timeout and upstream-boundary contracts.
            self.exec_contract_success()
            return
        # Hold Kubernetes exec upgrade requests long enough for the contract
        # timeout to win deterministically. The ordinary upstream-boundary
        # case then receives a deliberate 404.
        time.sleep(0.25)
        self.empty_response(404)

    do_POST = do_GET

    def log_message(self, format, *args):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
' "$ORCHESTRATION_KUBE_STUB_PORT"
}

start_orchestration_daemon_fixture() {
  local fixture_root="$RUN_DIR/orchestration-daemon-root"
  local workspace_root="$fixture_root/workspace"
  local home_root="$fixture_root/home"
  local token
  install -d -m 0700 "$fixture_root" "$workspace_root" "$home_root"
  cat > "$workspace_root/codewire-contract-exec-happy" <<'EOF'
#!/bin/sh
printf 'stdout-one\n'
printf 'stderr-one\n' >&2
printf 'stdout-two\n'
exit 17
EOF
  cat > "$workspace_root/codewire-contract-exec-timeout" <<'EOF'
#!/bin/sh
sleep 1
EOF
  chmod 0500 \
    "$workspace_root/codewire-contract-exec-happy" \
    "$workspace_root/codewire-contract-exec-timeout"
  token="$(
    CODEWIRE_TOKEN_SECRET="$SESSION_SECRET" \
    CODEWIRE_TOKEN_ENVIRONMENT_ID=env_exec_contract_backend \
      python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import os

environment_id = os.environ["CODEWIRE_TOKEN_ENVIRONMENT_ID"]
secret = os.environ["CODEWIRE_TOKEN_SECRET"].encode()
payload = json.dumps(
    {"environment_id": environment_id, "scope": "daemon"},
    separators=(",", ":"),
).encode()
encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
signature = base64.urlsafe_b64encode(
    hmac.new(secret, encoded, hashlib.sha256).digest()
).rstrip(b"=")
print((encoded + b"." + signature).decode())
PY
  )"

  log "starting orchestration-daemon"
  env \
    PATH="$workspace_root:$PATH" \
    CODEWIRE_WORKSPACE_SHIM_ADDR="127.0.0.1:${ORCHESTRATION_DAEMON_PORT}" \
    CODEWIRE_WORKSPACE_ROOT="$workspace_root" \
    CODEWIRE_HOME_ROOT="$home_root" \
    CODEWIRE_DAEMON_AUTH_TOKEN="$token" \
    "$CARGO_CI_DIR/cw" __hosted-daemon \
    > "$RUN_DIR/orchestration-daemon.log" 2>&1 &
  echo $! > "$RUN_DIR/orchestration-daemon.pid"
  local _
  for _ in $(seq 1 45); do
    if python3 - "$ORCHESTRATION_DAEMON_PORT" <<'PY'
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
    pass
PY
    then
      log "orchestration-daemon ready"
      return
    fi
    if ! kill -0 "$(cat "$RUN_DIR/orchestration-daemon.pid")" 2>/dev/null; then
      echo "::error::orchestration-daemon exited before accepting connections"
      return 1
    fi
    sleep 1
  done
  echo "::error::orchestration-daemon did not become ready"
  return 1
}

start_orchestration_process() {
  local kube_mode="$1" kubeconfig
  local -a daemon_endpoint_environment=()
  case "$kube_mode" in
    configured)
      kubeconfig="$(write_orchestration_kubeconfig)"
      daemon_endpoint_environment=(
        CODEWIRE_TEST_ENVIRONMENT_DAEMON_ENDPOINTS_JSON="{\"env_exec_contract_backend\":\"http://127.0.0.1:${ORCHESTRATION_DAEMON_PORT}\",\"env_exec_contract_unavailable\":\"http://127.0.0.1:${ORCHESTRATION_UNAVAILABLE_DAEMON_PORT}\"}"
      )
      ;;
    unconfigured)
      kubeconfig="$RUN_DIR/orchestration-deliberately-missing-kubeconfig"
      rm -f "$kubeconfig"
      ;;
    *)
      echo "::error::unknown orchestration kube mode: ${kube_mode}"
      return 1
      ;;
  esac

  # A worker with a sandbox backend requires the workspace-binding Service
  # namespace and an API URL at startup (Program #2238 review L2).
  start_proc orchestration "$ORCHESTRATION_PORT" env \
    KUBECONFIG="$kubeconfig" \
    KUBERNETES_SERVICE_HOST= KUBERNETES_SERVICE_PORT= \
    POD_NAMESPACE=codewire-integration \
    CODEWIRE_API_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
    DATABASE_URL="$DATABASE_URL_RUST" SESSION_SECRET="$SESSION_SECRET" \
    CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER=true \
    CODEWIRE_WORKSPACE_IMAGE_REPOSITORY=registry.example.invalid/codewire/workspace \
    CODEWIRE_APPROVED_IMAGE_REGISTRIES=registry.example.invalid/,docker.io/library/ \
    SANDBOX_DAEMON_IMAGE=registry.example.invalid/codewire/daemon@sha256:adaba1f8e5ca50ed7aaeaf1b15d0588e441cadd1830e508a83108f798f66e029 \
    SANDBOX_WORKSPACE_STORAGE_CLASS=standard \
    ORCHESTRATION_PORT="$ORCHESTRATION_PORT" \
    TEMPORAL_HOST_PORT="$TEMPORAL_HOST_PORT" WORKER_CONSUMERS= WORKER_LOOPS= \
    "${daemon_endpoint_environment[@]}" \
    CONNECT_TESTING_SURFACE=1 "$CARGO_CI_DIR/codewire-orchestration"
}

start_orchestration() {
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -f "$ROOT/tests/fixtures/orchestration/seed.sql"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -f "$ROOT/tests/fixtures/orchestration/runtime-ready.sql"
  start_temporal
  start_orchestration_kube_stub
  start_orchestration_daemon_fixture
  start_orchestration_process configured
  # /healthz answers once the listener binds; /readyz only after the first
  # background tenant-secret verification succeeds. The wire contract asserts
  # /readyz first, so wait for it here (PR run 22418 read 503 1.4 s after
  # start).
  wait_http orchestration-readiness "http://127.0.0.1:${ORCHESTRATION_PORT}/readyz" \
    "$RUN_DIR/orchestration.pid"
  probe_connect_surface orchestration "$ORCHESTRATION_PORT"
}

run_orchestration() {
  local logfile
  start_orchestration
  logfile="$RUN_DIR/orchestration-contract.log"
  ORCHESTRATION_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
    ORCHESTRATION_GLOBAL_ADMIN_SESSION_TOKEN=orchestration-global-admin-session-token \
    ORCHESTRATION_ADMIN_SESSION_TOKEN=apikey-contract-admin-session-token \
    ORCHESTRATION_USER_SESSION_TOKEN=apikey-contract-user-session-token \
    ORCHESTRATION_SEEDED=1 ORCHESTRATION_KUBE_MODE=configured \
    ORCHESTRATION_CONTRACT_SCOPE=complete \
    TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --locked --profile ci -p codewire-orchestration \
      --test wire_contract --features kind-e2e \
      configured_orchestration_wire_contract -- \
      --ignored --exact --nocapture | tee "$logfile"
  assert_passed_count "Rust orchestration wire contract" "$logfile" 1

  SMOKE_CONNECT_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
    SMOKE_DATABASE_URL="$DATABASE_URL_RUST" \
    SMOKE_ORG_ID=org_apikey_contract_1 \
    SMOKE_ENVIRONMENT_ID=env_environment_contract_read \
    SMOKE_SESSION_TOKEN=apikey-contract-admin-session-token \
    SMOKE_ASSERT_NO_BUFFERING_HEADER=1 \
    "$CARGO_CI_DIR/log-stream-smoke"

  stop_proc orchestration
  stop_proc orchestration-daemon
  start_orchestration_process unconfigured
  logfile="$RUN_DIR/orchestration-kube-unconfigured-contract.log"
  ORCHESTRATION_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
    ORCHESTRATION_GLOBAL_ADMIN_SESSION_TOKEN=orchestration-global-admin-session-token \
    ORCHESTRATION_ADMIN_SESSION_TOKEN=apikey-contract-admin-session-token \
    ORCHESTRATION_USER_SESSION_TOKEN=apikey-contract-user-session-token \
    ORCHESTRATION_SEEDED=1 ORCHESTRATION_KUBE_MODE=unconfigured \
    ORCHESTRATION_CONTRACT_SCOPE=runtime \
    cargo_ci test --locked --profile ci -p codewire-orchestration \
      --test wire_contract --features kind-e2e \
      configured_orchestration_wire_contract -- \
      --ignored --exact --nocapture | tee "$logfile"
  assert_passed_count "Rust orchestration kube-unconfigured contract" "$logfile" 1
}

run_connect_auth_matrix() {
  local logfile="$RUN_DIR/connect-auth.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-server-core --test connect_auth \
    -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::Connect auth matrix skipped"
    return 1
  fi
  assert_passed_count "Connect auth matrix" "$logfile" 6
}

run_billing_temporal() {
  [ -f "$RUN_DIR/billing.pid" ] || start_billing
  local wid="org-teardown/verification-${GITHUB_RUN_ID:-local}"
  "$RUN_DIR/bin/temporal" workflow start --address "$TEMPORAL_HOST_PORT" \
    --task-queue codewire-billing --type OrgTeardownWorkflow \
    --workflow-id "$wid" --input '{"org_id":"verification-nonexistent"}'
  timeout 120 "$RUN_DIR/bin/temporal" workflow result \
    --address "$TEMPORAL_HOST_PORT" --workflow-id "$wid"
}

run_orchestration_temporal() {
  [ -f "$RUN_DIR/orchestration.pid" ] || start_orchestration
  local env_id="env-temporal-verification-${GITHUB_RUN_ID:-local}" state reason
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v env_id="$env_id" <<'SQL'
INSERT INTO environment_presets (id, org_id, name, slug, project_spec)
VALUES (
  'preset_temporal_verification',
  'org_apikey_contract_1',
  'Temporal Verification',
  'temporal-verification',
  '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
);
INSERT INTO environments (
  id, org_id, created_by, type, state, desired_state,
  cpu_millicores, memory_mb, disk_gb, preset_id, project_spec
)
VALUES (
  :'env_id',
  'org_apikey_contract_1',
  'usr_apikey_contract_admin',
  'sandbox',
  'pending',
  'started',
  2000,
  4096,
  10,
  'preset_temporal_verification',
  '{"schema_version":1,"working_directory":"/workspace","resources":{"cpu_millicores":2000,"memory_mib":4096,"disk_gib":10}}'::jsonb
);
SQL
  TEMPORAL_ADDRESS="http://${TEMPORAL_HOST_PORT}" \
    DATABASE_URL="$DATABASE_URL_RUST" SMOKE_ENV_ID="$env_id" \
    timeout "${TEMPORAL_SMOKE_TIMEOUT:-120s}" "$CARGO_CI_DIR/temporal-smoke"
  state="$(psql "$DATABASE_URL" -tAc \
    "SELECT state FROM environments WHERE id = '$env_id'")"
  reason="$(psql "$DATABASE_URL" -tAc \
    "SELECT error_reason FROM environments WHERE id = '$env_id'")"
  log "orchestration Temporal smoke state=${state:-missing} reason=${reason:-missing}"
  if [ "$state" != error ] || [[ "$reason" != "template config:"* ]]; then
    echo "::error::orchestration Temporal smoke ended state=${state:-missing} reason=${reason:-missing}"
    return 1
  fi
}

run_temporal() {
  selected service_orchestration && run_orchestration_temporal
  selected service_billing && run_billing_temporal
  return 0
}

run_nats() {
  local logfile
  start_nats
  logfile="$RUN_DIR/coordinator-nats-kv.log"
  NATS_URL="$NATS_URL" cargo_ci test --profile ci -p codewire-coordinator \
    --lib coordination_plane_round_trips_nats_and_kv -- --ignored --nocapture \
    | tee "$logfile"
  assert_passed_count "coordinator NATS/KV smoke" "$logfile" 1
  logfile="$RUN_DIR/coordinator-generated-cross-replica.log"
  NATS_URL="$NATS_URL" cargo_ci test --profile ci -p codewire-coordinator \
    --lib generated_protocol_cross_replica_fanout_round_trips_over_nats \
    -- --ignored --nocapture | tee "$logfile"
  assert_passed_count "coordinator generated cross-replica smoke" "$logfile" 1
}

# The control plane's suites run in lanes when each can have its own
# PostgreSQL, all at once: one after another, the idp suites alone took 85 s
# of a 147 s job (main run 23934), and the job averaged 2 of its 8 cores.
# Each lane keeps its suites in their order against its own freshly migrated
# database, and each service it starts keeps its own port of the job's range
# (idp, coordinator, billing and Temporal), so no lane shares a schema, a
# row or a listener with another. The idp suites split three ways: the JWKS
# check and db_flow (38 s), two_factor_replacement (37 s), and session
# inventory with the rewrap CLI (8 s) and OAuth sign-in (under 1 s locally).
# The first lane runs against the job's own database, and every other lane
# against a PostgreSQL of its own.
readonly SERVICE_CONTROL_LANES=(
  idp-two-factor # idp two-factor replacement
  idp-flow       # idp JWKS readiness and db_flow
  idp-sessions   # idp session inventory, the signing-key rewrap CLI and OAuth sign-in
  connect-auth   # the Connect auth matrix
  billing        # the billing wire contract, then its Temporal workflow
  coordinator    # the coordinator protocol auth matrix and wire contract
)

run_service_lane() {
  case "$1" in
    idp-flow) run_idp_flow ;;
    idp-two-factor) run_idp_two_factor ;;
    idp-sessions)
      run_idp_session_inventory
      run_idp_rewrap_cli
      run_idp_oauth_sign_in
      ;;
    connect-auth) run_connect_auth_matrix ;;
    billing)
      run_billing
      if selected service_temporal; then
        run_billing_temporal
      fi
      ;;
    coordinator) run_coordinator ;;
    *) echo "::error::unknown service lane: $1"; return 2 ;;
  esac
}

# The control-plane lanes this run's selection asks for, in lane order.
service_control_lanes() {
  local lane
  for lane in "${SERVICE_CONTROL_LANES[@]}"; do
    case "$lane" in
      idp-*) selected service_idp || continue ;;
      connect-auth) selected service_connectcore || continue ;;
      billing) selected service_billing || continue ;;
      coordinator) selected service_coordinator || continue ;;
    esac
    printf '%s\n' "$lane"
  done
}

run_service_control_lanes() {
  local -a lanes=()
  local -A lane_url=() lane_rust_url=()
  mapfile -t lanes < <(service_control_lanes)
  [ "${#lanes[@]}" -gt 0 ] || return 0
  start_lane_databases "${lanes[@]}"
  run_lanes service "${#lanes[@]}" "" "${lanes[@]}"
}

run_services() {
  [ -z "$RUST_ARCHIVES" ] || extract_archives "$RUST_ARCHIVES"
  reset_schema
  build_selected_services
  if [ "$MODE" = services-control ] && integration_postgres_lanes_available; then
    run_service_control_lanes
    return
  fi
  selected service_idp && run_idp
  selected service_coordinator && run_coordinator
  selected service_billing && run_billing
  selected service_orchestration && run_orchestration
  selected service_connectcore && run_connect_auth_matrix
  selected service_temporal && run_temporal
  selected service_nats && run_nats
  return 0
}

filter_service_selection() {
  local token filtered='|valid:v3|'
  for token in "$@"; do
    selected "$token" && filtered+="${token}|"
  done
  printf '%scomplete|\n' "$filtered"
}

# service_plane_selection PLANE: this run's selection, cut to that plane.
service_plane_selection() {
  case "$1" in
    control)
      filter_service_selection service_idp service_coordinator service_billing \
        service_connectcore service_temporal
      ;;
    runtime) filter_service_selection service_orchestration service_nats service_temporal ;;
    *) echo "::error::unknown service plane: $1" >&2; return 2 ;;
  esac
}

case "$MODE" in
  database|services-control|services-runtime) acquire_lane_lock ;;
esac

case "$MODE" in
  database-archives)
    # The build runner's half of compile once: no PostgreSQL, no tests.
    : "${ARCHIVE_BUILD_DIR:?ARCHIVE_BUILD_DIR is required}"
    mkdir -p "$ARCHIVE_BUILD_DIR"
    compile_batches database_build "${DATABASE_BUILD_BATCHES[@]}" migration_runner
    log "database archives built: $(find "$ARCHIVE_BUILD_DIR" -name '*.tar.zst' | wc -l)"
    exit 0
    ;;
  database)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    run_database
    ;;
  services-control-archives|services-runtime-archives)
    # The build runner's half of compile once for one service plane: no
    # PostgreSQL, no tests. The binaries the plane starts go beside its
    # archives, the migration runner first.
    mkdir -p "$ARCHIVE_BUILD_DIR"
    plane="${MODE#services-}"
    SELECTION="$(service_plane_selection "${plane%-archives}")"
    mapfile -t batches < <(service_build_batches "${plane%-archives}")
    compile_batches service_build "${batches[@]}"
    log "$MODE built: $(find "$ARCHIVE_BUILD_DIR" -name '*.tar.zst' | wc -l) archives, $(find "$ARCHIVE_BUILD_DIR" -maxdepth 1 -type f ! -name '*.tar.zst' | wc -l) binaries"
    exit 0
    ;;
  services-control|services-runtime)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    SELECTION="$(service_plane_selection "${MODE#services-}")"
    run_services
    ;;
  *)
    echo "usage: run-integration-verification.sh database|database-archives|services-control|services-runtime|services-control-archives|services-runtime-archives" >&2
    exit 2
    ;;
esac

log "green"
