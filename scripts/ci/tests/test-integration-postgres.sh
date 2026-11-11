#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/integration-postgres-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  run)
    # A lane started in the background takes a while; one named in
    # FAKE_DOCKER_FAIL_RUN fails.
    case "$*" in *"${FAKE_DOCKER_FAIL_RUN:-no-such-container}"*) exit 125 ;; esac
    case "$*" in *-lane-*) sleep "${FAKE_DOCKER_RUN_SECONDS:-0}" ;; esac
    printf '%s\n' fake-container-id ;;
  port) printf '127.0.0.1:%s\n' "${FAKE_DOCKER_PORT:-45678}" ;;
  exec|rm) ;;
  # A PostgreSQL that never answers (#4196): its state, or that it is gone,
  # and its log.
  inspect)
    [ -z "${FAKE_DOCKER_GONE:-}" ] || { printf 'Error: No such object: %s\n' "${*: -1}" >&2; exit 1; }
    printf '%s\n' "${FAKE_DOCKER_STATE:-{\"Status\":\"running\"\}}" ;;
  logs) printf '%s\n' "${FAKE_DOCKER_LOGS:-}" ;;
  *) printf 'unexpected fake docker command: %s\n' "$1" >&2; exit 1 ;;
esac
EOF
chmod +x "$TMP/docker"
cat > "$TMP/psql" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_PSQL_LOG"
[ -z "${FAKE_PSQL_FAIL:-}" ] || { printf 'psql: error: %s\n' "$FAKE_PSQL_FAIL" >&2; exit 2; }
printf '%s\n' 1
EOF
chmod +x "$TMP/psql"
export PATH="$TMP:$PATH"
hash -r
# Fixtures trace the runner with fake tools; never start the workstation's
# real compiler-cache server from one.
export CODEWIRE_LOCAL_RUST_CACHE=off
# The job id and run attempt name containers (integration-postgres.sh); the
# cases below set them themselves, never inheriting the CI job's own (Policy
# runs this test).
unset GITHUB_JOB GITHUB_RUN_ATTEMPT

# shellcheck source=scripts/ci/verify/integration-postgres.sh
source "$ROOT/scripts/ci/verify/integration-postgres.sh"

reset_case() {
  DATABASE_URL=""
  DATABASE_URL_RUST=""
  DATABASE_URL_EXPLICIT=false
  DATABASE_URL_RUST_EXPLICIT=false
  GITHUB_ACTIONS=false
  GITHUB_RUN_ID="fixture-$$"
  INTEGRATION_POSTGRES_HOST_PORT=""
  FAKE_DOCKER_PORT=45678
  FAKE_DOCKER_LOG="$TMP/docker.log"
  FAKE_PSQL_LOG="$TMP/psql.log"
  export FAKE_DOCKER_LOG FAKE_PSQL_LOG FAKE_DOCKER_PORT
  : > "$FAKE_DOCKER_LOG"
  : > "$FAKE_PSQL_LOG"
  integration_postgres_init
}

reset_case
integration_postgres_configure
[ "$INTEGRATION_POSTGRES_SOURCE" = managed ]
[ "$DATABASE_URL" = "postgres://codewire:codewire@127.0.0.1:45678/codewire?sslmode=disable" ]
[ "$DATABASE_URL_RUST" = "postgres://codewire:codewire@127.0.0.1:45678/codewire" ]
grep -q '^run .*127.0.0.1::5432 docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$' "$FAKE_DOCKER_LOG"
grep -q '127.0.0.1:45678/codewire?sslmode=disable.*SELECT 1' "$FAKE_PSQL_LOG"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER$" "$FAKE_DOCKER_LOG"
[ "$INTEGRATION_POSTGRES_MANAGED" = false ]

# A managed database lane is one more loopback container, removed with the
# selected one.
reset_case
integration_postgres_configure
integration_postgres_lanes_available
integration_postgres_start_lane credential-broker
[ "$INTEGRATION_POSTGRES_LANE_URL" = "postgres://codewire:codewire@127.0.0.1:45678/codewire?sslmode=disable" ]
[ "$INTEGRATION_POSTGRES_LANE_URL_RUST" = "postgres://codewire:codewire@127.0.0.1:45678/codewire" ]
grep -q "^run -d --name $INTEGRATION_POSTGRES_CONTAINER-lane-credential-broker .*127.0.0.1::5432 docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER$" "$FAKE_DOCKER_LOG"

# A lane PostgreSQL that never answers says why (#4196): psql's last error,
# the container's state and the end of its log; a container that is gone is
# reported as gone. The lanes keep their containers (no --rm) for this.
report="$(FAKE_PSQL_FAIL='could not translate host name "codewire-integration-postgres-billing" to address' \
  FAKE_DOCKER_STATE='{"Status":"exited","ExitCode":1,"OOMKilled":false}' \
  FAKE_DOCKER_LOGS='FATAL:  could not create shared memory segment' INTEGRATION_POSTGRES_READY_ATTEMPTS=2 \
  integration_postgres_wait_ready postgres://x/codewire 'lane billing' fixture-lane-billing 2>&1)" &&
  { echo 'a PostgreSQL that never answered was ready' >&2; exit 1; }
for expected in '::error::lane billing PostgreSQL did not become ready' \
    'lane billing last psql error: psql: error: could not translate host name' \
    'fixture-lane-billing state: {"Status":"exited","ExitCode":1,"OOMKilled":false}' \
    '  | FATAL:  could not create shared memory segment'; do
  grep -qF -- "$expected" <<<"$report" || { echo "the readiness failure did not report: $expected" >&2; echo "$report" >&2; exit 1; }
done
report="$(FAKE_PSQL_FAIL='connection refused' FAKE_DOCKER_GONE=1 INTEGRATION_POSTGRES_READY_ATTEMPTS=1 \
  integration_postgres_wait_ready postgres://x/codewire 'lane billing' fixture-lane-billing 2>&1)" &&
  { echo 'a PostgreSQL that never answered was ready' >&2; exit 1; }
grep -qF 'fixture-lane-billing no longer exists: Error: No such object: fixture-lane-billing' <<<"$report" ||
  { echo "a removed container was not reported as gone: $report" >&2; exit 1; }
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER-lane-credential-broker$" "$FAKE_DOCKER_LOG"
if integration_postgres_start_lane 'Bad Lane' >/dev/null 2>&1; then
  echo 'an invalid database lane name was accepted' >&2
  exit 1
fi

# CI's database is explicit; its lanes join the job network under an alias.
reset_case
DATABASE_URL_EXPLICIT=true
DATABASE_URL="postgres://codewire:codewire@codewire-integration-postgres:5432/codewire?sslmode=disable"
integration_postgres_configure
if INTEGRATION_DOCKER_NETWORK='' integration_postgres_lanes_available; then
  echo 'an explicit database without a job network offered database lanes' >&2
  exit 1
fi
INTEGRATION_DOCKER_NETWORK=codewire-fixture-net
integration_postgres_lanes_available
integration_postgres_start_lane orchestration
[ "$INTEGRATION_POSTGRES_LANE_URL_RUST" = "postgres://codewire:codewire@codewire-integration-postgres-orchestration:5432/codewire" ]
grep -q "^run -d --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration --pids-limit 2048 --network codewire-fixture-net --network-alias codewire-integration-postgres-orchestration .* docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration$" "$FAKE_DOCKER_LOG"
# Lanes on the job network start at once in the background (their servers
# initialize while the archives extract); waiting for them reports a lane
# whose container did not start.
: > "$FAKE_DOCKER_LOG"
started=$SECONDS
FAKE_DOCKER_RUN_SECONDS=2 integration_postgres_start_lane core background
[ "$INTEGRATION_POSTGRES_LANE_URL_RUST" = "postgres://codewire:codewire@codewire-integration-postgres-core:5432/codewire" ]
FAKE_DOCKER_RUN_SECONDS=2 integration_postgres_start_lane broker-checked background
integration_postgres_wait_started
(( SECONDS - started < 4 )) || { echo 'the background lanes started one after another' >&2; exit 1; }
[ "$(grep -c "^run -d --name $INTEGRATION_POSTGRES_CONTAINER-lane-" "$FAKE_DOCKER_LOG")" -eq 2 ]
[ "${#INTEGRATION_POSTGRES_STARTING[@]}" -eq 0 ]
FAKE_DOCKER_FAIL_RUN=lane-orchestration integration_postgres_start_lane orchestration background
if integration_postgres_wait_started 2>"$TMP/wait-started.err"; then
  echo 'a lane whose container did not start was waited for as started' >&2
  exit 1
fi
grep -q 'a database lane PostgreSQL did not start' "$TMP/wait-started.err"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER-lane-broker-checked$" "$FAKE_DOCKER_LOG"
unset INTEGRATION_DOCKER_NETWORK

# A CI job's network without an explicit database: the run starts its own
# PostgreSQL on that network under its per-process container name, never a
# loopback port the job container cannot reach. Its lanes join the network.
reset_case
GITHUB_ACTIONS=true
INTEGRATION_DOCKER_NETWORK=codewire-fixture-net
integration_postgres_configure
[ "$INTEGRATION_POSTGRES_SOURCE" = network ]
[ "$INTEGRATION_POSTGRES_CONTAINER" = "codewire-product-postgres-fixture-$$-$$" ]
[ "$DATABASE_URL" = "postgres://codewire:codewire@$INTEGRATION_POSTGRES_CONTAINER:5432/codewire?sslmode=disable" ]
[ "$DATABASE_URL_RUST" = "postgres://codewire:codewire@$INTEGRATION_POSTGRES_CONTAINER:5432/codewire" ]
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER --pids-limit 2048 --network codewire-fixture-net --network-alias $INTEGRATION_POSTGRES_CONTAINER .* docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
if grep -q -- '127.0.0.1:' "$FAKE_DOCKER_LOG"; then
  echo 'a job-network PostgreSQL published a loopback port' >&2
  exit 1
fi
grep -q "@$INTEGRATION_POSTGRES_CONTAINER:5432/codewire?sslmode=disable.*SELECT 1" "$FAKE_PSQL_LOG"
integration_postgres_lanes_available
integration_postgres_start_lane orchestration
[ "$INTEGRATION_POSTGRES_LANE_URL_RUST" = "postgres://codewire:codewire@codewire-integration-postgres-orchestration:5432/codewire" ]
grep -q "^run -d --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration --pids-limit 2048 --network codewire-fixture-net " "$FAKE_DOCKER_LOG"
grep -q "^run -d --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration .* --label codewire.ci.run=fixture-$$ --label codewire.ci.attempt=0 --label codewire.ci.job=local " "$FAKE_DOCKER_LOG"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER$" "$FAKE_DOCKER_LOG"
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration$" "$FAKE_DOCKER_LOG"
[ "$INTEGRATION_POSTGRES_MANAGED" = false ]

reset_case
INTEGRATION_DOCKER_NETWORK='invalid/network'
if integration_postgres_configure >/dev/null 2>&1; then
  echo 'an invalid integration Docker network was accepted' >&2
  exit 1
fi
[ ! -s "$FAKE_DOCKER_LOG" ]
unset INTEGRATION_DOCKER_NETWORK

# Concurrent runs under one run ID (the lanes of one merge qualification)
# never share a run directory or a container name.
: > "$FAKE_DOCKER_LOG"
for _ in 1 2; do
  if GITHUB_RUN_ID="fixture-shared-$$" CODEWIRE_LOCAL_RUST_CACHE=off \
      "$ROOT/scripts/ci/verify/run-integration-verification.sh" no-such-mode >/dev/null 2>&1; then
    echo 'an unknown integration mode was accepted' >&2
    exit 1
  fi
done
shared_run_dirs=("$ROOT/.tmp/codewire-product-integration-fixture-shared-$$-"*)
rm -rf -- "${shared_run_dirs[@]}"
[ "${#shared_run_dirs[@]}" -eq 2 ]
[ "$(grep -c "^rm -f codewire-product-nats-fixture-shared-$$-[0-9]*$" "$FAKE_DOCKER_LOG")" -eq 2 ]
[ "$(sort -u "$FAKE_DOCKER_LOG" | grep -c '^rm -f codewire-product-nats-')" -eq 2 ]
first_container="$(bash -c 'GITHUB_RUN_ID=7; source "$1"; integration_postgres_init; printf %s "$INTEGRATION_POSTGRES_CONTAINER"' _ "$ROOT/scripts/ci/verify/integration-postgres.sh")"
second_container="$(bash -c 'GITHUB_RUN_ID=7; source "$1"; integration_postgres_init; printf %s "$INTEGRATION_POSTGRES_CONTAINER"' _ "$ROOT/scripts/ci/verify/integration-postgres.sh")"
[[ "$first_container" == codewire-product-postgres-7-* ]]
[ "$first_container" != "$second_container" ]
# Two jobs of one run on one Docker daemon (main's warm VM) never share a name,
# even when their processes have the same PID.
database_container="$(bash -c 'GITHUB_RUN_ID=7 GITHUB_JOB=database; source "$1"; integration_postgres_init; printf %s "$INTEGRATION_POSTGRES_CONTAINER"' _ "$ROOT/scripts/ci/verify/integration-postgres.sh")"
[[ "$database_container" == codewire-product-postgres-7-database-* ]]
# Two attempts of one job of one run never share a name, even with the same
# PID: a rerun attempt that starts while the old attempt's task still runs on
# the VM removes only its own fixtures. The attempt follows the job, so the
# VM's per-job usage match (codewire-.+-<run>-<job>(-.*)?) still finds them;
# every fixture carries its run, attempt and job as labels.
attempt_fixture() {
  bash -c 'GITHUB_RUN_ID=7 GITHUB_JOB=database GITHUB_RUN_ATTEMPT=$2
    source "$1"; integration_postgres_init
    printf "%s %s %s\n" "$(integration_fixture_name postgres)" "$(integration_fixture_name nats)" "${INTEGRATION_FIXTURE_LABELS[*]}"' \
    _ "$ROOT/scripts/ci/verify/integration-postgres.sh" "$1" |
    sed "s/-[0-9]* /-PID /g; s/-[0-9]*$/-PID/"
}
first_attempt="$(attempt_fixture 1)"
second_attempt="$(attempt_fixture 2)"
[ "$first_attempt" = 'codewire-product-postgres-7-database-a1-PID codewire-product-nats-7-database-a1-PID --label codewire.ci.run=7 --label codewire.ci.attempt=1 --label codewire.ci.job=database' ] ||
  { echo "unexpected attempt-1 fixture names: $first_attempt" >&2; exit 1; }
[ "$second_attempt" = 'codewire-product-postgres-7-database-a2-PID codewire-product-nats-7-database-a2-PID --label codewire.ci.run=7 --label codewire.ci.attempt=2 --label codewire.ci.job=database' ] ||
  { echo "unexpected attempt-2 fixture names: $second_attempt" >&2; exit 1; }
[[ "${first_attempt%% *}" =~ ^codewire-.+-7-database(-.*)?$ ]]
# A non-numeric attempt never reaches a container name.
[[ "$(bash -c 'GITHUB_RUN_ID=7 GITHUB_JOB=database GITHUB_RUN_ATTEMPT="1 x"; source "$1"; integration_fixture_name postgres' _ "$ROOT/scripts/ci/verify/integration-postgres.sh")" =~ ^codewire-product-postgres-7-database-[0-9]+$ ]]

reset_case
INTEGRATION_POSTGRES_HOST_PORT=55432
FAKE_DOCKER_PORT=55432
integration_postgres_configure
[ "$INTEGRATION_POSTGRES_SOURCE" = managed ]
[ "$DATABASE_URL" = "postgres://codewire:codewire@127.0.0.1:55432/codewire?sslmode=disable" ]
[ "$DATABASE_URL_RUST" = "postgres://codewire:codewire@127.0.0.1:55432/codewire" ]
grep -q '^run .*127.0.0.1:55432:5432 docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$' "$FAKE_DOCKER_LOG"
integration_postgres_cleanup

for invalid_port in invalid 1023 65536; do
  reset_case
  INTEGRATION_POSTGRES_HOST_PORT="$invalid_port"
  if integration_postgres_configure >/dev/null 2>&1; then
    echo "invalid fixed PostgreSQL port was accepted: $invalid_port" >&2
    exit 1
  fi
  [ ! -s "$FAKE_DOCKER_LOG" ]
done

reset_case
GITHUB_ACTIONS=true
integration_postgres_configure
[ "$INTEGRATION_POSTGRES_SOURCE" = ci ]
[ "$DATABASE_URL" = "postgres://codewire:codewire@127.0.0.1:5432/codewire?sslmode=disable" ]
[ "$DATABASE_URL_RUST" = "postgres://codewire:codewire@127.0.0.1:5432/codewire" ]
[ ! -s "$FAKE_DOCKER_LOG" ]

reset_case
DATABASE_URL_EXPLICIT=true
DATABASE_URL="postgres://synthetic:synthetic@127.0.0.1:60001/synthetic"
DATABASE_URL_RUST_EXPLICIT=true
DATABASE_URL_RUST="postgres://synthetic:synthetic@127.0.0.1:60002/synthetic"
integration_postgres_configure
[ "$INTEGRATION_POSTGRES_SOURCE" = explicit ]
[ "$DATABASE_URL" = "postgres://synthetic:synthetic@127.0.0.1:60001/synthetic" ]
[ "$DATABASE_URL_RUST" = "postgres://synthetic:synthetic@127.0.0.1:60002/synthetic" ]
[ ! -s "$FAKE_DOCKER_LOG" ]

reset_case
DATABASE_URL_EXPLICIT=true
DATABASE_URL="postgres://synthetic:synthetic@127.0.0.1:60003/synthetic"
integration_postgres_configure
[ "$DATABASE_URL_RUST" = "$DATABASE_URL" ]
[ ! -s "$FAKE_DOCKER_LOG" ]

reset_case
DATABASE_URL_EXPLICIT=true
if integration_postgres_configure >/dev/null 2>&1; then
  echo "explicit empty DATABASE_URL was accepted" >&2
  exit 1
fi
[ ! -s "$FAKE_DOCKER_LOG" ]

reset_case
mkdir -p "$TMP/no-tools" "$TMP/docker-only"
ln -s "$TMP/docker" "$TMP/docker-only/docker"
if missing_docker_output="$(PATH="$TMP/no-tools" integration_postgres_configure 2>&1)"; then
  echo "missing Docker was accepted for managed local PostgreSQL" >&2
  exit 1
fi
grep -Fq 'local integration verification requires Docker or explicit DATABASE_URL and DATABASE_URL_RUST' \
  <<<"$missing_docker_output"
[ ! -s "$FAKE_DOCKER_LOG" ]

reset_case
if missing_psql_output="$(PATH="$TMP/docker-only" integration_postgres_configure 2>&1)"; then
  echo "missing psql was accepted for managed local PostgreSQL" >&2
  exit 1
fi
grep -Fq 'local integration verification requires psql' \
  <<<"$missing_psql_output"
[ ! -s "$FAKE_DOCKER_LOG" ]

cat > "$TMP/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_CARGO_LOG"
EOF
chmod +x "$TMP/cargo"
mkdir -p "$TMP/target/ci"
cat > "$TMP/target/ci/codewire-db-migrate" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
EOF
chmod +x "$TMP/target/ci/codewire-db-migrate"
FAKE_CARGO_LOG="$TMP/cargo.log"
export FAKE_CARGO_LOG
: > "$FAKE_CARGO_LOG"
if invalid_network_output="$(
  CARGO_TARGET_DIR="$TMP/target" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$TMP/target" \
    RUN_DIR="$TMP/invalid-network" \
    INTEGRATION_DOCKER_NETWORK='invalid/network' \
    DATABASE_URL='postgres://synthetic:synthetic@127.0.0.1:60003/synthetic' \
    DATABASE_URL_RUST='postgres://synthetic:synthetic@127.0.0.1:60003/synthetic' \
    VERIFICATION_SELECTION='|valid:v3|service_nats|complete|' \
    "$ROOT/scripts/ci/verify/run-integration-verification.sh" services-runtime 2>&1
)"; then
  echo "invalid integration Docker network was accepted" >&2
  exit 1
fi
grep -Fq 'invalid integration Docker network or NATS alias' \
  <<<"$invalid_network_output"

if missing_scope_output="$(
  CARGO_TARGET_DIR="$TMP/target" \
    CODEWIRE_CARGO_CI_TARGET_DIR="$TMP/target" \
    RUN_DIR="$TMP/missing-service-scope" \
    DATABASE_URL='postgres://synthetic:synthetic@127.0.0.1:60003/synthetic' \
    DATABASE_URL_RUST='postgres://synthetic:synthetic@127.0.0.1:60003/synthetic' \
    VERIFICATION_SELECTION='|valid:v3|service_integration|complete|' \
    "$ROOT/scripts/ci/verify/run-integration-verification.sh" services-control 2>&1
)"; then
  echo "service integration without a service scope was accepted" >&2
  exit 1
fi
grep -Fq 'service integration selected without a service scope' \
  <<<"$missing_scope_output"
grep -Fq -- '--locked --profile ci -p codewire-server-core --bin codewire-db-migrate' \
  "$FAKE_CARGO_LOG"


# The database mode end to end, with a fake Cargo. No suite or count is kept
# here: each suite lists its tests first and must pass that many
# (counted_suite), and every database test must be in exactly one listing
# (database-test-coverage.py). The cases below prove the runner does both, and
# keep its lanes, their databases and their scheduling.
python3 - "$ROOT" "$TMP" <<'PYTHON'
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

root, temporary = map(Path, sys.argv[1:])
# In the order of DATABASE_BUILD_BATCHES: one after another here, in one
# folder; the build runner's batches at once are checked below.
batches = [
    ['test', '-p', 'codewire-server-core', '--lib', '--test', 'session_auth',
     '--test', 'org_deletion_lifecycle', '--test', 'oauth_bearer_auth', '--no-run'],
    ['test', '-p', 'codewire-mesh', '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-orchestration', '--lib', '--test', 'access_profiles',
     '--test', 'credentials', '--test', 'environment_external_cleanup', '--test', 'environment_sources', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-service', '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform',
     '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features',
     'platform,ssh-agent', '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'storage',
     '--test', 'profiles', '--test', 'refresh', '--test', 'authority', '--test', 'owner_sources', '--no-run'],
    ['test', '-p', 'codewire-billing', '--lib', '--no-run'],
]
lane_order = ['core', 'credential-mutations', 'credential-service', 'broker-admission', 'broker-checked',
              'broker-decisions', 'broker-refresh', 'orchestration', 'orchestration-journals',
              'orchestration-workspaces']
# The fakes are shared; each case traces into its own folder, so the cases
# below run side by side and are checked in order afterwards.
tools = temporary / 'database-tools'
tools.mkdir()
cases_root = temporary / 'database-cases'
cases_root.mkdir()
# Bash, not Python: the cases start it about two thousand times, and an
# interpreter start per call was most of this test's time. A suite is its
# arguments; its listing names three tests of its own (plus an ignored one a
# run without --ignored leaves out), and a run passes them. DB_TRACE_FAILURE
# KIND:TEXT changes the suites whose arguments contain TEXT: empty lists none,
# count passes one fewer than listed, skip reports a missing database, test
# fails; compile:PACKAGE fails that package's build.
cargo = tools / 'cargo'
cargo.write_text(r'''#!/usr/bin/env bash
set -euo pipefail
work="${DB_TRACE_ROOT:?}" failure="${DB_TRACE_FAILURE?}"
# Appends one JSON string, or null for an unset variable, to the record.
add() {
  local value="${1//\\/\\\\}"
  value="${value//\"/\\\"}"
  record+="\"$value\""
}
add_variable() {
  if [ -n "${!1+set}" ]; then add "${!1}"; else record+=null; fi
}
record='{"args": [' separator=''
for arg in "$@"; do
  record+="$separator"
  add "$arg"
  separator=', '
done
record+='], "target": '
add "${CARGO_TARGET_DIR:?}"
record+=', "test_database": '
add_variable TEST_DATABASE_URL
record+=', "database": '
add_variable DATABASE_URL
record+=', "threads": '
add_variable RUST_TEST_THREADS
printf '%s}\n' "$record" >> "$work/trace.jsonl"
if [ "$1" = build ]; then
  target="$CARGO_TARGET_DIR/ci/codewire-db-migrate"
  mkdir -p "${target%/*}"
  # Lanes migrate at once: replace the runner whole, never write one that runs.
  printf '#!/bin/sh\nexit 0\n' > "$target.$$"
  chmod 755 "$target.$$"
  mv -f "$target.$$" "$target"
  exit 0
fi
for arg in "$@"; do
  [ "$arg" = --no-run ] || continue
  package='' previous=''
  for arg in "$@"; do
    if [ "$previous" = -p ]; then package="$arg"; break; fi
    previous="$arg"
  done
  [ "$failure" != "compile:${package:?}" ] || exit 42
  echo 'Finished compiling synthetic database harnesses'
  exit 0
done
args=("$@") listing='' kind="${failure%%:*}" text="${failure#*:}"
if [ "${args[-1]}" = --list ]; then
  listing=all
  unset 'args[-1]'
elif [ "${args[-1]}" = --ignored ] && [ "${args[-2]}" = --list ]; then
  listing=ignored
  unset "args[${#args[@]}-1]" "args[${#args[@]}-2]"
fi
key="${args[*]}"
suite="fixture::s$(printf '%s' "$key" | sha256sum | cut -c1-12)"
selected=false
[ -z "$text" ] || [[ "$key" != *"$text"* ]] || selected=true
if [ -n "$listing" ]; then
  if [ "$listing" = all ]; then
    [ "$kind:$selected" = empty:true ] || printf '%s::case_%s: test\n' "$suite" 1 "$suite" 2 "$suite" 3
  fi
  if [[ " $key " != *' --ignored '* ]]; then
    printf '%s::ignored_case: test\n' "$suite"
  fi
  printf '\n3 tests, 0 benchmarks\n'
  exit 0
fi
# Count the database executions running at once across lanes: each marks
# itself active and records how many are, held for DB_TRACE_HOLD seconds.
: > "$work/active/$$"
active=("$work/active/"*)
printf '%s\n' "${#active[@]}" >> "$work/running"
# With DB_TRACE_BARRIER=N, each lane's first execution (its database's first)
# waits until N executions are active, for at most 30 s, so lanes the
# scheduler runs at once are all seen at once, however slowly they start.
if [ -n "${DB_TRACE_BARRIER:-}" ]; then
  url="${TEST_DATABASE_URL:-${DATABASE_URL:-}}"
  if mkdir "$work/first-$(printf '%s' "$url" | sha256sum | cut -c1-16)" 2>/dev/null; then
    for _ in $(seq 1 300); do
      active=("$work/active/"*)
      [ "${#active[@]}" -lt "$DB_TRACE_BARRIER" ] || break
      sleep 0.1
    done
    active=("$work/active/"*)
    printf '%s\n' "${#active[@]}" >> "$work/running"
  fi
fi
[ -z "${DB_TRACE_HOLD:-}" ] || sleep "$DB_TRACE_HOLD"
rm -f -- "$work/active/$$"
count=3
if [ "$selected" = true ]; then
  case "$kind" in
    test) exit 43 ;;
    skip) echo 'DATABASE_URL unset' ;;
    count) count=2 ;;
  esac
fi
# A test that runs a child test process prints the child's result first
# (the credential mutation matrix does); the suite's own result is the last.
echo 'test result: ok. 1 passed; 0 failed; 0 ignored (a child test process)'
echo "test result: ok. $count passed; 0 failed; 0 ignored"
''')
cargo.chmod(0o755)
(tools / 'psql').write_text('#!/bin/sh\nexit 0\n')
(tools / 'psql').chmod(0o755)
# DB_TRACE_RM_DELAY slows each lane's PostgreSQL removal, which the scheduler
# runs between lanes, so other lanes end while it is busy.
(tools / 'docker').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>"$DB_TRACE_ROOT/docker.log"\n'
                              '[ "$1" != rm ] || sleep "${DB_TRACE_RM_DELAY:-0}"\nexit 0\n')
(tools / 'docker').chmod(0o755)
# The sources the coverage check reads: none with a database test, or one
# with a database test no fake listing names.
no_database_tests = temporary / 'sources-none'
(no_database_tests / 'crates').mkdir(parents=True)
unwired = temporary / 'sources-unwired'
(unwired / 'crates' / 'fixture' / 'src').mkdir(parents=True)
(unwired / 'crates' / 'fixture' / 'Cargo.toml').write_text('[package]\nname = "codewire-fixture"\nversion = "0.0.0"\n')
(unwired / 'crates' / 'fixture' / 'src' / 'lib.rs').write_text(
    '#[tokio::test]\n#[ignore = "requires isolated TEST_DATABASE_URL"]\nasync fn db_nothing_runs() {}\n')

lock_dir = temporary / 'lane-locks'

def case_environment(failure='', extra=None):
    work = Path(tempfile.mkdtemp(dir=cases_root))
    (work / 'active').mkdir()
    return {
        'CODEWIRE_INTEGRATION_LOCK_DIR': str(lock_dir),
        'DATABASE_TEST_SOURCE_ROOT': str(no_database_tests), **(extra or {}),
        'PATH': str(tools) + os.pathsep + os.environ['PATH'],
        'CODEWIRE_LOCAL_RUST_CACHE': 'off',
        'CARGO_TARGET_DIR': str(work / 'debug-target'),
        'CODEWIRE_CARGO_CI_TARGET_DIR': str(work / 'ci-target'),
        'RUN_DIR': str(work / 'run'),
        'DATABASE_URL': 'postgres://synthetic:synthetic@127.0.0.1:60003/sql-client',
        'DATABASE_URL_RUST': 'postgres://synthetic:synthetic@127.0.0.1:60003/rust-client',
        'DB_TRACE_ROOT': str(work), 'DB_TRACE_FAILURE': failure,
    }

def case_file(environment, name):
    return Path(environment['DB_TRACE_ROOT']) / name

def peak_running(environment):
    return max(map(int, case_file(environment, 'running').read_text().split()))

def run_case(failure='', extra=None):
    environment = case_environment(failure, extra)
    result = subprocess.run(['bash', str(root / 'scripts/ci/verify/run-integration-verification.sh'),
                             'database'], env=environment, cwd=root, capture_output=True, text=True)
    commands = [json.loads(line) for line in case_file(environment, 'trace.jsonl').read_text().splitlines()]
    return result, commands, environment

def is_listing(command):
    return command['args'][-1] == '--list' or command['args'][-2:] == ['--list', '--ignored']

def executions_of(commands):
    return [command for command in commands if command['args'][0] == 'test'
            and '--no-run' not in command['args'] and not is_listing(command)]

# The integration lane lock (#2755). Another run holds the 62000 range:
# this hermetic fixture sets no VERIFICATION_PORT_BASE, so it neither takes
# the lock nor waits on it; a real lane, which is given the base, waits for it.
# It mostly waits, so it runs beside the other cases from the start.
def lane_lock_case():
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    held = os.open(lock_dir / 'ports-62000.lock', os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX)
    (lock_dir / 'ports-62000.lock.holder').write_text('database in /worktrees/other pid=1\n')
    fixture, _, _ = run_case()
    assert fixture.returncode == 0 and '[product-integration] green' in fixture.stdout, fixture.stdout + fixture.stderr
    assert 'integration lane lock' not in fixture.stdout
    lane_environment = case_environment(extra={'VERIFICATION_PORT_BASE': '62000'})
    lane = subprocess.Popen(['bash', str(root / 'scripts/ci/verify/run-integration-verification.sh'), 'database'],
                            env=lane_environment, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    waiting = lane.stdout.readline()
    while waiting and 'integration lane lock' not in waiting:
        waiting = lane.stdout.readline()
    assert 'waiting for the integration lane lock' in waiting and 'held by database in /worktrees/other' in waiting, waiting
    time.sleep(2)
    assert lane.poll() is None and not case_file(lane_environment, 'trace.jsonl').exists(), 'a real lane ran while another held its range'
    os.close(held)
    rest, _ = lane.communicate(timeout=300)
    assert lane.returncode == 0 and '[product-integration] green' in rest, rest
    assert 'acquired' in rest
    assert f'{root} pid=' in (lock_dir / 'ports-62000.lock.holder').read_text()

# Side by side within the job's CPU share (cpu-share.sh), or this host's CPUs.
share = os.environ.get('CODEWIRE_CI_CPU_SHARE', '')
width = int(share) if share.isdigit() and int(share) > 0 else len(os.sched_getaffinity(0))
pool = ThreadPoolExecutor(max_workers=max(1, min(8, width)))
lane_lock = ThreadPoolExecutor(max_workers=1).submit(lane_lock_case)
# With CI's job network each lane after the first gets its own PostgreSQL on
# that network, and the lanes run side by side. A database execution holds
# its place briefly there, so lanes that run at once overlap in the count.
network = {'INTEGRATION_DOCKER_NETWORK': 'codewire-fixture-net', 'DB_TRACE_HOLD': '0.02'}
# Suites picked by their arguments: the first suite of the first lane, two
# that run without --ignored and report a skip, and the journal matrix.
first_suite = 'codewire-server-core --lib migrate::'
failures = ['compile:codewire-server-core', 'compile:codewire-platform-credentials',
            'compile:codewire-orchestration', 'test:' + first_suite,
            'test:billing_teardown::tests::db_',
            'skip:--test session_auth', 'skip:--test org_deletion_lifecycle',
            'skip:--test environment_external_cleanup']
cases = {
    'explicit': pool.submit(run_case),
    'lanes': pool.submit(run_case, extra=network),
    # Every lane ends at once while the scheduler is still removing the first
    # one's PostgreSQL: the scheduler must hear each end, never wait on a
    # lane the shell already reaped (Bash 5.2's wait -n -p refused that).
    'instant': pool.submit(run_case, extra={'INTEGRATION_DOCKER_NETWORK': 'codewire-fixture-net',
                                            'DB_TRACE_RM_DELAY': '0.3'}),
    'shared': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '12'}),
    'heavy': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '16', 'DB_TRACE_BARRIER': '10'}),
    'wide': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '40'}),
    'small': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '2'}),
    'serial': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '12', 'CODEWIRE_CI_DATABASE_LANES_AT_ONCE': '1'}),
    'invalid': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '12', 'CODEWIRE_CI_DATABASE_LANES_AT_ONCE': 'two'}),
    'too many': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '12', 'CODEWIRE_CI_DATABASE_LANES_AT_ONCE': '11'}),
    'malformed': pool.submit(run_case, extra=network | {'CODEWIRE_CI_CPU_SHARE': '12cores'}),
    'failed lane': pool.submit(run_case, 'test:platform::tests:: -- --ignored --skip', extra=network),
    'journal': pool.submit(run_case, 'test:platform_agents::journal::database_tests::db_'),
    # What the pinned counts caught, and what they missed. A suite that
    # passes fewer tests than its filter lists (a dropped test), in a lane
    # and against the one explicit database:
    'dropped': pool.submit(run_case, 'count:api::cw_runtime::owner::database_tests::'),
    'dropped in a lane': pool.submit(run_case, 'count:platform::tests::checked::', extra=network),
    # a filter that matches nothing;
    'empty': pool.submit(run_case, 'empty:--test owner_sources'),
    # and a database test that no suite lists, which no count could see:
    'unwired': pool.submit(run_case, extra={'DATABASE_TEST_SOURCE_ROOT': str(unwired)}),
    **{failure: pool.submit(run_case, failure) for failure in failures},
}

result, commands, environment = cases['explicit'].result()
assert result.returncode == 0, result.stdout + result.stderr
assert '[product-integration] green' in result.stdout
actual_batches = [command for command in commands if '--no-run' in command['args']]
assert [command['args'] for command in actual_batches] == batches
assert all(command['target'] == environment['CARGO_TARGET_DIR'] and
           command['test_database'] == environment['DATABASE_URL_RUST'] for command in actual_batches)
executions = executions_of(commands)
listings = [command for command in commands if command['args'][-1] == '--list']
# Every suite lists its tests before any runs, after every harness compiled,
# and then runs once; the coverage check found no database test unlisted.
assert executions and len(executions) == len(listings), (len(executions), len(listings))
assert [command['args'][:-1] for command in listings] == [command['args'] for command in executions]
assert commands.index(actual_batches[-1]) < commands.index(listings[0]), 'a suite listed before every harness compiled'
assert commands.index(listings[-1]) < commands.index(executions[0]), 'a suite ran before every suite listed'
assert 'each of 0 database tests runs in exactly one of ' in result.stdout, result.stdout
# The migration runner builds before any suite runs; every suite runs in the
# test profile its batch built, against the explicit database.
migration = next(command for command in commands if command['args'][0] == 'build')
assert migration['args'] == ['build', '--locked', '--profile', 'ci', '-p', 'codewire-server-core', '--bin', 'codewire-db-migrate']
assert migration['target'] == environment['CODEWIRE_CARGO_CI_TARGET_DIR']
assert commands.index(migration) < commands.index(executions[0])
for execution in executions:
    assert execution['target'] == environment['CARGO_TARGET_DIR'], execution['args']
    assert environment['DATABASE_URL_RUST'] in (execution['test_database'], execution['database']), execution['args']
# A suite that runs without --ignored lists the ignored tests apart.
plain = [command for command in executions if '--ignored' not in command['args']]
assert plain and all(command['args'] + ['--list', '--ignored'] in [c['args'] for c in commands] for command in plain)
for batch in actual_batches:
    package = batch['args'][batch['args'].index('-p') + 1]
    first_test = next(command for command in executions if package in command['args'])
    assert commands.index(batch) < commands.index(first_test)
# Each suite's listing is kept for the coverage check: three tests a suite.
listed = sorted((Path(environment['RUN_DIR']) / 'suite-listings').glob('*.list'))
assert len(listed) == len(executions) and all(len(path.read_text().splitlines()) == 3 for path in listed)
# With CI's job network each lane after the first gets its own PostgreSQL on
# that network, migrated before the lanes start side by side. Each lane runs
# its own suites in the order the listing pass ran them, against its own
# database, and every lane container is removed afterwards, also when a lane
# fails.
def lane_url(lane):
    return ('postgres://codewire:codewire@codewire-integration-postgres-' + lane + ':5432/codewire'
            if lane != 'core' else environment['DATABASE_URL_RUST'])
def lane_runs(commands):
    return {lane: [command['args'] for command in executions_of(commands)
                   if (command['test_database'] or command['database']) == lane_url(lane)]
            for lane in lane_order}
def check_lanes(commands, case, complete=True):
    runs = lane_runs(commands)
    order = [command['args'] for command in executions]
    for lane in lane_order:
        assert runs[lane] or not complete, lane
        assert [order.index(args) for args in runs[lane]] == sorted(order.index(args) for args in runs[lane]), lane
    if complete:
        assert sorted(args for lane in lane_order for args in runs[lane]) == sorted(order), 'a suite ran in no lane or twice'
    migrations = [command for command in commands if command['args'][0] == 'build']
    assert len(migrations) == len(lane_order), migrations
    started = case_file(case, 'docker.log').read_text().splitlines()
    for lane in lane_order[1:]:
        name = 'codewire-product-postgres-local-'
        runs = [line for line in started if line.startswith('run -d --name ' + name) and line.split()[3].endswith('-lane-' + lane)]
        assert len(runs) == 1 and '--network codewire-fixture-net --network-alias codewire-integration-postgres-' + lane in runs[0], started
        assert any(line.startswith('rm -f ') and line.endswith('-lane-' + lane) for line in started[started.index(runs[0]):]), started
        # A finished lane's PostgreSQL is removed then, not only at the end.
        assert sum(line == 'rm -f ' + runs[0].split()[3] for line in started) >= 3, (lane, started)
lanes, lane_commands, lanes_environment = cases['lanes'].result()
assert lanes.returncode == 0 and '[product-integration] green' in lanes.stdout, lanes.stdout + lanes.stderr
# Without a CPU share (a cloud runner, a workstation) all ten lanes run at
# once, longest first, with the test threads their commands name.
lane_start_order = ('credential-mutations orchestration-journals broker-admission broker-checked broker-decisions '
                    'credential-service orchestration core broker-refresh orchestration-workspaces')
assert sorted(lane_start_order.split()) == sorted(lane_order)
assert 'database lanes: 10 at a time: ' + lane_start_order in lanes.stdout, lanes.stdout
assert all(command['threads'] is None for command in lane_commands), 'a lane set test threads without a CPU share'
for lane in lane_order:
    assert f'=== database lane {lane} ===' in lanes.stdout, lane
    assert f'CODEWIRE_CI_PHASE name=database-lane-{lane} seconds=' in lanes.stdout, lane
check_lanes(lane_commands, lanes_environment)
suites_per_lane = {lane: len(runs) for lane, runs in lane_runs(lane_commands).items()}
instant, instant_commands, instant_environment = cases['instant'].result()
assert instant.returncode == 0 and '[product-integration] green' in instant.stdout, instant.stdout + instant.stderr
for lane in lane_order:
    assert f'=== database lane {lane} ===' in instant.stdout, lane
check_lanes(instant_commands, instant_environment)
# On a metal guest, one lane per core of the share runs at once, at most the
# memory bound of ten, and each lane's tests get its part of the share, at
# least two threads; every lane still runs every suite. A share of 12 runs all
# ten at once.
shared, shared_commands, shared_environment = cases['shared'].result()
assert shared.returncode == 0 and '[product-integration] green' in shared.stdout, shared.stdout + shared.stderr
assert 'database lanes: 10 at a time, 2 test threads each: ' + lane_start_order in shared.stdout, shared.stdout
check_lanes(shared_commands, shared_environment)
assert peak_running(shared_environment) <= 10, 'more than ten lanes ran at once'
lane_executions = executions_of(shared_commands)
assert lane_executions and all(command['threads'] == '2' for command in lane_executions), lane_executions[:2]
for lane in lane_order:
    assert f'CODEWIRE_CI_PHASE name=database-lane-{lane} seconds=' in shared.stdout, lane
# A heavy guest's share of 16 runs all ten at once, as does a share of 40,
# with more threads each; a share of 2 runs two at a time, with two threads.
heavy, heavy_commands, heavy_environment = cases['heavy'].result()
assert heavy.returncode == 0 and 'database lanes: 10 at a time, 2 test threads each: ' in heavy.stdout, heavy.stdout
# Each lane's first suite waits for the others (DB_TRACE_BARRIER): all ten
# ran at once.
assert peak_running(heavy_environment) == 10, 'the heavy share did not run all ten lanes at once'
check_lanes(heavy_commands, heavy_environment)
wide, _, wide_environment = cases['wide'].result()
assert wide.returncode == 0 and 'database lanes: 10 at a time, 4 test threads each: ' in wide.stdout, wide.stdout
assert peak_running(wide_environment) <= 10, 'more lanes ran at once than the memory bound'
small, _, small_environment = cases['small'].result()
assert small.returncode == 0 and 'database lanes: 2 at a time, 2 test threads each: ' in small.stdout, small.stdout
assert peak_running(small_environment) <= 2, 'more than two lanes ran on a share of two'
# One at a time on request; an invalid count fails before any lane runs.
serial, serial_commands, serial_environment = cases['serial'].result()
assert serial.returncode == 0 and 'database lanes: 1 at a time, 12 test threads each' in serial.stdout, serial.stdout
assert peak_running(serial_environment) == 1, 'lanes overlapped at one at a time'
check_lanes(serial_commands, serial_environment)
invalid, invalid_commands, _ = cases['invalid'].result()
assert invalid.returncode != 0 and 'CODEWIRE_CI_DATABASE_LANES_AT_ONCE must be 1 to 10' in invalid.stdout + invalid.stderr
assert not executions_of(invalid_commands)
too_many, too_many_commands, _ = cases['too many'].result()
assert too_many.returncode != 0 and 'CODEWIRE_CI_DATABASE_LANES_AT_ONCE must be 1 to 10, not 11' in too_many.stdout + too_many.stderr
assert not executions_of(too_many_commands)
# A malformed share is ignored with a warning, never read as a smaller one.
malformed, _, _ = cases['malformed'].result()
assert malformed.returncode == 0 and 'database lanes: 10 at a time:' in malformed.stdout, malformed.stdout
assert 'ignoring CODEWIRE_CI_CPU_SHARE' in malformed.stdout + malformed.stderr
failed_lane, failed_commands, failed_environment = cases['failed lane'].result()
assert failed_lane.returncode != 0 and '[product-integration] green' not in failed_lane.stdout
assert '::error::database lane broker-admission failed' in failed_lane.stdout, failed_lane.stdout
check_lanes(failed_commands, failed_environment, complete=False)
for lane, runs in lane_runs(failed_commands).items():
    if lane != 'broker-admission':
        assert len(runs) == suites_per_lane[lane], lane
# A dropped test fails its suite, against one database and in a lane.
dropped, _, _ = cases['dropped'].result()
assert dropped.returncode != 0 and '[product-integration] green' not in dropped.stdout
assert '::error::platform cw runtime journal matrix passed 2 of the 3 tests its filter lists' in dropped.stdout, dropped.stdout
dropped, _, _ = cases['dropped in a lane'].result()
assert dropped.returncode != 0 and '::error::database lane broker-checked failed' in dropped.stdout, dropped.stdout
assert 'platform broker checked lease matrix passed 2 of the 3 tests its filter lists' in dropped.stdout, dropped.stdout
# A filter that matches nothing fails before any suite runs.
empty, empty_commands, _ = cases['empty'].result()
assert empty.returncode != 0 and '::error::platform owner-source authority matrix selects no test' in empty.stdout, empty.stdout
assert not executions_of(empty_commands)
# A database test no suite lists fails the run before any suite runs.
unwired_run, unwired_commands, _ = cases['unwired'].result()
assert unwired_run.returncode != 0 and '[product-integration] green' not in unwired_run.stdout
assert 'codewire-fixture database test db_nothing_runs (crates/fixture/src/lib.rs:2) runs in no database lane' in unwired_run.stderr, unwired_run.stderr
assert not executions_of(unwired_commands)
failed, trace, _ = cases['journal'].result()
assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout
assert 'api::platform_agents::journal::database_tests::db_' in trace[-1]['args']
for failure in failures:
    failed, trace, _ = cases[failure].result()
    assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout, failure
    if failure.startswith('compile:'):
        assert '--no-run' in trace[-1]['args'], failure
    if failure.startswith('skip:'):
        assert 'skipped: a test found no database' in failed.stdout, failure
lane_lock.result()
pool.shutdown()

print(f'Database lanes: {len(cases) + 1} trace/failure cases over {len(executions)} counted suites')
PYTHON

# The coverage check's own fixtures: an unwired test, a test two suites run,
# and tests written by a macro.
python3 -B "$ROOT/scripts/ci/verify/database-test-coverage.py" --self-test

# Every integration PostgreSQL gets the same server settings (#3198) and the
# same digest-pinned image: the ones this file starts above, ci.yaml's "Start
# integration Postgres" steps, and the Kind PostgreSQL. In CI each job's
# "Make the fixture images present" step makes that image present first, from
# the guest's store, its warm cache or the pin (load-fixture-images.sh), and
# the job's PostgreSQL runs what it named.
[ "${INTEGRATION_POSTGRES_SERVER_ARGS[*]}" = '-c max_locks_per_transaction=1024' ]
[[ "$INTEGRATION_POSTGRES_PINNED_IMAGE" =~ ^docker\.io/library/postgres:17-alpine@sha256:[0-9a-f]{64}$ ]]
grep -qxF "  KIND_POSTGRES_IMAGE='$INTEGRATION_POSTGRES_PINNED_IMAGE'" "$ROOT/scripts/ci/verify/kind/common.sh" ||
  { echo 'the integration PostgreSQL image is not the Kind PostgreSQL pin' >&2; exit 1; }
python3 - "$ROOT/.gitea/workflows/ci.yaml" "${INTEGRATION_POSTGRES_SERVER_ARGS[*]}" <<'PYTHON'
import re
import sys

workflow, server_args = open(sys.argv[1], encoding="utf-8").read(), sys.argv[2]
steps = re.findall(r"- name: Start integration Postgres\n(.*?)(?=\n      - name: )", workflow, re.S)
assert len(steps) >= 3, f"expected the database and two service Postgres steps, found {len(steps)}"
for step in steps:
    run = step.replace("\\\n", " ")
    command = re.search(r"docker run -d [^\n]*", run)
    assert command, "a Postgres step has no docker run"
    assert " ".join(command.group(0).split()).endswith(f' "${{INTEGRATION_POSTGRES_IMAGE:?}}" {server_args}'), command.group(0)
    # Each job's PostgreSQL is named and labelled for its run, job and
    # attempt, so a rerun attempt never removes a still-running one's.
    assert 'container="codewire-integration-${GITHUB_RUN_ID:?}-${GITHUB_JOB:?}-a${GITHUB_RUN_ATTEMPT:?}"' in run, step
    for label in ('run=${GITHUB_RUN_ID}', 'attempt=${GITHUB_RUN_ATTEMPT}', 'job=${GITHUB_JOB}'):
        assert f'--label "codewire.ci.{label}"' in command.group(0), (label, command.group(0))
# Each job makes its fixture images present right before its PostgreSQL
# starts, under the same condition, with the guest's warm cache.
loads = re.findall(r"      - name: Make the fixture images present\n        if: ([^\n]*)\n"
                   r"        env:\n          CODEWIRE_TOOL_CACHE: [^\n]*/target/ci-rust-cargo-home/codewire-tools\n"
                   r"        run: scripts/ci/setup/load-fixture-images.sh ([a-z ]+)\n\n"
                   r"      - name: Start integration Postgres\n        if: ([^\n]*)\n", workflow)
assert len(loads) == len(steps), f"{len(steps)} Postgres steps but {len(loads)} fixture image steps before them"
assert all(load == start for load, _, start in loads), loads
assert sorted(images for _, images, _ in loads) == ["postgres", "postgres", "postgres nats"], loads
PYTHON

# The archive extractor links each archive's non-test binaries at their build
# path, in the target folder the archive records (each build-once leg has its
# own; main run 23071: idp's rewrap_cli started codewire-idp from
# targets/services_control), and skips the libraries nextest also lists (main
# run 22655: boringtun's static library in the credential service's
# enrollment archive); any other unexpected path, or a folder outside the
# build tree, still fails.
extract_case() {
  local entries="$1" case_dir="$TMP/extract-$2" target="${3:-targets/archive}"
  mkdir -p "$case_dir/archives-in" "$case_dir/root" "$case_dir/bin"
  : > "$case_dir/archives-in/codewire-credential-service--features-enrollment.tar.zst"
  printf '%s' "$entries" > "$case_dir/entries.json"
  cat > "$case_dir/bin/nextest" <<'NEXTEST'
#!/usr/bin/env bash
# Writes the binaries metadata the archive would carry into --extract-to.
while [ "$#" -gt 0 ]; do
  [ "$1" = --extract-to ] && { mkdir -p "$2/target/nextest"; out="$2"; shift; }
  shift
done
printf '{"rust-build-meta":{"target-directory":"%s","non-test-binaries":{"codewire-credential-service":%s}}}' \
  "$EXTRACT_TARGET" "$(cat "$EXTRACT_ENTRIES")" > "$out/target/nextest/binaries-metadata.json"
NEXTEST
  chmod +x "$case_dir/bin/nextest"
  # The variables and log() are the eval'd extractor's.
  # shellcheck disable=SC2034,SC2329
  (
    set -euo pipefail
    log() { :; }
    eval "$(awk '/^extract_archives\(\) \{/,/^\}/' "$ROOT/scripts/ci/verify/run-integration-verification.sh")"
    ROOT="$case_dir/root" RUN_DIR="$case_dir/run" DATABASE_ARCHIVE_BUILD_ROOT="$case_dir/build" \
      RUST_TEST_NEXTEST="$case_dir/bin/nextest" EXTRACT_ENTRIES="$case_dir/entries.json"
    EXTRACT_TARGET="$case_dir/build/$target"
    case "$target" in /*) EXTRACT_TARGET="$target" ;; esac
    export EXTRACT_ENTRIES EXTRACT_TARGET
    extract_archives "$case_dir/archives-in"
  ) > "$case_dir/out.log" 2>&1
}
extract_case '[{"name":"codewire-credential-service","path":"debug/codewire-credential-service"},{"name":"boringtun","path":"debug/deps/libboringtun-963df387f682c248.a"},{"name":"boringtun","path":"debug/deps/libboringtun-963df387f682c248.so"}]' libraries ||
  { cat "$TMP/extract-libraries/out.log" >&2; echo 'the extractor refused a library nextest lists' >&2; exit 1; }
[ -L "$TMP/extract-libraries/build/targets/archive/debug/codewire-credential-service" ] ||
  { echo 'the extractor did not link the archive binary' >&2; exit 1; }
[ -d "$TMP/extract-libraries/build/src" ] ||
  { echo 'the extractor did not copy the checkout into the build folder (main run 23164)' >&2; exit 1; }
[ ! -e "$TMP/extract-libraries/build/targets/archive/debug/deps" ] ||
  { echo 'the extractor linked a library' >&2; exit 1; }
if extract_case '[{"name":"x","path":"debug/../escape"}]' escape; then
  echo 'the extractor accepted a path outside its folder' >&2; exit 1
fi
grep -q 'names an unexpected binary path: debug/../escape' "$TMP/extract-escape/out.log" ||
  { echo 'the extractor gave no reason for the refused path' >&2; exit 1; }
if extract_case '[{"name":"x","path":"debug/deps/notalib-1.a"}]' nonlib; then
  echo 'the extractor skipped an unexpected non-library path' >&2; exit 1
fi
extract_case '[{"name":"codewire-idp","path":"debug/codewire-idp"}]' leg targets/services_control ||
  { cat "$TMP/extract-leg/out.log" >&2; echo 'the extractor refused a leg target folder' >&2; exit 1; }
[ "$(readlink "$TMP/extract-leg/build/targets/services_control/debug/codewire-idp")" = \
  "$TMP/extract-leg/run/archives/codewire-credential-service--features-enrollment/target/debug/codewire-idp" ] ||
  { echo 'the extractor did not link the binary in its leg target folder' >&2; exit 1; }
[ -d "$TMP/extract-leg/build/targets/services_control/tmp" ] ||
  { echo 'the extractor made no CARGO_TARGET_TMPDIR in the leg target folder' >&2; exit 1; }
[ ! -e "$TMP/extract-leg/build/targets/archive" ] ||
  { echo 'the extractor linked into a folder the archive was not built in' >&2; exit 1; }
# A leg's build batch has its own folder inside the leg's (compile_batches).
extract_case '[{"name":"codewire-orchestration","path":"debug/codewire-orchestration"}]' batch \
  targets/database/batch-orchestration ||
  { cat "$TMP/extract-batch/out.log" >&2; echo 'the extractor refused a build batch folder' >&2; exit 1; }
[ -L "$TMP/extract-batch/build/targets/database/batch-orchestration/debug/codewire-orchestration" ] &&
  [ -d "$TMP/extract-batch/build/targets/database/batch-orchestration/tmp" ] ||
  { echo 'the extractor did not link the binary in its build batch folder' >&2; exit 1; }
if extract_case '[{"name":"codewire-idp","path":"debug/codewire-idp"}]' nested targets/database/debug; then
  echo 'the extractor accepted a nested folder that is no build batch' >&2; exit 1
fi
if extract_case '[{"name":"codewire-idp","path":"debug/codewire-idp"}]' outside /elsewhere/target; then
  echo 'the extractor accepted a target folder outside the build tree' >&2; exit 1
fi
grep -q 'was built in /elsewhere/target, not a target folder of' "$TMP/extract-outside/out.log" ||
  { echo 'the extractor gave no reason for the refused target folder' >&2; exit 1; }

# The control plane's suites run in lanes when each can have its own
# PostgreSQL: the selected lanes all at once, each against its own database
# (the first against the job's own), each keeping its suites in order, and
# every lane runs to its end when another fails. The scheduler and the lane
# databases are the runner's own; the suites are traced stand-ins.
service_lanes_case() {
  local name="$1" selection="$2" failing="${3:-}" runner="$ROOT/scripts/ci/verify/run-integration-verification.sh"
  local case_dir="$TMP/service-lanes-$name" fn_name
  mkdir -p "$case_dir/active"
  # The variables and functions are the eval'd runner's.
  # shellcheck disable=SC2034,SC2329
  (
    set -euo pipefail
    eval "$(awk '/^readonly SERVICE_CONTROL_LANES=\(/,/^\)/' "$runner")"
    for fn_name in log selected start_lane_databases run_lanes run_service_lane \
        service_control_lanes run_service_control_lanes; do
      eval "$(awk "/^${fn_name}\\(\\) \\{/,/^\\}/" "$runner")"
    done
    reset_case
    INTEGRATION_POSTGRES_SOURCE=explicit
    INTEGRATION_DOCKER_NETWORK=codewire-fixture-net
    RUN_DIR="$case_dir/run"
    mkdir -p "$RUN_DIR"
    SELECTION="$selection"
    DATABASE_URL='postgres://codewire:codewire@codewire-integration-postgres:5432/codewire?sslmode=disable'
    DATABASE_URL_RUST='postgres://codewire:codewire@codewire-integration-postgres:5432/codewire'
    lanes_expected="$(service_control_lanes | wc -l)"
    reset_schema() { printf 'migrate %s\n' "$DATABASE_URL_RUST" >> "$case_dir/trace"; }
    # A suite records its database; a lane's first suite waits until every
    # lane is running (at most 30 s), so lanes run at once are seen at once.
    suite() {
      local active
      printf 'start %s %s\n' "$1" "$DATABASE_URL_RUST" >> "$case_dir/trace"
      : > "$case_dir/active/$1"
      if mkdir "$case_dir/first-$(printf '%s' "$DATABASE_URL_RUST" | sha256sum | cut -c1-16)" 2>/dev/null; then
        for _ in $(seq 1 300); do
          active=("$case_dir/active/"*)
          [ "${#active[@]}" -lt "$lanes_expected" ] || break
          sleep 0.1
        done
      fi
      active=("$case_dir/active/"*)
      printf '%s\n' "${#active[@]}" >> "$case_dir/running"
      rm -f -- "$case_dir/active/$1"
      [ "$1" != "$failing" ] || return 1
      printf 'end %s %s\n' "$1" "$DATABASE_URL_RUST" >> "$case_dir/trace"
    }
    run_idp_flow() { suite idp_flow; }
    run_idp_two_factor() { suite idp_two_factor; }
    run_idp_session_inventory() { suite idp_session_inventory; }
    run_idp_rewrap_cli() { suite idp_rewrap_cli; }
    run_idp_oauth_sign_in() { suite idp_oauth_sign_in; }
    run_connect_auth_matrix() { suite connect_auth; }
    run_billing() { suite billing; }
    run_billing_temporal() { suite billing_temporal; }
    run_coordinator() { suite coordinator; }
    : > "$case_dir/trace"
    run_service_control_lanes
  ) > "$case_dir/out" 2>&1
}
service_lane_url() {
  printf 'postgres://codewire:codewire@codewire-integration-postgres-%s:5432/codewire' "$1"
}
service_lane_check() {
  local case_dir="$TMP/service-lanes-$1" lane="$2" url="$3" suites="$4" expected actual
  expected="$(for suite_name in $suites; do printf 'start %s %s\nend %s %s\n' "$suite_name" "$url" "$suite_name" "$url"; done)"
  actual="$(grep -F " $url" "$case_dir/trace" | grep -v '^migrate ' || true)"
  [ "$actual" = "$expected" ] ||
    { printf 'service lane %s ran:\n%s\nnot:\n%s\n' "$lane" "$actual" "$expected" >&2; exit 1; }
  grep -qxF "=== service lane $lane ===" "$case_dir/out" ||
    { echo "service lane $lane printed no heading" >&2; exit 1; }
  grep -q "^CODEWIRE_CI_PHASE name=service-lane-$lane seconds=[0-9]* status=0$" "$case_dir/out" ||
    { echo "service lane $lane reported no phase" >&2; exit 1; }
}
full='|valid:v3|service_idp|service_coordinator|service_billing|service_connectcore|service_temporal|complete|'
service_lanes_case full "$full" ||
  { cat "$TMP/service-lanes-full/out" >&2; echo 'the control-plane lanes failed' >&2; exit 1; }
grep -qF '[product-integration] service lanes: 6 at a time: idp-two-factor idp-flow idp-sessions connect-auth billing coordinator' \
  "$TMP/service-lanes-full/out" || { cat "$TMP/service-lanes-full/out" >&2; echo 'the control-plane lanes did not all start at once' >&2; exit 1; }
[ "$(sort -n "$TMP/service-lanes-full/running" | tail -n 1)" = 6 ] ||
  { echo 'the six control-plane lanes did not run at the same time' >&2; exit 1; }
service_lane_check full idp-two-factor 'postgres://codewire:codewire@codewire-integration-postgres:5432/codewire' idp_two_factor
service_lane_check full idp-flow "$(service_lane_url idp-flow)" idp_flow
service_lane_check full idp-sessions "$(service_lane_url idp-sessions)" 'idp_session_inventory idp_rewrap_cli idp_oauth_sign_in'
service_lane_check full connect-auth "$(service_lane_url connect-auth)" connect_auth
service_lane_check full billing "$(service_lane_url billing)" 'billing billing_temporal'
service_lane_check full coordinator "$(service_lane_url coordinator)" coordinator
# Every lane after the first migrated its own PostgreSQL, which was removed
# when the lane ended.
for lane in idp-flow idp-sessions connect-auth billing coordinator; do
  grep -qxF "migrate $(service_lane_url "$lane")" "$TMP/service-lanes-full/trace" ||
    { echo "service lane $lane did not migrate its database" >&2; exit 1; }
  grep -q "^run -d --name codewire-product-postgres-[^ ]*-lane-$lane .*--network-alias codewire-integration-postgres-$lane " \
    "$TMP/docker.log" || { echo "service lane $lane got no PostgreSQL of its own" >&2; exit 1; }
  grep -q "^rm -f codewire-product-postgres-[^ ]*-lane-$lane$" "$TMP/docker.log" ||
    { echo "service lane $lane's PostgreSQL was not removed" >&2; exit 1; }
done
[ "$(grep -c '^migrate ' "$TMP/service-lanes-full/trace")" -eq 5 ] ||
  { echo 'the first control-plane lane did not use the job database' >&2; exit 1; }
# A narrow selection runs only its lanes; billing's Temporal workflow runs
# only when Temporal is selected.
service_lanes_case billing '|valid:v3|service_billing|complete|' ||
  { cat "$TMP/service-lanes-billing/out" >&2; echo 'the billing lane failed' >&2; exit 1; }
grep -qF '[product-integration] service lanes: 1 at a time: billing' "$TMP/service-lanes-billing/out" ||
  { echo 'a billing-only selection ran other lanes' >&2; exit 1; }
service_lane_check billing billing 'postgres://codewire:codewire@codewire-integration-postgres:5432/codewire' billing
! grep -q '^migrate \|-lane-' "$TMP/service-lanes-billing/trace" "$TMP/docker.log" ||
  { echo 'a single control-plane lane started a PostgreSQL of its own' >&2; exit 1; }
# A failing lane fails the plane, and every other lane still runs to its end.
if service_lanes_case failed "$full" idp_two_factor; then
  echo 'a failed control-plane lane passed' >&2; exit 1
fi
grep -qF '::error::service lane idp-two-factor failed' "$TMP/service-lanes-failed/out" ||
  { cat "$TMP/service-lanes-failed/out" >&2; echo 'the failed control-plane lane was not reported' >&2; exit 1; }
[ "$(grep -c '^end ' "$TMP/service-lanes-failed/trace")" -eq 8 ] ||
  { echo 'the other control-plane lanes did not run to their end' >&2; exit 1; }

# Building archives on the build runner (database-archives and
# services-PLANE-archives), the builds run in batches at once, each batch in
# its own target folder (compile_batches; infra#1534 lever 2). Batching
# changes only where and when each build runs: the build invocations, so
# every package, feature set and test target, are exactly those of the
# builds one after another in one folder (EXPECTED_* below, from main before
# the batches). The fake Cargo records each invocation with its folder and
# time, writes what the runner copies and a unit in its folder, and holds
# each folder's first build until every batch has started, for at most 30 s.
archive_tools="$TMP/archive-build-tools"
mkdir -p "$archive_tools"
cat > "$archive_tools/cargo" <<'CARGO'
#!/usr/bin/env bash
set -euo pipefail
trace="${ARCHIVE_TRACE:?}"
args="$*"
out='' previous='' package='' bin=''
for arg in "$@"; do
  case "$previous" in
    --archive-file) out="$arg" ;;
    -p) [ -n "$package" ] || package="$arg" ;;
    --bin) bin="$arg" ;;
  esac
  previous="$arg"
done
# The output folder varies by case; the trace names it OUT.
args="${args//"${ARCHIVE_OUT:?}"/OUT}"
mkdir -p "$CARGO_TARGET_DIR"
printf 'unit' > "$CARGO_TARGET_DIR/unit.rlib"
: > "$trace/active/$$"
# Each folder's first build waits until every batch has started one.
if mkdir "$trace/first-$(printf '%s' "$CARGO_TARGET_DIR" | sha256sum | cut -c1-16)" 2>/dev/null; then
  for _ in $(seq 1 300); do
    started=("$trace/first-"*)
    [ "${#started[@]}" -lt "$ARCHIVE_BATCHES" ] || break
    sleep 0.1
  done
fi
active=("$trace/active/"*)
printf '%s\n' "${#active[@]}" >> "$trace/running"
printf '%s %s|%s\n' "$(date +%s%N)" "${CARGO_TARGET_DIR#"$ARCHIVE_TARGETS"}" "$args" >> "$trace/calls"
rm -f -- "$trace/active/$$"
[ "$package" != "${ARCHIVE_FAIL:-none}" ] || { echo "error: could not compile \`$package\`"; exit 101; }
if [ "$1" = build ]; then
  profile=debug
  [[ " $* " != *' --profile ci '* ]] || profile=ci
  mkdir -p "$CARGO_TARGET_DIR/$profile"
  if [ -n "$bin" ]; then
    printf '#!/bin/sh\n' > "$CARGO_TARGET_DIR/$profile/$bin"
  else
    for arg in "$@"; do
      case "$arg" in codewire-*) printf '#!/bin/sh\n' > "$CARGO_TARGET_DIR/$profile/$arg" ;; esac
    done
  fi
  chmod 755 "$CARGO_TARGET_DIR/$profile"/*
  exit 0
fi
# The orchestration wire contract builds its package's binaries too.
if [[ " $* " == *' --features kind-e2e --test wire_contract '* ]]; then
  mkdir -p "$CARGO_TARGET_DIR/debug"
  for binary in codewire-orchestration log-stream-smoke temporal-smoke; do
    printf '#!/bin/sh\n' > "$CARGO_TARGET_DIR/debug/$binary"
    chmod 755 "$CARGO_TARGET_DIR/debug/$binary"
  done
fi
if [ -n "$out" ]; then printf 'archive' > "$out"; fi
CARGO
chmod +x "$archive_tools/cargo"
# archive_build_case NAME MODE LEG BATCHES SELECTION [FAILING PACKAGE]
archive_build_case() {
  local name="$1" mode="$2" leg="$3" batches="$4" selection="$5" failing="${6:-none}"
  local case_dir="$TMP/archive-build-$name"
  mkdir -p "$case_dir/trace/active" "$case_dir/out" "$case_dir/build/targets"
  PATH="$archive_tools:$PATH" ARCHIVE_TRACE="$case_dir/trace" ARCHIVE_OUT="$case_dir/out" \
    ARCHIVE_TARGETS="$case_dir/build/targets/" ARCHIVE_BATCHES="$batches" ARCHIVE_FAIL="$failing" \
    CARGO_TARGET_DIR="$case_dir/build/targets/$leg" CODEWIRE_CARGO_CI_TARGET_DIR="$case_dir/build/targets/$leg" \
    ARCHIVE_BUILD_DIR="$case_dir/out" RUN_DIR="$case_dir/run" VERIFICATION_SELECTION="$selection" \
    "$ROOT/scripts/ci/verify/run-integration-verification.sh" "$mode" > "$case_dir/log" 2>&1
}
# archive_build_calls NAME: the invocations, without folders, sorted.
archive_build_calls() {
  cut -d' ' -f2- "$TMP/archive-build-$1/trace/calls" | cut -d'|' -f2- | sort
}
# archive_build_folders NAME: each folder and its invocations, in the order
# they ran there.
archive_build_folders() {
  sort -n "$TMP/archive-build-$1/trace/calls" | cut -d' ' -f2- | sort -s -t'|' -k1,1 |
    awk -F'|' '$1 != folder { folder = $1; print folder ":" } { print "  " $2 }'
}
archive_build_check() {
  local name="$1" expected_calls="$2" expected_folders="$3" batches="$4" actual
  actual="$(archive_build_calls "$name")"
  [ "$actual" = "$(sort <<< "$expected_calls")" ] ||
    { printf '%s built:\n%s\nnot the builds one after another:\n%s\n' "$name" "$actual" "$(sort <<< "$expected_calls")" >&2; exit 1; }
  actual="$(archive_build_folders "$name")"
  [ "$actual" = "$expected_folders" ] ||
    { printf '%s built in its folders:\n%s\nnot:\n%s\n' "$name" "$actual" "$expected_folders" >&2; exit 1; }
  [ "$(sort -n "$TMP/archive-build-$name/trace/running" | tail -n 1)" = "$batches" ] ||
    { echo "the $batches $name build batches did not run at the same time" >&2; exit 1; }
}
EXPECTED_DATABASE_ARCHIVES='nextest archive --locked -p codewire-server-core --lib --test session_auth --test org_deletion_lifecycle --test oauth_bearer_auth --archive-file OUT/codewire-server-core.tar.zst
nextest archive --locked -p codewire-platform-credentials --test storage --test profiles --test refresh --test authority --test owner_sources --archive-file OUT/codewire-platform-credentials.tar.zst
nextest archive --locked -p codewire-orchestration --lib --test access_profiles --test credentials --test environment_external_cleanup --test environment_sources --archive-file OUT/codewire-orchestration.tar.zst
nextest archive --locked -p codewire-credential-service --features enrollment --lib --archive-file OUT/codewire-credential-service--features-enrollment.tar.zst
nextest archive --locked -p codewire-credential-service --lib --archive-file OUT/codewire-credential-service.tar.zst
nextest archive --locked -p codewire-credential-broker --no-default-features --features platform --lib --archive-file OUT/codewire-credential-broker--no-default--features-platform.tar.zst
nextest archive --locked -p codewire-credential-broker --no-default-features --features platform,ssh-agent --lib --archive-file OUT/codewire-credential-broker--no-default--features-platform-ssh-agent.tar.zst
nextest archive --locked -p codewire-billing --lib --archive-file OUT/codewire-billing.tar.zst
nextest archive --locked -p codewire-mesh --lib --archive-file OUT/codewire-mesh.tar.zst
build --locked --profile ci -p codewire-server-core --bin codewire-db-migrate'
archive_build_case database database-archives database 5 '|valid:v3|database|complete|' ||
  { cat "$TMP/archive-build-database/log" >&2; echo 'the database archive build failed' >&2; exit 1; }
archive_build_check database "$EXPECTED_DATABASE_ARCHIVES" 'database:
  nextest archive --locked -p codewire-server-core --lib --test session_auth --test org_deletion_lifecycle --test oauth_bearer_auth --archive-file OUT/codewire-server-core.tar.zst
  nextest archive --locked -p codewire-mesh --lib --archive-file OUT/codewire-mesh.tar.zst
database/batch-credential-service-enrollment:
  nextest archive --locked -p codewire-credential-service --features enrollment --lib --archive-file OUT/codewire-credential-service--features-enrollment.tar.zst
  nextest archive --locked -p codewire-credential-service --lib --archive-file OUT/codewire-credential-service.tar.zst
  nextest archive --locked -p codewire-credential-broker --no-default-features --features platform --lib --archive-file OUT/codewire-credential-broker--no-default--features-platform.tar.zst
  nextest archive --locked -p codewire-credential-broker --no-default-features --features platform,ssh-agent --lib --archive-file OUT/codewire-credential-broker--no-default--features-platform-ssh-agent.tar.zst
database/batch-migration-runner:
  build --locked --profile ci -p codewire-server-core --bin codewire-db-migrate
database/batch-orchestration:
  nextest archive --locked -p codewire-orchestration --lib --test access_profiles --test credentials --test environment_external_cleanup --test environment_sources --archive-file OUT/codewire-orchestration.tar.zst
database/batch-platform-credentials:
  nextest archive --locked -p codewire-platform-credentials --test storage --test profiles --test refresh --test authority --test owner_sources --archive-file OUT/codewire-platform-credentials.tar.zst
  nextest archive --locked -p codewire-billing --lib --archive-file OUT/codewire-billing.tar.zst' 5
[ "$(find "$TMP/archive-build-database/out" -name '*.tar.zst' | wc -l)" -eq 9 ] &&
  [ -x "$TMP/archive-build-database/out/codewire-db-migrate" ] ||
  { echo 'the database archive build did not write every archive and the migration runner' >&2; exit 1; }
# Each batch reports its time and its own folder's size: the first batch's
# leaves out the batch folders inside it.
for batch in server_core orchestration; do
  grep -q "^\[build batch\] $batch: finish (elapsed_seconds=[0-9]* folder_size=[0-9.]\+[KMG])$" "$TMP/archive-build-database/log" ||
    { grep '^\[build batch\]' "$TMP/archive-build-database/log" >&2; echo "the $batch build batch did not report its time and folder size" >&2; exit 1; }
done
# A failing build stops its own batch at once and fails the build, after
# every other batch has run to its end.
if archive_build_case database-failed database-archives database 5 '|valid:v3|database|complete|' codewire-server-core; then
  echo 'a failed database build batch passed' >&2; exit 1
fi
grep -qF '::error::the server_core build batch failed' "$TMP/archive-build-database-failed/log" ||
  { cat "$TMP/archive-build-database-failed/log" >&2; echo 'the failed build batch was not reported' >&2; exit 1; }
! grep -q 'codewire-mesh' "$TMP/archive-build-database-failed/trace/calls" ||
  { echo 'a batch went on after its failed build' >&2; exit 1; }
[ "$(wc -l < "$TMP/archive-build-database-failed/trace/calls")" -eq 9 ] ||
  { echo 'the other build batches did not run to their end' >&2; exit 1; }

EXPECTED_SERVICES_CONTROL_ARCHIVES='build --locked -p codewire-server-core --bin codewire-db-migrate
build --locked -p codewire-idp -p codewire-coordinator -p codewire-billing
nextest archive --locked -p codewire-idp --test db_flow --test session_inventory --test two_factor_replacement --test rewrap_cli --test oauth_sign_in --archive-file OUT/codewire-idp.tar.zst
nextest archive --locked -p codewire-coordinator --lib --test wire_contract --archive-file OUT/codewire-coordinator.tar.zst
nextest archive --locked -p codewire-billing --test wire_contract --archive-file OUT/codewire-billing.tar.zst
nextest archive --locked -p codewire-server-core --test connect_auth --archive-file OUT/codewire-server-core.tar.zst'
archive_build_case control services-control-archives services_control 4 "$full" ||
  { cat "$TMP/archive-build-control/log" >&2; echo 'the control-plane archive build failed' >&2; exit 1; }
archive_build_check control "$EXPECTED_SERVICES_CONTROL_ARCHIVES" 'services_control:
  build --locked -p codewire-server-core --bin codewire-db-migrate
  build --locked -p codewire-idp -p codewire-coordinator -p codewire-billing
  nextest archive --locked -p codewire-server-core --test connect_auth --archive-file OUT/codewire-server-core.tar.zst
services_control/batch-billing:
  nextest archive --locked -p codewire-billing --test wire_contract --archive-file OUT/codewire-billing.tar.zst
services_control/batch-coordinator:
  nextest archive --locked -p codewire-coordinator --lib --test wire_contract --archive-file OUT/codewire-coordinator.tar.zst
services_control/batch-idp:
  nextest archive --locked -p codewire-idp --test db_flow --test session_inventory --test two_factor_replacement --test rewrap_cli --test oauth_sign_in --archive-file OUT/codewire-idp.tar.zst' 4
for binary in codewire-db-migrate codewire-idp codewire-coordinator codewire-billing; do
  [ -x "$TMP/archive-build-control/out/$binary" ] ||
    { echo "the control-plane archive build did not keep $binary" >&2; exit 1; }
done

EXPECTED_SERVICES_RUNTIME_ARCHIVES='build --locked -p codewire-server-core --bin codewire-db-migrate
build --locked -p codewire-coordinator
build --locked -p codewire-cli-bin --bin cw
nextest archive --locked -p codewire-orchestration --features kind-e2e --test wire_contract --archive-file OUT/codewire-orchestration--features-kind-e2e.tar.zst
nextest archive --locked -p codewire-coordinator --lib --archive-file OUT/codewire-coordinator.tar.zst'
archive_build_case runtime services-runtime-archives services_runtime 1 \
  '|valid:v3|service_orchestration|service_nats|service_temporal|complete|' ||
  { cat "$TMP/archive-build-runtime/log" >&2; echo 'the runtime-plane archive build failed' >&2; exit 1; }
archive_build_check runtime "$EXPECTED_SERVICES_RUNTIME_ARCHIVES" 'services_runtime:
  build --locked -p codewire-server-core --bin codewire-db-migrate
  build --locked -p codewire-coordinator
  build --locked -p codewire-cli-bin --bin cw
  nextest archive --locked -p codewire-orchestration --features kind-e2e --test wire_contract --archive-file OUT/codewire-orchestration--features-kind-e2e.tar.zst
  nextest archive --locked -p codewire-coordinator --lib --archive-file OUT/codewire-coordinator.tar.zst' 1
for binary in codewire-db-migrate cw; do
  [ -x "$TMP/archive-build-runtime/out/$binary" ] ||
    { echo "the runtime-plane archive build did not keep $binary" >&2; exit 1; }
done

printf '[test-integration-postgres] hermetic selection, prerequisite, scope, and cleanup cases passed\n'
