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
  *) printf 'unexpected fake docker command: %s\n' "$1" >&2; exit 1 ;;
esac
EOF
chmod +x "$TMP/docker"
cat > "$TMP/psql" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_PSQL_LOG"
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
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-credential-broker .*127.0.0.1::5432 docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER$" "$FAKE_DOCKER_LOG"
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
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration --pids-limit 2048 --network codewire-fixture-net --network-alias codewire-integration-postgres-orchestration .* docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
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
[ "$(grep -c "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-" "$FAKE_DOCKER_LOG")" -eq 2 ]
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
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration --pids-limit 2048 --network codewire-fixture-net " "$FAKE_DOCKER_LOG"
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration .* --label codewire.ci.run=fixture-$$ --label codewire.ci.attempt=0 --label codewire.ci.job=local " "$FAKE_DOCKER_LOG"
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


# Preserve the accepted execution contracts while adding source-admission proof:
# compile grouping may change, but no suite, environment or count may disappear.
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
suites = [
    {'args': ['test', '-p', 'codewire-server-core', '--lib', 'migrate::', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'server-core migration matrix', 'count': 22},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'storage', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform credential storage matrix', 'count': 24},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'profiles', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform access profile matrix', 'count': 15},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'owner_sources', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform owner-source authority matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::preview::authorization::database_tests::', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'preview browser authorization matrix', 'count': 9},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--test', 'access_profiles', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'public access profile restricted API matrix', 'count': 8},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--test', 'credentials', '--', '--ignored', '--nocapture', '--test-threads=3'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'public credential metadata matrix', 'count': 3},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'mutation::tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'public credential mutation matrix', 'count': 28},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'runtime::tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'isolated credential runtime matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'repositories::tests::integration::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'GitHub repository discovery matrix', 'count': 9},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'runtime::kind::config::tests::effective_acl_guard_rejects_direct_column_and_membership_authority', '--', '--exact', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'Kind credential effective ACL matrix', 'count': 1},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'refresh', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform credential refresh matrix', 'count': 14},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'authority', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform credential restricted-role matrix', 'count': 13},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::', '--', '--ignored', '--skip', 'platform::tests::checked::', '--skip', 'platform::tests::claude_sign_in::', '--skip', 'platform::tests::codex_login::', '--skip', 'platform::tests::decision::', '--skip', 'platform::tests::keepalive::', '--skip', 'platform::tests::material_cache::', '--skip', 'platform::tests::subscription::', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker admission matrix', 'count': 13, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::checked::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker checked lease matrix', 'count': 8, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::claude_sign_in::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker Claude sign-in matrix', 'count': 5, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::decision::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker decision matrix', 'count': 8, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::codex_login::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker Codex login matrix', 'count': 4, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::keepalive::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker keepalive matrix', 'count': 5, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::material_cache::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker material cache matrix', 'count': 5, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::subscription::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker subscription matrix', 'count': 2, 'matrix': 'platform broker admission matrix'},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform,ssh-agent', '--lib', 'platform::tests::ssh::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker SSH matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::bridge::tests::rotation::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker gRPC rotation drain matrix', 'count': 4},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--lib', 'tests::database::', '--', '--ignored', '--skip', 'tests::database::projection::', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform runtime restricted identity matrix', 'count': 6},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--lib', 'tests::database::projection::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform runtime projection matrix', 'count': 13},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'delegation::authority::tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'owner-local delegation authority matrix', 'count': 8},
    {'args': ['test', '--locked', '-p', 'codewire-server-core', '--test', 'oauth_bearer_auth', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'OAuth-only restricted identity matrix', 'count': 6},
    {'args': ['test', '-p', 'codewire-server-core', '--test', 'session_auth', '--', '--nocapture'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'session hash-only matrix', 'count': 4},
    {'args': ['test', '-p', 'codewire-server-core', '--test', 'org_deletion_lifecycle', '--', '--nocapture'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'organization deletion lifecycle matrix', 'count': 20},
    {'args': ['test', '-p', 'codewire-billing', '--lib', 'billing_teardown::tests::db_', '--', '--nocapture'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'organization billing teardown matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'connect::mesh_authorization::tests::generated_mesh_authorization_service_enforces_the_canonical_matrix', '--', '--ignored', '--exact', '--nocapture'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'Mesh authorization receiver matrix', 'count': 1},
    {'args': ['test', '-p', 'codewire-orchestration', '--test', 'environment_external_cleanup', '--', '--nocapture'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'environment external cleanup matrix', 'count': 9},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environment_daemon::session_mutation::tests::db_', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment session admission matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'worker::lifecycle::tests::destroy_template_hint_allows_missing_creation_config_but_not_database_failure', '--', '--ignored', '--exact', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment destroy template hint matrix', 'count': 1},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'worker::create::projection_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment projection capture matrix', 'count': 5},
    {'args': ['test', '-p', 'codewire-orchestration', '--lib', 'worker::tenant_secret_teardown::tests::db_', '--', '--nocapture'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'organization tenant secret teardown matrix', 'count': 2},
    {'args': ['test', '-p', 'codewire-orchestration', '--lib', 'worker::postgres_secrets::tests::encrypted_store_reencrypts_renames_and_deletes_final_dek', '--', '--ignored', '--exact', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'encrypted tenant secret store matrix', 'count': 1},
    {'args': ['test', '-p', 'codewire-mesh', '--lib', 'store::migration_tests::', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'Mesh migration ledger', 'count': 16},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--test', 'environment_sources', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment source admission matrix', 'count': 6},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::admin::startup_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'admin startup summary matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'worker::workspace_binding::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'workspace binding recorder matrix', 'count': 20},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'workspace_binding::store::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'workspace binding access store matrix', 'count': 4},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'environment_mesh::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment Mesh membership matrix', 'count': 3},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::cw_runtime::owner::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform cw runtime journal matrix', 'count': 31},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::platform_agents::journal::database_tests::db_', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform managed agent journal matrix', 'count': 40},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environment_resize::tests::db_', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'environment resize admission matrix', 'count': 3},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::ssh_proxy::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'SSH proxy runtime lease matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environment_daemon::repair_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment daemon repair lease matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environments::access_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment membership access matrix', 'count': 1},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::organizations::membership_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'organization membership credential matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'worker::billing_sessions::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'billing session bind matrix', 'count': 4},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'worker::credential_relay::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'credential relay target matrix', 'count': 1},
]
batches = [
    ['test', '-p', 'codewire-server-core', '--lib', '--test', 'session_auth',
     '--test', 'org_deletion_lifecycle', '--test', 'oauth_bearer_auth', '--no-run'],
    ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'storage',
     '--test', 'profiles', '--test', 'refresh', '--test', 'authority', '--test', 'owner_sources', '--no-run'],
    ['test', '--locked', '-p', 'codewire-orchestration', '--lib', '--test', 'access_profiles',
     '--test', 'credentials', '--test', 'environment_external_cleanup', '--test', 'environment_sources', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-service', '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform',
     '--lib', '--no-run'],
    ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features',
     'platform,ssh-agent', '--lib', '--no-run'],
    ['test', '-p', 'codewire-billing', '--lib', '--no-run'],
    ['test', '-p', 'codewire-mesh', '--lib', '--no-run'],
]
# Ten lanes, each keeping its suites in their established order. Every
# harness compiles before any lane starts.
lane_order = ['core', 'credential-mutations', 'credential-service', 'broker-admission', 'broker-checked',
              'broker-decisions', 'broker-refresh', 'orchestration', 'orchestration-journals',
              'orchestration-workspaces']
lane_labels = {
    'core': {'server-core migration matrix', 'platform credential storage matrix',
             'platform access profile matrix', 'platform owner-source authority matrix',
             'platform credential refresh matrix', 'platform credential restricted-role matrix',
             'OAuth-only restricted identity matrix', 'session hash-only matrix',
             'organization deletion lifecycle matrix', 'organization billing teardown matrix',
             'Mesh migration ledger'},
    'credential-mutations': {'public credential mutation matrix', 'owner-local delegation authority matrix'},
    'credential-service': {'isolated credential runtime matrix', 'GitHub repository discovery matrix',
                           'Kind credential effective ACL matrix', 'platform runtime restricted identity matrix',
                           'platform runtime projection matrix'},
    'broker-admission': {'platform broker admission matrix', 'platform broker Claude sign-in matrix',
                         'platform broker gRPC rotation drain matrix'},
    'broker-checked': {'platform broker checked lease matrix'},
    'broker-decisions': {'platform broker decision matrix', 'platform broker Codex login matrix'},
    'broker-refresh': {'platform broker keepalive matrix', 'platform broker material cache matrix',
                       'platform broker subscription matrix', 'platform broker SSH matrix'},
    'orchestration-journals': {'platform cw runtime journal matrix', 'platform managed agent journal matrix'},
    'orchestration-workspaces': {'environment source admission matrix', 'admin startup summary matrix',
                                 'workspace binding recorder matrix', 'workspace binding access store matrix',
                                 'environment Mesh membership matrix', 'environment resize admission matrix',
                                 'SSH proxy runtime lease matrix', 'environment daemon repair lease matrix',
                                 'environment membership access matrix', 'organization membership credential matrix',
                                 'billing session bind matrix', 'credential relay target matrix'},
}
for suite in suites:
    suite['lane'] = next((lane for lane, labels in lane_labels.items() if suite['label'] in labels), 'orchestration')
assert sum(suite['lane'] != 'orchestration' for suite in suites) == sum(map(len, lane_labels.values()))
lane_suites = {lane: [suite for suite in suites if suite['lane'] == lane] for lane in lane_order}
assert all(lane_suites.values()), 'a database lane runs no suite'
# The broker admission matrix runs in four lanes by module: together its
# parts still require every one of its 50 tests.
assert sum(suite['count'] for suite in suites
           if suite.get('matrix') == 'platform broker admission matrix') == 50
assert len({suite['label'] for suite in suites}) == len(suites)
# The fakes are shared; each case traces into its own folder, so the cases
# below run side by side and are checked in order afterwards.
tools = temporary / 'database-tools'
tools.mkdir()
cases_root = temporary / 'database-cases'
cases_root.mkdir()
# The fake Cargo looks a suite up by its arguments, one suite per line:
# index, count, and the arguments joined by the unit separator.
assert all(not set(arg) & {'\t', '\n', '\x1f'} for suite in suites for arg in suite['args'])
(tools / 'suites.tsv').write_text(''.join(
    f"{index}\t{suite['count']}\t{chr(31).join(suite['args'])}\n" for index, suite in enumerate(suites)))
# Bash, not Python: the cases start it about two thousand times, and an
# interpreter start per call was most of this test's time.
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
IFS=$'\x1f'
key="$*"
IFS=$' \t\n'
index='' count=''
while IFS=$'\t' read -r line_index line_count line_args; do
  if [ "$line_args" = "$key" ]; then index="$line_index" count="$line_count"; break; fi
done < "${BASH_SOURCE[0]%/*}/suites.tsv"
[ -n "$index" ] || { echo 'Unexpected database execution' >&2; exit 1; }
[ "$failure" != "test:$index" ] || exit 43
if [ "$failure" = "skip:$index" ]; then echo 'DATABASE_URL unset'; fi
if [ "$failure" = "count:$index" ]; then count=$((count - 1)); fi
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

lock_dir = temporary / 'lane-locks'

def case_environment(failure='', extra=None):
    work = Path(tempfile.mkdtemp(dir=cases_root))
    (work / 'active').mkdir()
    return {
        'CODEWIRE_INTEGRATION_LOCK_DIR': str(lock_dir), **(extra or {}),
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
broker_index = next(i for i, suite in enumerate(suites) if suite['label'] == 'platform broker admission matrix')
journal_index = next(i for i, item in enumerate(suites)
                     if item['label'] == 'platform cw runtime journal matrix')
def suite_index(label):
    return next(i for i, suite in enumerate(suites) if suite['label'] == label)
failures = ['compile:codewire-server-core', 'compile:codewire-platform-credentials',
            'compile:codewire-orchestration', 'test:0',
            'test:' + str(suite_index('organization billing teardown matrix')),
            'skip:' + str(suite_index('session hash-only matrix')),
            'skip:' + str(suite_index('organization deletion lifecycle matrix')),
            'skip:' + str(suite_index('environment external cleanup matrix'))]
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
    'failed lane': pool.submit(run_case, 'test:' + str(broker_index), extra=network),
    'journal': pool.submit(run_case, 'test:' + str(journal_index)),
    **{'count:' + str(index): pool.submit(run_case, 'count:' + str(index)) for index in range(len(suites))},
    **{failure: pool.submit(run_case, failure) for failure in failures},
}

result, commands, environment = cases['explicit'].result()
assert result.returncode == 0, result.stdout + result.stderr
assert '[product-integration] green' in result.stdout
assert commands[0]['args'] == ['build', '--locked', '--profile', 'ci', '-p',
                               'codewire-server-core', '--bin', 'codewire-db-migrate']
assert commands[0]['target'] == environment['CODEWIRE_CARGO_CI_TARGET_DIR']
actual_batches = [command for command in commands if '--no-run' in command['args']]
assert [command['args'] for command in actual_batches] == batches
assert all(command['target'] == environment['CARGO_TARGET_DIR'] and
           command['test_database'] == environment['DATABASE_URL_RUST'] for command in actual_batches)
# Every database suite runs in the test profile its batch built.
assert not any(suite['ci'] for suite in suites)
executions = [command for command in commands if command['args'][0] == 'test'
              and '--no-run' not in command['args']]
# 45 suite contracts before the broker admission matrix ran in four lanes by
# module (one suite became eight); 438 required tests (437, plus #3402's
# ListOrganizations statement test).
assert len(executions) == len(suites) == 52
assert sum(suite['count'] for suite in suites) == 438
assert commands.index(actual_batches[-1]) < commands.index(executions[0]), 'a lane started before every harness compiled'
# Against one explicit database the lanes run one after another, in lane order.
for expected, actual in zip([suite for lane in lane_order for suite in lane_suites[lane]], executions):
    assert actual['args'] == expected['args'], expected['label']
    assert actual['target'] == environment['CODEWIRE_CARGO_CI_TARGET_DIR' if expected['ci']
                                           else 'CARGO_TARGET_DIR'], expected['label']
    field = 'test_database' if expected['database_env'] == 'TEST_DATABASE_URL' else 'database'
    assert actual[field] == environment['DATABASE_URL_RUST'], expected['label']
for batch in actual_batches:
    package = batch['args'][batch['args'].index('-p') + 1]
    first_test = next(command for command in executions if package in command['args'])
    assert commands.index(batch) < commands.index(first_test)
# With CI's job network each lane after the first gets its own PostgreSQL on
# that network, migrated before the lanes start side by side. Each lane runs
# its own suites in order against its own database, and every lane container
# is removed afterwards, also when a lane fails.
def lane_url(lane):
    return ('postgres://codewire:codewire@codewire-integration-postgres-' + lane + ':5432/codewire'
            if lane != 'core' else environment['DATABASE_URL_RUST'])
def check_lanes(commands, case, complete=True):
    executions = [command for command in commands if command['args'][0] == 'test' and '--no-run' not in command['args']]
    for lane in lane_order:
        expected = [suite for suite in lane_suites[lane]]
        actual = [command for command in executions
                  if (command['test_database'] or command['database']) == lane_url(lane)]
        assert [command['args'] for command in actual] == [suite['args'] for suite in expected][:len(actual)], lane
        if complete:
            assert len(actual) == len(expected), lane
    migrations = [command for command in commands if command['args'][0] == 'build']
    assert len(migrations) == len(lane_order), migrations
    started = case_file(case, 'docker.log').read_text().splitlines()
    for lane in lane_order[1:]:
        name = 'codewire-product-postgres-local-'
        runs = [line for line in started if line.startswith('run -d --rm --name ' + name) and line.split()[4].endswith('-lane-' + lane)]
        assert len(runs) == 1 and '--network codewire-fixture-net --network-alias codewire-integration-postgres-' + lane in runs[0], started
        assert any(line.startswith('rm -f ') and line.endswith('-lane-' + lane) for line in started[started.index(runs[0]):]), started
        # A finished lane's PostgreSQL is removed then, not only at the end.
        assert sum(line == 'rm -f ' + runs[0].split()[4] for line in started) >= 3, (lane, started)
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
lane_executions = [command for command in shared_commands
                   if command['args'][0] == 'test' and '--no-run' not in command['args']]
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
assert not [command for command in invalid_commands if command['args'][0] == 'test' and '--no-run' not in command['args']]
too_many, too_many_commands, _ = cases['too many'].result()
assert too_many.returncode != 0 and 'CODEWIRE_CI_DATABASE_LANES_AT_ONCE must be 1 to 10, not 11' in too_many.stdout + too_many.stderr
assert not [command for command in too_many_commands if command['args'][0] == 'test' and '--no-run' not in command['args']]
# A malformed share is ignored with a warning, never read as a smaller one.
malformed, _, _ = cases['malformed'].result()
assert malformed.returncode == 0 and 'database lanes: 10 at a time:' in malformed.stdout, malformed.stdout
assert 'ignoring CODEWIRE_CI_CPU_SHARE' in malformed.stdout + malformed.stderr
failed_lane, failed_commands, failed_environment = cases['failed lane'].result()
assert failed_lane.returncode != 0 and '[product-integration] green' not in failed_lane.stdout
assert '::error::database lane broker-admission failed' in failed_lane.stdout, failed_lane.stdout
check_lanes(failed_commands, failed_environment, complete=False)
for lane in (lane for lane in lane_order if lane != 'broker-admission'):
    assert sum((command['test_database'] or command['database']) == lane_url(lane) for command in failed_commands
               if command['args'][0] == 'test' and '--no-run' not in command['args']) == len(lane_suites[lane]), lane
# Every retained assertion must fail on an incorrect count. This also catches
# deleting the assertion while leaving the corresponding test command present.
for index in range(len(suites)):
    failed, _, _ = cases['count:' + str(index)].result()
    assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout, index
failed, trace, _ = cases['journal'].result()
assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout
assert trace[-1]['args'] == suites[journal_index]['args']
for failure in failures:
    failed, trace, _ = cases[failure].result()
    assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout, failure
    if failure.startswith('compile:'):
        assert '--no-run' in trace[-1]['args'], failure
lane_lock.result()
pool.shutdown()

print(f'Database batching: {len(suites) + 10} trace/failure cases; '
      f'all {len(suites)} suite contracts and {sum(suite["count"] for suite in suites)} required tests preserved')
PYTHON

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
service_lane_check full idp-sessions "$(service_lane_url idp-sessions)" 'idp_session_inventory idp_rewrap_cli'
service_lane_check full connect-auth "$(service_lane_url connect-auth)" connect_auth
service_lane_check full billing "$(service_lane_url billing)" 'billing billing_temporal'
service_lane_check full coordinator "$(service_lane_url coordinator)" coordinator
# Every lane after the first migrated its own PostgreSQL, which was removed
# when the lane ended.
for lane in idp-flow idp-sessions connect-auth billing coordinator; do
  grep -qxF "migrate $(service_lane_url "$lane")" "$TMP/service-lanes-full/trace" ||
    { echo "service lane $lane did not migrate its database" >&2; exit 1; }
  grep -q "^run -d --rm --name codewire-product-postgres-[^ ]*-lane-$lane .*--network-alias codewire-integration-postgres-$lane " \
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
[ "$(grep -c '^end ' "$TMP/service-lanes-failed/trace")" -eq 7 ] ||
  { echo 'the other control-plane lanes did not run to their end' >&2; exit 1; }

printf '[test-integration-postgres] hermetic selection, prerequisite, scope, and cleanup cases passed\n'
