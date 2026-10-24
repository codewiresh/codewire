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
  run) printf '%s\n' fake-container-id ;;
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
grep -q '^run .*127.0.0.1::5432 postgres:17-alpine -c max_locks_per_transaction=1024$' "$FAKE_DOCKER_LOG"
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
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-credential-broker .*127.0.0.1::5432 postgres:17-alpine -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
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
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration --pids-limit 2048 --network codewire-fixture-net --network-alias codewire-integration-postgres-orchestration .* postgres:17-alpine -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
integration_postgres_cleanup
grep -q "^rm -f $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration$" "$FAKE_DOCKER_LOG"
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
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER --pids-limit 2048 --network codewire-fixture-net --network-alias $INTEGRATION_POSTGRES_CONTAINER .* postgres:17-alpine -c max_locks_per_transaction=1024$" "$FAKE_DOCKER_LOG"
if grep -q -- '127.0.0.1:' "$FAKE_DOCKER_LOG"; then
  echo 'a job-network PostgreSQL published a loopback port' >&2
  exit 1
fi
grep -q "@$INTEGRATION_POSTGRES_CONTAINER:5432/codewire?sslmode=disable.*SELECT 1" "$FAKE_PSQL_LOG"
integration_postgres_lanes_available
integration_postgres_start_lane orchestration
[ "$INTEGRATION_POSTGRES_LANE_URL_RUST" = "postgres://codewire:codewire@codewire-integration-postgres-orchestration:5432/codewire" ]
grep -q "^run -d --rm --name $INTEGRATION_POSTGRES_CONTAINER-lane-orchestration --pids-limit 2048 --network codewire-fixture-net " "$FAKE_DOCKER_LOG"
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

reset_case
INTEGRATION_POSTGRES_HOST_PORT=55432
FAKE_DOCKER_PORT=55432
integration_postgres_configure
[ "$INTEGRATION_POSTGRES_SOURCE" = managed ]
[ "$DATABASE_URL" = "postgres://codewire:codewire@127.0.0.1:55432/codewire?sslmode=disable" ]
[ "$DATABASE_URL_RUST" = "postgres://codewire:codewire@127.0.0.1:55432/codewire" ]
grep -q '^run .*127.0.0.1:55432:5432 postgres:17-alpine -c max_locks_per_transaction=1024$' "$FAKE_DOCKER_LOG"
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
import json
import os
from pathlib import Path
import subprocess
import sys

root, temporary = map(Path, sys.argv[1:])
suites = [
    {'args': ['test', '-p', 'codewire-server-core', '--lib', 'migrate::', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'server-core migration matrix', 'count': 21},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'storage', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform credential storage matrix', 'count': 24},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'profiles', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform access profile matrix', 'count': 15},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'owner_sources', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform owner-source authority matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::preview::authorization::database_tests::', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'preview browser authorization matrix', 'count': 8},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--test', 'access_profiles', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'public access profile restricted API matrix', 'count': 8},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--test', 'credentials', '--', '--ignored', '--nocapture', '--test-threads=3'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'public credential metadata matrix', 'count': 3},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'mutation::tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'public credential mutation matrix', 'count': 28},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'runtime::tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'isolated credential runtime matrix', 'count': 5},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'repositories::tests::integration::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'GitHub repository discovery matrix', 'count': 9},
    {'args': ['test', '--locked', '-p', 'codewire-credential-service', '--features', 'enrollment', '--lib', 'runtime::kind::config::tests::effective_acl_guard_rejects_direct_column_and_membership_authority', '--', '--exact', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'Kind credential effective ACL matrix', 'count': 1},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'refresh', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform credential refresh matrix', 'count': 14},
    {'args': ['test', '--locked', '-p', 'codewire-platform-credentials', '--test', 'authority', '--', '--ignored', '--nocapture', '--test-threads=4'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform credential restricted-role matrix', 'count': 13},
    {'args': ['test', '--locked', '-p', 'codewire-credential-broker', '--no-default-features', '--features', 'platform', '--lib', 'platform::tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform broker admission matrix', 'count': 49},
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
    {'args': ['test', '-p', 'codewire-mesh', '--lib', 'store::migration_tests::', '--', '--ignored', '--nocapture'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'Mesh migration ledger', 'count': 15},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--test', 'environment_sources', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment source admission matrix', 'count': 6},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::admin::startup_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'admin startup summary matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'worker::workspace_binding::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'workspace binding recorder matrix', 'count': 20},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'workspace_binding::store::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'workspace binding access store matrix', 'count': 4},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::cw_runtime::owner::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform cw runtime journal matrix', 'count': 31},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::platform_agents::journal::database_tests::db_', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'platform managed agent journal matrix', 'count': 40},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environment_resize::tests::db_', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'DATABASE_URL', 'ci': False, 'label': 'environment resize admission matrix', 'count': 3},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::ssh_proxy::database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'SSH proxy runtime lease matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environment_daemon::repair_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment daemon repair lease matrix', 'count': 2},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::environments::access_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'environment membership access matrix', 'count': 1},
    {'args': ['test', '--locked', '-p', 'codewire-orchestration', '--lib', 'api::organizations::membership_database_tests::', '--', '--ignored', '--nocapture', '--test-threads=1'], 'database_env': 'TEST_DATABASE_URL', 'ci': False, 'label': 'organization membership credential matrix', 'count': 1},
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
# Four lanes, each keeping its suites in their established order. Every
# harness compiles before any lane starts.
lane_order = ['core', 'credential-service', 'credential-broker', 'orchestration']
lane_labels = {
    'core': {'server-core migration matrix', 'platform credential storage matrix',
             'platform access profile matrix', 'platform owner-source authority matrix',
             'platform credential refresh matrix', 'platform credential restricted-role matrix',
             'OAuth-only restricted identity matrix', 'session hash-only matrix',
             'organization deletion lifecycle matrix', 'organization billing teardown matrix',
             'Mesh migration ledger'},
    'credential-service': {'public credential mutation matrix', 'isolated credential runtime matrix',
                           'GitHub repository discovery matrix', 'Kind credential effective ACL matrix',
                           'platform runtime restricted identity matrix', 'platform runtime projection matrix',
                           'owner-local delegation authority matrix'},
    'credential-broker': {'platform broker admission matrix', 'platform broker SSH matrix',
                          'platform broker gRPC rotation drain matrix'},
}
for suite in suites:
    suite['lane'] = next((lane for lane, labels in lane_labels.items() if suite['label'] in labels), 'orchestration')
assert sum(suite['lane'] != 'orchestration' for suite in suites) == sum(map(len, lane_labels.values()))
lane_suites = {lane: [suite for suite in suites if suite['lane'] == lane] for lane in lane_order}
trace_root = temporary / 'database-trace'
trace_root.mkdir()
(trace_root / 'suites.json').write_text(json.dumps(suites))
cargo = trace_root / 'cargo'
cargo.write_text(r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
work = Path(os.environ['DB_TRACE_ROOT'])
record = dict(args=args, target=os.environ['CARGO_TARGET_DIR'],
              test_database=os.environ.get('TEST_DATABASE_URL'), database=os.environ.get('DATABASE_URL'))
with (work / 'trace.jsonl').open('a') as output:
    output.write(json.dumps(record) + '\n')
if args[0] == 'build':
    target = Path(record['target']) / 'ci' / 'codewire-db-migrate'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('#!/bin/sh\nexit 0\n')
    target.chmod(0o755)
    sys.exit(0)
if '--no-run' in args:
    if os.environ['DB_TRACE_FAILURE'] == 'compile:' + args[args.index('-p') + 1]:
        sys.exit(42)
    print('Finished compiling synthetic database harnesses')
    sys.exit(0)
suites = json.loads((work / 'suites.json').read_text())
index = next((i for i, item in enumerate(suites) if item['args'] == args), None)
if index is None:
    sys.exit('Unexpected database execution')
failure = os.environ['DB_TRACE_FAILURE']
if failure == 'test:' + str(index):
    sys.exit(43)
if failure == 'skip:' + str(index):
    print('DATABASE_URL unset')
count = suites[index]['count'] - (failure == 'count:' + str(index))
print(f'test result: ok. {count} passed; 0 failed; 0 ignored')
''')
cargo.chmod(0o755)
(trace_root / 'psql').write_text('#!/bin/sh\nexit 0\n')
(trace_root / 'psql').chmod(0o755)
(trace_root / 'docker').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>"$DB_TRACE_ROOT/docker.log"\nexit 0\n')
(trace_root / 'docker').chmod(0o755)

lock_dir = temporary / 'lane-locks'

def run_case(failure='', extra=None):
    trace = trace_root / 'trace.jsonl'
    trace.unlink(missing_ok=True)
    (trace_root / 'docker.log').unlink(missing_ok=True)
    environment = {
        'CODEWIRE_INTEGRATION_LOCK_DIR': str(lock_dir), **(extra or {}),
        'PATH': str(trace_root) + os.pathsep + os.environ['PATH'],
        'CODEWIRE_LOCAL_RUST_CACHE': 'off',
        'CARGO_TARGET_DIR': str(trace_root / 'debug-target'),
        'CODEWIRE_CARGO_CI_TARGET_DIR': str(trace_root / 'ci-target'),
        'RUN_DIR': str(trace_root / 'run'),
        'DATABASE_URL': 'postgres://synthetic:synthetic@127.0.0.1:60003/sql-client',
        'DATABASE_URL_RUST': 'postgres://synthetic:synthetic@127.0.0.1:60003/rust-client',
        'DB_TRACE_ROOT': str(trace_root), 'DB_TRACE_FAILURE': failure,
    }
    result = subprocess.run(['bash', str(root / 'scripts/ci/verify/run-integration-verification.sh'),
                             'database'], env=environment, cwd=root, capture_output=True, text=True)
    commands = [json.loads(line) for line in trace.read_text().splitlines()]
    return result, commands, environment

result, commands, environment = run_case()
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
assert len(executions) == len(suites) == 44
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
network = {'INTEGRATION_DOCKER_NETWORK': 'codewire-fixture-net'}
def lane_url(lane):
    return ('postgres://codewire:codewire@codewire-integration-postgres-' + lane + ':5432/codewire'
            if lane != 'core' else environment['DATABASE_URL_RUST'])
def check_lanes(commands, complete=True):
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
    started = (trace_root / 'docker.log').read_text().splitlines()
    for lane in lane_order[1:]:
        name = 'codewire-product-postgres-local-'
        runs = [line for line in started if line.startswith('run -d --rm --name ' + name) and line.split()[4].endswith('-lane-' + lane)]
        assert len(runs) == 1 and '--network codewire-fixture-net --network-alias codewire-integration-postgres-' + lane in runs[0], started
        assert any(line.startswith('rm -f ') and line.endswith('-lane-' + lane) for line in started[started.index(runs[0]):]), started
lanes, lane_commands, _ = run_case(extra=network)
assert lanes.returncode == 0 and '[product-integration] green' in lanes.stdout, lanes.stdout + lanes.stderr
assert 'database lanes run side by side: core credential-service credential-broker orchestration' in lanes.stdout
for lane in lane_order:
    assert f'=== database lane {lane} ===' in lanes.stdout, lane
    assert f'CODEWIRE_CI_PHASE name=database-lane-{lane} seconds=' in lanes.stdout, lane
check_lanes(lane_commands)
broker_index = next(i for i, suite in enumerate(suites) if suite['label'] == 'platform broker admission matrix')
failed_lane, failed_commands, _ = run_case('test:' + str(broker_index), extra=network)
assert failed_lane.returncode != 0 and '[product-integration] green' not in failed_lane.stdout
assert '::error::database lane credential-broker failed' in failed_lane.stdout, failed_lane.stdout
check_lanes(failed_commands, complete=False)
for lane in ('core', 'credential-service', 'orchestration'):
    assert sum((command['test_database'] or command['database']) == lane_url(lane) for command in failed_commands
               if command['args'][0] == 'test' and '--no-run' not in command['args']) == len(lane_suites[lane]), lane
# Every retained assertion must fail on an incorrect count. This also catches
# deleting the assertion while leaving the corresponding test command present.
for index in range(len(suites)):
    failed, _, _ = run_case('count:' + str(index))
    assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout, index
journal_index = next(i for i, item in enumerate(suites)
                     if item['label'] == 'platform cw runtime journal matrix')
failed, trace, _ = run_case('test:' + str(journal_index))
assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout
assert trace[-1]['args'] == suites[journal_index]['args']
for failure in ['compile:codewire-server-core', 'compile:codewire-platform-credentials',
                'compile:codewire-orchestration', 'test:0', 'test:22', 'skip:20', 'skip:21', 'skip:24']:
    failed, trace, _ = run_case(failure)
    assert failed.returncode != 0 and '[product-integration] green' not in failed.stdout, failure
    if failure.startswith('compile:'):
        assert '--no-run' in trace[-1]['args'], failure
# The integration lane lock (#2755). Another run holds the 62000 range:
# this hermetic fixture sets no VERIFICATION_PORT_BASE, so it neither takes
# the lock nor waits on it; a real lane, which is given the base, waits for it.
import fcntl
lock_dir.mkdir(mode=0o700, exist_ok=True)
held = os.open(lock_dir / 'ports-62000.lock', os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(held, fcntl.LOCK_EX)
(lock_dir / 'ports-62000.lock.holder').write_text('database in /worktrees/other pid=1\n')
fixture, _, _ = run_case()
assert fixture.returncode == 0 and '[product-integration] green' in fixture.stdout, fixture.stdout + fixture.stderr
assert 'integration lane lock' not in fixture.stdout
lane_environment = dict(environment, VERIFICATION_PORT_BASE='62000', RUN_DIR=str(trace_root / 'lane-run'))
(trace_root / 'trace.jsonl').unlink(missing_ok=True)
lane = subprocess.Popen(['bash', str(root / 'scripts/ci/verify/run-integration-verification.sh'), 'database'],
                        env=lane_environment, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
waiting = lane.stdout.readline()
while waiting and 'integration lane lock' not in waiting:
    waiting = lane.stdout.readline()
assert 'waiting for the integration lane lock' in waiting and 'held by database in /worktrees/other' in waiting, waiting
import time
time.sleep(2)
assert lane.poll() is None and not (trace_root / 'trace.jsonl').exists(), 'a real lane ran while another held its range'
os.close(held)
rest, _ = lane.communicate(timeout=300)
assert lane.returncode == 0 and '[product-integration] green' in rest, rest
assert 'acquired' in rest
assert f'{root} pid=' in (lock_dir / 'ports-62000.lock.holder').read_text()

print(f'Database batching: {len(suites) + 10} trace/failure cases; '
      f'all {len(suites)} suite contracts and {sum(suite["count"] for suite in suites)} required tests preserved')
PYTHON

# Every integration PostgreSQL gets the same server settings (#3198): the ones
# this file starts above, and ci.yaml's "Start integration Postgres" steps.
[ "${INTEGRATION_POSTGRES_SERVER_ARGS[*]}" = '-c max_locks_per_transaction=1024' ]
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
    assert " ".join(command.group(0).split()).endswith(f"postgres:17-alpine {server_args}"), command.group(0)
PYTHON

printf '[test-integration-postgres] hermetic selection, prerequisite, scope, and cleanup cases passed\n'
