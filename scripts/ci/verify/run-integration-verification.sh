#!/usr/bin/env bash
# Bounded database and per-service verification extracted from the all-up
# Rust stack rehearsal. A reachable disposable Postgres is required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MODE="${1:-}"
SELECTION="${VERIFICATION_SELECTION:-|valid:v3|complete|}"
CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
export CARGO_TARGET_DIR
CARGO_CI_TARGET_DIR="${CODEWIRE_CARGO_CI_TARGET_DIR:-$CARGO_TARGET_DIR}"
CARGO_CI_DIR="$CARGO_CI_TARGET_DIR/ci"
RUN_DIR="${RUN_DIR:-$ROOT/.tmp/codewire-product-integration-${GITHUB_RUN_ID:-local-$$}}"
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
NATS_CONTAINER="codewire-product-nats-${GITHUB_RUN_ID:-local-$$}"
IDP_SIGNING_KEK_DIR=""
BILLING_FIXTURE_LOADED=false

# shellcheck source=scripts/ci/verify/integration-postgres.sh
source "$ROOT/scripts/ci/verify/integration-postgres.sh"
integration_postgres_init

mkdir -p "$RUN_DIR/bin"
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-5}" TZ=UTC

log() {
  printf '[product-integration] %s\n' "$*"
}

selected() {
  [[ "$SELECTION" == *"|$1|"* ]]
}

cargo_ci() {
  CARGO_TARGET_DIR="$CARGO_CI_TARGET_DIR" cargo "$@"
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
  if [ -n "$IDP_SIGNING_KEK_DIR" ]; then
    rm -rf -- "$IDP_SIGNING_KEK_DIR"
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

run_database() {
  local logfile
  reset_schema

  # Compile independent harnesses together, but execute the database suites in
  # their established order against the shared schema. Each batch uses one
  # package, default features and the default test profile; CI-profile and
  # restricted-feature checks below remain separate.
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --lib --test session_auth \
      --test org_deletion_lifecycle --test oauth_bearer_auth --no-run

  logfile="$RUN_DIR/server-core-migrate.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --lib migrate:: -- --ignored --nocapture \
      | tee "$logfile"
  assert_passed_count "server-core migration matrix" "$logfile" 71

  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test storage \
      --test profiles --test refresh --test authority --test owner_sources --no-run

  logfile="$RUN_DIR/platform-credential-storage.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test storage \
      -- --ignored --nocapture --test-threads=4 | tee "$logfile"
  assert_passed_count "platform credential storage matrix" "$logfile" 21

  logfile="$RUN_DIR/platform-access-profiles.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test profiles \
      -- --ignored --nocapture --test-threads=4 | tee "$logfile"
  assert_passed_count "platform access profile matrix" "$logfile" 14

  logfile="$RUN_DIR/platform-owner-source-authority.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test owner_sources \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "platform owner-source authority matrix" "$logfile" 5

  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib --test access_profiles \
      --test credentials --test environment_external_cleanup --test environment_sources --no-run

  logfile="$RUN_DIR/preview-browser-authorization.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      api::preview::authorization::database_tests:: -- --ignored --nocapture \
      | tee "$logfile"
  assert_passed_count "preview browser authorization matrix" "$logfile" 7

  logfile="$RUN_DIR/public-access-profiles.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --test access_profiles \
      -- --ignored --nocapture --test-threads=4 | tee "$logfile"
  assert_passed_count "public access profile restricted API matrix" "$logfile" 8

  logfile="$RUN_DIR/public-credential-metadata.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --test credentials \
      -- --ignored --nocapture --test-threads=3 | tee "$logfile"
  assert_passed_count "public credential metadata matrix" "$logfile" 3

  logfile="$RUN_DIR/public-credential-mutations.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib mutation::tests:: -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "public credential mutation matrix" "$logfile" 26

  logfile="$RUN_DIR/isolated-credential-runtime.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib runtime::tests:: -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "isolated credential runtime matrix" "$logfile" 4

  logfile="$RUN_DIR/github-repository-discovery.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib repositories::tests::integration:: -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "GitHub repository discovery matrix" "$logfile" 8

  logfile="$RUN_DIR/kind-credential-effective-acl.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib runtime::kind::config::tests::effective_acl_guard_rejects_direct_column_and_membership_authority \
      -- --exact --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "Kind credential effective ACL matrix" "$logfile" 1

  logfile="$RUN_DIR/platform-credential-refresh.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test refresh \
      -- --ignored --nocapture --test-threads=4 | tee "$logfile"
  assert_passed_count "platform credential refresh matrix" "$logfile" 13

  logfile="$RUN_DIR/platform-credential-authority.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-platform-credentials --test authority \
      -- --ignored --nocapture --test-threads=4 | tee "$logfile"
  assert_passed_count "platform credential restricted-role matrix" "$logfile" 10

  logfile="$RUN_DIR/platform-broker-admission.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::tests:: -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "platform broker admission matrix" "$logfile" 14

  logfile="$RUN_DIR/platform-broker-ssh.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-broker --no-default-features \
      --features platform,ssh-agent --lib platform::tests::ssh:: \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "platform broker SSH matrix" "$logfile" 4

  logfile="$RUN_DIR/platform-broker-grpc-rotation.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-broker --no-default-features --features platform \
      --lib platform::bridge::tests::rotation:: -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "platform broker gRPC rotation drain matrix" "$logfile" 3

  logfile="$RUN_DIR/platform-runtime-identity.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service \
      --lib tests::database:: -- --ignored \
      --skip tests::database::projection:: \
      --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "platform runtime restricted identity matrix" "$logfile" 3

  logfile="$RUN_DIR/platform-runtime-projection.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service \
      --lib tests::database::projection:: \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "platform runtime projection matrix" "$logfile" 10

  logfile="$RUN_DIR/owner-local-delegation-authority.log"
  TMPDIR="$RUN_DIR" TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-credential-service --features enrollment \
      --lib delegation::authority::tests:: \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "owner-local delegation authority matrix" "$logfile" 7

  logfile="$RUN_DIR/oauth-bearer-identity.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-server-core --test oauth_bearer_auth \
      -- --ignored --nocapture | tee "$logfile"
  assert_passed_count "OAuth-only restricted identity matrix" "$logfile" 6

  logfile="$RUN_DIR/session-hash-only.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --test session_auth -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::session hash-only matrix skipped"
    return 1
  fi
  assert_passed_count "session hash-only matrix" "$logfile" 4

  logfile="$RUN_DIR/organization-deletion-lifecycle.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --test org_deletion_lifecycle \
      -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::organization deletion lifecycle matrix skipped"
    return 1
  fi
  assert_passed_count "organization deletion lifecycle matrix" "$logfile" 20

  logfile="$RUN_DIR/organization-billing-teardown.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-billing --lib 'billing_teardown::tests::db_' \
      -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::organization billing teardown matrix skipped"
    return 1
  fi
  assert_passed_count "organization billing teardown matrix" "$logfile" 5

  logfile="$RUN_DIR/mesh-authorization-receiver.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-orchestration --lib \
      connect::mesh_authorization::tests::generated_mesh_authorization_service_enforces_the_canonical_matrix \
      -- --ignored --exact --nocapture | tee "$logfile"
  assert_passed_count "Mesh authorization receiver matrix" "$logfile" 1

  logfile="$RUN_DIR/environment-external-cleanup.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-orchestration --test environment_external_cleanup \
      -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::environment external cleanup matrix skipped"
    return 1
  fi
  assert_passed_count "environment external cleanup matrix" "$logfile" 8

  logfile="$RUN_DIR/environment-session-admission.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environment_daemon::session_mutation::tests::db_' \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "environment session admission matrix" "$logfile" 5

  logfile="$RUN_DIR/environment-destroy-template-hint.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      worker::lifecycle::tests::destroy_template_hint_allows_missing_creation_config_but_not_database_failure \
      -- --ignored --exact --nocapture | tee "$logfile"
  assert_passed_count "environment destroy template hint matrix" "$logfile" 1

  logfile="$RUN_DIR/environment-projection-capture.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      'worker::create::projection_database_tests::' \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "environment projection capture matrix" "$logfile" 4

  logfile="$RUN_DIR/organization-tenant-secret-teardown.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-orchestration --lib \
      'worker::tenant_secret_teardown::tests::db_' \
      -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::organization tenant secret teardown matrix skipped"
    return 1
  fi
  assert_passed_count "organization tenant secret teardown matrix" "$logfile" 2

  logfile="$RUN_DIR/encrypted-tenant-secret-store.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-orchestration --lib \
      'worker::postgres_secrets::tests::encrypted_store_reencrypts_renames_and_deletes_final_dek' \
      -- --ignored --exact --nocapture | tee "$logfile"
  assert_passed_count "encrypted tenant secret store matrix" "$logfile" 1

  logfile="$RUN_DIR/mesh-migration-ledger.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-mesh --lib 'store::migration_tests::' \
      -- --ignored --nocapture | tee "$logfile"
  assert_passed_count "Mesh migration ledger" "$logfile" 15

  logfile="$RUN_DIR/environment-source-admission.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --test environment_sources \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "environment source admission matrix" "$logfile" 6

  logfile="$RUN_DIR/admin-startup-summary.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      'api::admin::startup_database_tests::' \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "admin startup summary matrix" "$logfile" 2

  logfile="$RUN_DIR/environment-resize-admission.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environment_resize::tests::db_' \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "environment resize admission matrix" "$logfile" 2

  logfile="$RUN_DIR/ssh-proxy-runtime-lease.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      'api::ssh_proxy::database_tests::' \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "SSH proxy runtime lease matrix" "$logfile" 2

  logfile="$RUN_DIR/environment-daemon-repair-lease.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --locked -p codewire-orchestration --lib \
      'api::environment_daemon::repair_database_tests::' \
      -- --ignored --nocapture --test-threads=1 | tee "$logfile"
  assert_passed_count "environment daemon repair lease matrix" "$logfile" 2

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
  "$RUN_DIR/bin/temporal" server start-dev --headless --ip 127.0.0.1 \
    --port "$TEMPORAL_PORT" --db-filename "$RUN_DIR/temporal.db" \
    > "$RUN_DIR/temporal.log" 2>&1 &
  echo $! > "$RUN_DIR/temporal.pid"
  local _
  for _ in $(seq 1 45); do
    if "$RUN_DIR/bin/temporal" operator cluster health \
        --address "$TEMPORAL_HOST_PORT" >/dev/null 2>&1; then
      log "Temporal ready"
      return
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
    "${docker_network_args[@]}" \
    nats:2.12-alpine -js -m 8222 > "$RUN_DIR/nats.container"
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
  local packages=()
  local orchestration_bins=(
    --bin codewire-orchestration
    --bin log-stream-smoke
  )
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
  fi
  if selected service_orchestration; then
    selected service_temporal && orchestration_bins+=( --bin temporal-smoke )
    cargo_ci build --locked --profile ci -p codewire-cli-bin --bin cw
    cargo_ci build --locked --profile ci -p codewire-orchestration \
      "${orchestration_bins[@]}" --features kind-e2e
  fi
}

run_idp() {
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

  logfile="$RUN_DIR/idp-session-inventory.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test session_inventory -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp session inventory DB tests skipped"
    return 1
  fi
  assert_passed_count "idp session inventory" "$logfile" 7

  logfile="$RUN_DIR/idp-two-factor-replacement.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test two_factor_replacement -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp two-factor replacement DB tests skipped"
    return 1
  fi
  assert_passed_count "idp two-factor replacement" "$logfile" 11

  logfile="$RUN_DIR/idp-rewrap-cli.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-idp --test rewrap_cli -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp rewrap CLI DB test skipped"
    return 1
  fi
  assert_passed_count "idp rewrap CLI" "$logfile" 2

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

start_billing() {
  ensure_billing_fixture
  start_temporal
  start_proc billing "$BILLING_PORT" env \
    DATABASE_URL="$DATABASE_URL_RUST" SESSION_SECRET="$SESSION_SECRET" \
    BILLING_PORT="$BILLING_PORT" BILLING_LOOPS= \
    FRONTEND_URL="http://127.0.0.1:${BILLING_PORT}" \
    STRIPE_SECRET_KEY=sk_test_buildtest_dummy \
    STRIPE_WEBHOOK_SECRET=whsec_test_secret \
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
                self.json_response({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": runtime["pod_name"],
                        "namespace": namespace,
                        "uid": runtime["pod_uid"],
                    },
                    "spec": {
                        "containers": [],
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

  start_proc orchestration "$ORCHESTRATION_PORT" env \
    KUBECONFIG="$kubeconfig" \
    KUBERNETES_SERVICE_HOST= KUBERNETES_SERVICE_PORT= \
    DATABASE_URL="$DATABASE_URL_RUST" SESSION_SECRET="$SESSION_SECRET" \
    CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER=true \
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
  probe_connect_surface orchestration "$ORCHESTRATION_PORT"
}

run_orchestration() {
  local logfile="$RUN_DIR/orchestration-activity-fencing.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo_ci test --profile ci -p codewire-orchestration --lib \
      'worker::' -- --ignored \
      --skip 'worker::postgres_secrets::tests::encrypted_store_reencrypts_renames_and_deletes_final_dek' \
      --skip 'worker::lifecycle::tests::destroy_template_hint_allows_missing_creation_config_but_not_database_failure' \
      --skip 'worker::create::projection_database_tests::' \
      --nocapture | tee "$logfile"
  assert_passed_count "orchestration activity fencing matrix" "$logfile" 2

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
  assert_passed_count "Connect auth matrix" "$logfile" 5
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

run_services() {
  reset_schema
  if selected service_apikey_smoke; then
    scripts/runtime/tests/test-apikey-smoke.sh
  fi
  build_selected_services
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

case "$MODE" in
  database)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    run_database
    ;;
  services-control)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    SELECTION="$(filter_service_selection \
      service_apikey_smoke service_idp service_coordinator service_billing \
      service_connectcore service_temporal)"
    run_services
    ;;
  services-runtime)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    SELECTION="$(filter_service_selection \
      service_orchestration service_nats service_temporal)"
    run_services
    ;;
  *)
    echo "usage: run-integration-verification.sh database|services-control|services-runtime" >&2
    exit 2
    ;;
esac

log "green"
