#!/usr/bin/env bash
# Bounded database and per-service verification extracted from the all-up
# Rust stack rehearsal. A reachable disposable Postgres is required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MODE="${1:-}"
SELECTION="${VERIFICATION_SELECTION:-|valid:v2|complete|}"
export CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
CARGO_CI_DIR="$CARGO_TARGET_DIR/ci"
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
TEMPORAL_HOST_PORT="127.0.0.1:${TEMPORAL_PORT}"
NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT}"
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

dump_logs() {
  local name
  for name in idp coordinator billing orchestration \
      orchestration-kube-stub temporal nats; do
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
  cargo build --locked --profile ci -p codewire-server-core --bin codewire-db-migrate
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;'
  DATABASE_URL="$DATABASE_URL_RUST" "$CARGO_CI_DIR/codewire-db-migrate"
}

run_database() {
  local logfile
  reset_schema

  logfile="$RUN_DIR/server-core-migrate.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --lib migrate:: -- --ignored --nocapture \
      | tee "$logfile"
  assert_passed_count "server-core migration matrix" "$logfile" 5

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
  assert_passed_count "organization deletion lifecycle matrix" "$logfile" 17

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
    cargo test --profile ci -p codewire-orchestration --lib \
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
  assert_passed_count "environment external cleanup matrix" "$logfile" 3

  logfile="$RUN_DIR/organization-tenant-secret-teardown.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-orchestration --lib \
      'worker::tenant_secret_teardown::tests::db_' \
      -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::organization tenant secret teardown matrix skipped"
    return 1
  fi
  assert_passed_count "organization tenant secret teardown matrix" "$logfile" 4

  logfile="$RUN_DIR/mesh-migration-ledger.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-mesh --lib 'store::migration_tests::' \
      -- --ignored --nocapture | tee "$logfile"
  assert_passed_count "Mesh migration ledger" "$logfile" 5

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
  docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$NATS_CONTAINER" --pids-limit 2048 \
    -p "127.0.0.1:${NATS_CLIENT_PORT}:4222" \
    -p "127.0.0.1:${NATS_MONITOR_PORT}:8222" \
    nats:2.12-alpine -js -m 8222 > "$RUN_DIR/nats.container"
  touch "$RUN_DIR/nats.started"
  local _
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${NATS_MONITOR_PORT}/healthz" >/dev/null 2>&1; then
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
  local orchestration_bins=( --bin codewire-orchestration --bin log-stream-smoke )
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
    cargo build --locked --profile ci "${packages[@]}"
  fi
  if selected service_orchestration; then
    selected service_temporal && orchestration_bins+=( --bin temporal-smoke )
    cargo build --locked --profile ci -p codewire-orchestration \
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
    cargo test --profile ci -p codewire-idp --test db_flow -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp db_flow skipped"
    return 1
  fi
  assert_passed_count "idp db_flow" "$logfile" 12

  logfile="$RUN_DIR/idp-rewrap-cli.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --profile ci -p codewire-idp --test rewrap_cli -- --nocapture \
    | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp rewrap CLI DB test skipped"
    return 1
  fi
  assert_passed_count "idp rewrap CLI" "$logfile" 2

}

run_coordinator() {
  local logfile="$RUN_DIR/coordinator-protocol-auth.log"
  DATABASE_URL="$DATABASE_URL_RUST" cargo test --profile ci \
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
    COORDINATOR_PORT="$COORDINATOR_PORT" COORDINATOR_SERVE_CONNECT=1 \
    CODEWIRE_API_URL="http://127.0.0.1:${COORDINATOR_PORT}" NATS_URL= \
    ENVIRONMENT=local "$CARGO_CI_DIR/codewire-coordinator"
  wait_http coordinator-ready "http://127.0.0.1:${COORDINATOR_PORT}/readyz" \
    "$RUN_DIR/coordinator.pid"
  COORDINATOR_BASE_URL="http://127.0.0.1:${COORDINATOR_PORT}" \
    COORDINATOR_SEEDED=1 \
    COORDINATOR_USER_SESSION_TOKEN=coordinator-contract-session-token \
    COORDINATOR_SESSION_SECRET="$SESSION_SECRET" \
    cargo test --locked --profile ci -p codewire-coordinator \
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
      BILLING_FRONTEND_URL="http://127.0.0.1:${BILLING_PORT}" \
      BILLING_ADMIN_SESSION_TOKEN=contract-admin-session-token \
      BILLING_USER_SESSION_TOKEN=contract-user-session-token BILLING_SEEDED=1 \
      BILLING_STRIPE_CONFIGURED=1 \
      cargo test --locked --profile ci -p codewire-billing \
        --test wire_contract configured_billing_wire_contract \
        -- --ignored --exact --nocapture | tee "$RUN_DIR/billing-contract.log"
    assert_passed_count \
      "configured Rust billing wire contract" "$RUN_DIR/billing-contract.log" 1
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

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def empty_response(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

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

start_orchestration_process() {
  local kube_mode="$1" kubeconfig anthropic_api_key
  case "$kube_mode" in
    configured)
      kubeconfig="$(write_orchestration_kubeconfig)"
      anthropic_api_key=contract-test-key
      ;;
    unconfigured)
      kubeconfig="$RUN_DIR/orchestration-deliberately-missing-kubeconfig"
      rm -f "$kubeconfig"
      anthropic_api_key=
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
    ORCHESTRATION_PORT="$ORCHESTRATION_PORT" \
    ANTHROPIC_API_KEY="$anthropic_api_key" \
    TEMPORAL_HOST_PORT="$TEMPORAL_HOST_PORT" WORKER_CONSUMERS= WORKER_LOOPS= \
    CONNECT_TESTING_SURFACE=1 "$CARGO_CI_DIR/codewire-orchestration"
}

start_orchestration() {
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
    -f "$ROOT/tests/fixtures/orchestration/seed.sql"
  start_temporal
  start_orchestration_kube_stub
  start_orchestration_process configured
  probe_connect_surface orchestration "$ORCHESTRATION_PORT"
}

run_orchestration() {
  local logfile="$RUN_DIR/orchestration-activity-fencing.log"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --profile ci -p codewire-orchestration --lib \
      'worker::' -- --ignored --nocapture | tee "$logfile"
  assert_passed_count "orchestration activity fencing matrix" "$logfile" 2

  start_orchestration
  logfile="$RUN_DIR/orchestration-contract.log"
  ORCHESTRATION_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
    ORCHESTRATION_GLOBAL_ADMIN_SESSION_TOKEN=orchestration-global-admin-session-token \
    ORCHESTRATION_ADMIN_SESSION_TOKEN=apikey-contract-admin-session-token \
    ORCHESTRATION_USER_SESSION_TOKEN=apikey-contract-user-session-token \
    ORCHESTRATION_SEEDED=1 ORCHESTRATION_KUBE_MODE=configured \
    ORCHESTRATION_CONTRACT_SCOPE=complete \
    cargo test --locked --profile ci -p codewire-orchestration \
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
  start_orchestration_process unconfigured
  logfile="$RUN_DIR/orchestration-kube-unconfigured-contract.log"
  ORCHESTRATION_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
    ORCHESTRATION_GLOBAL_ADMIN_SESSION_TOKEN=orchestration-global-admin-session-token \
    ORCHESTRATION_ADMIN_SESSION_TOKEN=apikey-contract-admin-session-token \
    ORCHESTRATION_USER_SESSION_TOKEN=apikey-contract-user-session-token \
    ORCHESTRATION_SEEDED=1 ORCHESTRATION_KUBE_MODE=unconfigured \
    ORCHESTRATION_CONTRACT_SCOPE=runtime \
    cargo test --locked --profile ci -p codewire-orchestration \
      --test wire_contract --features kind-e2e \
      configured_orchestration_wire_contract -- \
      --ignored --exact --nocapture | tee "$logfile"
  assert_passed_count "Rust orchestration kube-unconfigured contract" "$logfile" 1
}

run_connect_auth_matrix() {
  local logfile="$RUN_DIR/connect-auth.log"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test --profile ci -p codewire-server-core --test connect_auth \
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
INSERT INTO environment_presets (id, org_id, name, slug)
VALUES (
  'preset_temporal_verification',
  'org_apikey_contract_1',
  'Temporal Verification',
  'temporal-verification'
);
INSERT INTO environments (
  id, org_id, created_by, type, state, desired_state,
  cpu_millicores, memory_mb, disk_gb, preset_id
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
  'preset_temporal_verification'
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
  NATS_URL="$NATS_URL" cargo test --profile ci -p codewire-coordinator \
    --lib coordination_plane_round_trips_nats_and_kv -- --ignored --nocapture \
    | tee "$logfile"
  assert_passed_count "coordinator NATS/KV smoke" "$logfile" 1
  logfile="$RUN_DIR/coordinator-mixed-transport.log"
  NATS_URL="$NATS_URL" cargo test --profile ci -p codewire-coordinator \
    --lib mixed_transport_cross_replica_fanout_round_trips_over_nats \
    -- --ignored --nocapture | tee "$logfile"
  assert_passed_count "coordinator mixed-transport smoke" "$logfile" 1
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

case "$MODE" in
  database)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    run_database
    ;;
  services)
    integration_postgres_configure
    log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
    run_services
    ;;
  *)
    echo "usage: run-integration-verification.sh database|services" >&2
    exit 2
    ;;
esac

log "green"
