#!/usr/bin/env bash
# Full Rust product-stack rehearsal.
#
# Uses an explicitly supplied Postgres or starts a disposable local one, and
# expects the standard Go/Rust toolchains. The caller is responsible for
# installing OS tools such as psql, protoc, jq, curl, and docker. The script
# starts the Rust product services, then runs the contract, idp DB, NATS, and
# Temporal smoke gates.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
CARGO_TARGET_DIR="$(
  "$ROOT/scripts/ci/verify/resolve-cargo-target-dir.sh" "$ROOT"
)"
export CARGO_TARGET_DIR
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
select_local_rust_cache "$ROOT" || true
CARGO_CI_DIR="$CARGO_TARGET_DIR/ci"
RUN_DIR="${RUN_DIR:-$ROOT/.tmp/codewire-rust-stack-rehearsal}"
mkdir -p "$RUN_DIR/bin"

# Synthetic, local-only idp signing keyring. Reproduce kubelet's Secret
# atomic-writer layout so the real idp boot covers its sticky mount root and
# confined `..data` indirection. The rehearsal must never depend on a
# dev/production Secret value or silently skip the real idp boot.
IDP_SIGNING_KEK_DIR="$RUN_DIR/idp-signing-keks-${GITHUB_RUN_ID:-local-$$}"
IDP_SIGNING_ACTIVE_KEK_ID=v1
IDP_SIGNING_KEK_REVISION="..synthetic-${GITHUB_RUN_ID:-local-$$}"
install -d -m 1777 "$IDP_SIGNING_KEK_DIR"
install -d -m 755 "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_KEK_REVISION"
printf '%s' '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' \
  > "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_KEK_REVISION/$IDP_SIGNING_ACTIVE_KEK_ID"
chmod 644 "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_KEK_REVISION/$IDP_SIGNING_ACTIVE_KEK_ID"
ln -s "$IDP_SIGNING_KEK_REVISION" "$IDP_SIGNING_KEK_DIR/..data"
ln -s "..data/$IDP_SIGNING_ACTIVE_KEK_ID" \
  "$IDP_SIGNING_KEK_DIR/$IDP_SIGNING_ACTIVE_KEK_ID"
export IDP_SIGNING_KEK_DIR IDP_SIGNING_ACTIVE_KEK_ID

DATABASE_URL_EXPLICIT=false
DATABASE_URL_RUST_EXPLICIT=false
[[ -v DATABASE_URL ]] && DATABASE_URL_EXPLICIT=true
[[ -v DATABASE_URL_RUST ]] && DATABASE_URL_RUST_EXPLICIT=true
DATABASE_URL="${DATABASE_URL-}"
DATABASE_URL_RUST="${DATABASE_URL_RUST-}"
SESSION_SECRET="${SESSION_SECRET:-build-test-not-a-real-secret-padded}"
TEMPORAL_HOST_PORT="${TEMPORAL_HOST_PORT:-127.0.0.1:7233}"
TEMPORAL_PORT="${TEMPORAL_PORT:-${TEMPORAL_HOST_PORT##*:}}"
NATS_URL="${NATS_URL:-nats://127.0.0.1:4222}"
NATS_CLIENT_PORT="${NATS_CLIENT_PORT:-${NATS_URL##*:}}"
NATS_MONITOR_PORT="${NATS_MONITOR_PORT:-8222}"
NATS_CONTAINER="${NATS_CONTAINER:-codewire-ci-nats-${GITHUB_RUN_ID:-local-$$}}"
STARTED_NATS_CONTAINER=0
export PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-5}"
export TZ=UTC

# shellcheck source=scripts/ci/verify/integration-postgres.sh
source "$ROOT/scripts/ci/verify/integration-postgres.sh"
integration_postgres_init

RUST_COORD_PORT="${RUST_COORD_PORT:-8091}"
BILLING_PORT="${BILLING_PORT:-8081}"
BILLING_WEBHOOK_PORT="${BILLING_WEBHOOK_PORT:-8082}"
ORCHESTRATION_PORT="${ORCHESTRATION_PORT:-8084}"
DERP_PORT="${DERP_PORT:-8086}"
IDP_PORT="${IDP_PORT:-8087}"
REHEARSAL_PORT_BLOCK_STRIDE="${REHEARSAL_PORT_BLOCK_STRIDE:-16}"

log() {
  printf '[rust-stack] %s\n' "$*"
}

dump_logs() {
  for name in idp rust-coord derp billing billing-webhook orchestration temporal-server nats; do
    if [ -f "$RUN_DIR/${name}.log" ]; then
      echo "--- ${name}.log ---"
      tail -200 "$RUN_DIR/${name}.log" || true
    fi
  done
}

cleanup() {
  for pidfile in "$RUN_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    kill "$(cat "$pidfile")" 2>/dev/null || true
  done
  rm -rf -- "$IDP_SIGNING_KEK_DIR"
  if [ "${STARTED_NATS_CONTAINER:-0}" = "1" ]; then
    docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  fi
  integration_postgres_cleanup
}

on_exit() {
  status=$?
  if [ "$status" -ne 0 ]; then
    dump_logs
  fi
  cleanup
  exit "$status"
}
trap on_exit EXIT

wait_http() {
  local name="$1" url="$2" pidfile="${3:-}"
  for i in $(seq 1 45); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "$name up after ${i}s"
      return 0
    fi
    if [ -n "$pidfile" ] && [ -f "$pidfile" ] && ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
      echo "::error::${name} exited before ${url} responded"
      return 1
    fi
    sleep 1
  done
  echo "::error::${name} did not become ready at ${url}"
  return 1
}

run_go_no_skip() {
  local label="$1" logfile="$2"
  shift 2
  timeout "${RUN_GO_NO_SKIP_TIMEOUT:-12m}" "$@" | tee "$logfile"
  if grep -E -- '--- SKIP' "$logfile"; then
    echo "::error::${label} skipped; bootstrap or env wiring is broken"
    return 1
  fi
}

assert_passed_count() {
  local label="$1" logfile="$2" expected="$3" count
  count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$count" != "$expected" ]]; then
    echo "::error::${label} reported ${count:-no} passing tests; expected ${expected}"
    return 1
  fi
}

run_idp_db_flow() {
  local logfile="$RUN_DIR/idp-db-flow.log"
  log "running codewire-idp DB flow"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-idp --test db_flow -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp db_flow reported DATABASE_URL unset"
    return 1
  fi
  local passed_count
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "13" ]]; then
    echo "::error::idp db_flow did not report its 13 passing DB-backed tests"
    return 1
  fi

  logfile="$RUN_DIR/idp-rewrap-cli.log"
  log "running codewire-idp signing KEK rewrap CLI"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-idp --test rewrap_cli -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::idp rewrap CLI DB test reported DATABASE_URL unset"
    return 1
  fi
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "2" ]]; then
    echo "::error::idp rewrap CLI did not report its 2 passing tests"
    return 1
  fi
}

run_migration_matrix() {
  local logfile="$RUN_DIR/server-core-migrate.log"
  log "running standard SQLx application migration tests"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --lib migrate:: -- --ignored --nocapture \
      | tee "$logfile"
  local passed_count
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "17" ]]; then
    echo "::error::server-core migration matrix did not report its 17 passing tests"
    return 1
  fi
}

run_session_hash_only_matrix() {
  local logfile="$RUN_DIR/session-hash-only.log"
  log "running server-core session hash-only matrix"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --test session_auth -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::session hash-only matrix reported DATABASE_URL unset"
    return 1
  fi
  local passed_count
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "4" ]]; then
    echo "::error::session hash-only matrix did not report its 4 passing tests"
    return 1
  fi
}

run_mesh_migration_ledger() {
  local logfile="$RUN_DIR/mesh-migration-ledger.log"
  log "running codewire-mesh migration ledger tests"
  TEST_DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-mesh --lib 'store::migration_tests::' \
      -- --ignored --nocapture | tee "$logfile"
  local passed_count
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "15" ]]; then
    echo "::error::Mesh migration ledger did not execute exactly 15 DB-backed tests"
    return 1
  fi
}

# Connect probe smoke (codewire/plans:connect-rpc/03, WI-3): a binary started
# with CONNECT_TESTING_SURFACE=1 must answer Connect JSON on the D8 probe —
# PublicPing without a credential, Ping with the seeded contract session
# cookie — through the same port that serves REST. The Rust shared serving-
# stack matrix supplies the full wire-shape coverage.
probe_connect_surface() {
  local name="$1" port="$2" body
  body="$(curl -fsS -X POST -H 'content-type: application/json' -d '{}' \
    "http://127.0.0.1:${port}/codewire.testing.v1.PingService/PublicPing")" || {
    echo "::error::${name}: Connect probe PublicPing failed"
    return 1
  }
  if [ "$body" != '{"message":"public pong"}' ]; then
    echo "::error::${name}: unexpected PublicPing body: ${body}"
    return 1
  fi
  body="$(curl -fsS -X POST -H 'content-type: application/json' \
    -H 'cookie: codewire.session_token=contract-user-session-token' \
    -d '{"message":"probe"}' \
    "http://127.0.0.1:${port}/codewire.testing.v1.PingService/Ping")" || {
    echo "::error::${name}: Connect probe authenticated Ping failed"
    return 1
  }
  if [ "$body" != '{"message":"probe"}' ]; then
    echo "::error::${name}: unexpected Ping body: ${body}"
    return 1
  fi
  log "${name}: Connect probe surface OK"
}

# Connect auth-layer acceptance matrix (codewire/plans:connect-rpc/03, WI-2):
# session cookie / cw_ API key / OIDC bearer admission plus raw session-bearer
# rejection through ConnectAuthLayer, rejection wire shapes, admin mount, and
# allowlist bypass.
# The suite skips silently without DATABASE_URL, so this runner — like
# run_idp_db_flow — fails hard if it skipped instead of executing.
run_connect_auth_matrix() {
  local logfile="$RUN_DIR/connect-auth.log"
  log "running codewire-server-core Connect auth matrix"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-server-core --test connect_auth -- --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::Connect auth matrix reported DATABASE_URL unset"
    return 1
  fi
  local passed_count
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "5" ]]; then
    echo "::error::Connect auth matrix did not report its 5 passing DB-backed tests"
    return 1
  fi
}

# Coordinator D9 production-auth parity: the real ProductionAuthorizer and
# shared credential stack must produce identical Connect/native-gRPC outcomes,
# including an org-A API key being denied against org B. This DB-backed test
# also skips without DATABASE_URL, so fail hard on the sentinel or wrong count.
run_coordinator_protocol_auth_matrix() {
  local logfile="$RUN_DIR/coordinator-protocol-auth.log"
  log "running coordinator Connect/native-gRPC production auth matrix"
  DATABASE_URL="$DATABASE_URL_RUST" \
    cargo test -p codewire-coordinator --lib \
      connect::tests::production_user_credentials_match_for_connect_and_grpc \
      -- --exact --nocapture | tee "$logfile"
  if grep -q 'DATABASE_URL unset' "$logfile"; then
    echo "::error::coordinator protocol auth matrix reported DATABASE_URL unset"
    return 1
  fi
  local passed_count
  passed_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$logfile" | tail -n 1)"
  if [[ "$passed_count" != "1" ]]; then
    echo "::error::coordinator protocol auth matrix did not report its DB-backed test"
    return 1
  fi
}

docker_host_port() {
  local container="$1" container_port="$2" mapping port
  mapping="$(docker port "$container" "${container_port}/tcp" | head -n1 || true)"
  port="${mapping##*:}"
  if [ -z "$mapping" ] || [ "$port" = "$mapping" ]; then
    echo "::error::could not resolve ${container_port}/tcp host port for ${container}"
    return 1
  fi
  printf '%s\n' "$port"
}

start_nats() {
  if [ "${REHEARSAL_USE_EXISTING_NATS:-0}" = "1" ]; then
    if curl -fsS "http://127.0.0.1:${NATS_MONITOR_PORT}/healthz" >/dev/null 2>&1; then
      log "using existing NATS at ${NATS_URL}"
      return 0
    fi
    echo "::error::REHEARSAL_USE_EXISTING_NATS=1 but NATS is not healthy at 127.0.0.1:${NATS_MONITOR_PORT}"
    return 1
  fi

  log "starting private NATS JetStream"
  docker rm -f "$NATS_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$NATS_CONTAINER" --pids-limit 2048 \
    -p "127.0.0.1::4222" \
    -p "127.0.0.1::8222" \
    nats:2.12-alpine -js -m 8222 \
    > "$RUN_DIR/nats.container"
  STARTED_NATS_CONTAINER=1

  NATS_CLIENT_PORT="$(docker_host_port "$NATS_CONTAINER" 4222)"
  NATS_MONITOR_PORT="$(docker_host_port "$NATS_CONTAINER" 8222)"
  NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT}"
  export NATS_CLIENT_PORT NATS_MONITOR_PORT NATS_URL
  log "private NATS mapped to ${NATS_URL} with monitor 127.0.0.1:${NATS_MONITOR_PORT}"

  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${NATS_MONITOR_PORT}/healthz" >/dev/null 2>&1; then
      log "nats up"
      return 0
    fi
    sleep 1
  done
  docker logs "$NATS_CONTAINER" > "$RUN_DIR/nats.log" 2>&1 || true
  echo "::error::NATS did not become healthy"
  return 1
}

install_temporal() {
  local version="${TEMPORAL_CLI_VERSION:-1.5.0}"
  if [ -x "$RUN_DIR/bin/temporal" ]; then
    return 0
  fi
  log "installing Temporal CLI ${version}"
  (
    cd "$RUN_DIR"
    curl -fsSLO "https://github.com/temporalio/cli/releases/download/v${version}/temporal_cli_${version}_linux_amd64.tar.gz"
    curl -fsSLO "https://github.com/temporalio/cli/releases/download/v${version}/checksums.txt"
    grep "temporal_cli_${version}_linux_amd64.tar.gz" checksums.txt | sha256sum -c -
    tar -xzf "temporal_cli_${version}_linux_amd64.tar.gz" temporal
    install temporal "$RUN_DIR/bin/temporal"
  )
}

temporal_health() {
  timeout "${TEMPORAL_HEALTH_TIMEOUT:-3s}" \
    "$RUN_DIR/bin/temporal" operator cluster health --address "$TEMPORAL_HOST_PORT" \
    >/dev/null 2>&1
}

start_temporal() {
  install_temporal
  if temporal_health; then
    log "temporal already up"
    return 0
  fi
  log "starting Temporal dev server"
  rm -f "$RUN_DIR"/temporal-dev.db*
  "$RUN_DIR/bin/temporal" server start-dev --headless --ip 127.0.0.1 --port "$TEMPORAL_PORT" \
    --db-filename "$RUN_DIR/temporal-dev.db" > "$RUN_DIR/temporal-server.log" 2>&1 &
  echo $! > "$RUN_DIR/temporal-server.pid"
  for _ in $(seq 1 45); do
    if temporal_health; then
      log "temporal up"
      return 0
    fi
    if ! kill -0 "$(cat "$RUN_DIR/temporal-server.pid")" 2>/dev/null; then
      echo "::error::Temporal dev server exited before becoming healthy"
      return 1
    fi
    sleep 1
  done
  echo "::error::Temporal dev server did not become healthy"
  return 1
}

start_proc() {
  local name="$1" port="$2"
  shift 2
  log "starting $name"
  "$@" > "$RUN_DIR/${name}.log" 2>&1 &
  echo $! > "$RUN_DIR/${name}.pid"
  wait_http "$name" "http://127.0.0.1:${port}/healthz" "$RUN_DIR/${name}.pid"
}

stop_proc() {
  local name="$1" pidfile
  pidfile="$RUN_DIR/${name}.pid"
  if [ ! -f "$pidfile" ]; then
    return 0
  fi
  kill "$(cat "$pidfile")" 2>/dev/null || true
  wait "$(cat "$pidfile")" 2>/dev/null || true
  rm -f "$pidfile"
}

default_rehearsal_port_base() {
  case "${GITHUB_RUN_ID:-}" in
    ''|*[!0-9]*)
      printf '%s\n' "$((BILLING_PORT - 1))"
      ;;
    *)
      local floor=61000 width slots
      width="$REHEARSAL_PORT_BLOCK_STRIDE"
      slots=$((((65535 - floor - 9) / width) + 1))
      printf '%s\n' "$((floor + ((GITHUB_RUN_ID % slots) * width)))"
      ;;
  esac
}

find_free_port_block() {
  local start="$1" count="$2" stride="$3" python_bin
  python_bin="$(command -v python3 || command -v python || true)"
  if [ -z "$python_bin" ]; then
    echo "::warning::python is unavailable; skipping rehearsal port collision preflight" >&2
    printf '%s\n' "$start"
    return 0
  fi
  "$python_bin" - "$start" "$count" "$stride" <<'PY'
import socket
import sys

start = max(1024, int(sys.argv[1]))
count = int(sys.argv[2])
stride = max(1, int(sys.argv[3]))
limit = 65535 - count

for base in range(start, limit + 1, stride):
    sockets = []
    try:
        for offset in range(1, count + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", base + offset))
            sockets.append(sock)
        print(base)
        sys.exit(0)
    except OSError:
        for sock in sockets:
            sock.close()

print(f"no free block of {count} ports found starting at {start}", file=sys.stderr)
sys.exit(1)
PY
}

configure_port_block() {
  if [ "${REHEARSAL_AUTO_PORT_BLOCK:-1}" = "0" ]; then
    return 0
  fi

  local current_base chosen_base
  current_base="${REHEARSAL_PORT_BASE:-$(default_rehearsal_port_base)}"
  chosen_base="$(find_free_port_block "$current_base" 9 "$REHEARSAL_PORT_BLOCK_STRIDE")"
  if [ "$chosen_base" != "$current_base" ]; then
    log "rehearsal port block starting at ${current_base} is busy; using ${chosen_base}"
  else
    log "using rehearsal port block starting at ${chosen_base}"
  fi

  BILLING_PORT=$((chosen_base + 1))
  BILLING_WEBHOOK_PORT=$((chosen_base + 2))
  ORCHESTRATION_PORT=$((chosen_base + 3))
  RUST_COORD_PORT=$((chosen_base + 4))
  TEMPORAL_PORT=$((chosen_base + 5))
  TEMPORAL_HOST_PORT="127.0.0.1:${TEMPORAL_PORT}"
  NATS_CLIENT_PORT=$((chosen_base + 6))
  NATS_MONITOR_PORT=$((chosen_base + 7))
  DERP_PORT=$((chosen_base + 8))
  IDP_PORT=$((chosen_base + 9))
  NATS_URL="nats://127.0.0.1:${NATS_CLIENT_PORT}"
  export BILLING_PORT BILLING_WEBHOOK_PORT ORCHESTRATION_PORT
  export RUST_COORD_PORT TEMPORAL_PORT TEMPORAL_HOST_PORT DERP_PORT IDP_PORT
  export NATS_CLIENT_PORT NATS_MONITOR_PORT NATS_URL
}

configure_port_block

integration_postgres_configure
log "PostgreSQL source=${INTEGRATION_POSTGRES_SOURCE}"
log "resetting postgres schema"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;'

log "building binaries"
(
  cd "$ROOT"
  cargo build --profile ci -p codewire-server-core --bin codewire-db-migrate
  cargo build --profile ci -p codewire-coordinator --bin codewire-coordinator
  cargo build --profile ci -p codewire-idp --bin codewire-idp
  cargo build --profile ci -p codewire-billing
  cargo build --profile ci -p codewire-orchestration \
    --bin codewire-orchestration --bin deploy-shape-smoke --features kind-e2e
  cargo build --profile ci -p codewire-derp --bin codewire-derp
)

log "applying standard SQLx application baseline"
DATABASE_URL="$DATABASE_URL_RUST" "$CARGO_CI_DIR/codewire-db-migrate"

run_idp_db_flow

run_session_hash_only_matrix

run_connect_auth_matrix

run_coordinator_protocol_auth_matrix

run_migration_matrix

run_mesh_migration_ledger

start_proc idp "$IDP_PORT" env \
  DATABASE_URL="$DATABASE_URL_RUST" \
  SESSION_SECRET="$SESSION_SECRET" \
  IDP_PORT="$IDP_PORT" \
  PUBLIC_OIDC_ISSUER_URL="http://127.0.0.1:${IDP_PORT}" \
  FRONTEND_URL="http://127.0.0.1:${IDP_PORT}" \
  IDP_SIGNING_KEK_DIR="$IDP_SIGNING_KEK_DIR" \
  IDP_SIGNING_ACTIVE_KEK_ID="$IDP_SIGNING_ACTIVE_KEK_ID" \
  RUST_LOG=info \
  "$CARGO_CI_DIR/codewire-idp"
curl -fsS "http://127.0.0.1:${IDP_PORT}/.well-known/jwks.json" \
  | jq -e '.keys | length >= 1' >/dev/null
kill "$(cat "$RUN_DIR/idp.pid")" 2>/dev/null || true
rm -f "$RUN_DIR/idp.pid"

log "seeding coordinator Connect contract fixture"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f "$ROOT/tests/fixtures/coordinator/seed.sql"
if [[ "$(psql "$DATABASE_URL" -Atqc \
    "SELECT count(*) FROM sessions WHERE id = 'ses_coordinator_contract' AND token_hash = encode(digest('coordinator-contract-session-token', 'sha256'), 'hex')")" != "1" ]]; then
  echo "::error::coordinator contract session fixture is not hash-only"
  exit 1
fi

start_proc rust-coord "$RUST_COORD_PORT" env \
  DATABASE_URL="$DATABASE_URL_RUST" \
  SESSION_SECRET="$SESSION_SECRET" \
  COORDINATOR_PORT="$RUST_COORD_PORT" \
  CODEWIRE_API_URL="http://127.0.0.1:${RUST_COORD_PORT}" \
  NATS_URL= \
  ENVIRONMENT=local \
  RUST_LOG=info \
  "$CARGO_CI_DIR/codewire-coordinator"
wait_http rust-coord-ready "http://127.0.0.1:${RUST_COORD_PORT}/readyz" "$RUN_DIR/rust-coord.pid"

log "running Rust coordinator wire contract"
COORDINATOR_BASE_URL="http://127.0.0.1:${RUST_COORD_PORT}" \
  COORDINATOR_SEEDED=1 \
  COORDINATOR_USER_SESSION_TOKEN=coordinator-contract-session-token \
  COORDINATOR_SESSION_SECRET="$SESSION_SECRET" \
  cargo test --locked --profile ci -p codewire-coordinator \
    --test wire_contract configured_coordinator_wire_contract -- \
    --ignored --exact --nocapture | tee "$RUN_DIR/coordinator-contract.log"
assert_passed_count \
  "Rust coordinator wire contract" "$RUN_DIR/coordinator-contract.log" 1

kill "$(cat "$RUN_DIR/rust-coord.pid")" 2>/dev/null || true
rm -f "$RUN_DIR/rust-coord.pid"

start_proc derp "$DERP_PORT" env \
  PORT="$DERP_PORT" \
  TLS_PORT= \
  STUN_PORT=-1 \
  RUST_LOG=info \
  "$CARGO_CI_DIR/codewire-derp"

log "running DERP contract suite against Rust"
(
  cd "$ROOT/tests/contract"
  run_go_no_skip "DERP raw HTTP Go-client interop" "$RUN_DIR/derp-contract.log" \
    env DERP_BASE_URL="http://127.0.0.1:${DERP_PORT}/derp" GOWORK=off \
    go test -count=1 -v -run '^TestRawHTTPUpgradeRelaysTailscaleGoClients$' ./derp/...
  run_go_no_skip "DERP WebSocket Go-client interop" "$RUN_DIR/derp-websocket-contract.log" \
    env DERP_BASE_URL="http://127.0.0.1:${DERP_PORT}/derp" DERP_WEBSOCKET=1 \
    GOWORK=off go test -tags ts_debug_websockets -count=1 -v \
      -run '^TestWebSocketFallbackRelaysTailscaleGoClients$' ./derp/...
)

kill "$(cat "$RUN_DIR/derp.pid")" 2>/dev/null || true
rm -f "$RUN_DIR/derp.pid"

log "seeding billing contract fixture"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$ROOT/tests/fixtures/billing/seed.sql"
if [[ "$(psql "$DATABASE_URL" -Atqc \
    "SELECT count(*) FROM sessions WHERE id IN ('ses_contract_admin', 'ses_contract_user', 'ses_contract_stale') AND token_hash IN (encode(digest('contract-admin-session-token', 'sha256'), 'hex'), encode(digest('contract-user-session-token', 'sha256'), 'hex'), encode(digest('contract-stale-session-token', 'sha256'), 'hex'))")" != "3" ]]; then
  echo "::error::billing contract session fixtures are not hash-only"
  exit 1
fi

set -a
# shellcheck source=../../tests/e2e/flip-state.env
# shellcheck disable=SC1091
. "$ROOT/tests/e2e/flip-state.env"
set +a

start_proc billing "$BILLING_PORT" env \
  DATABASE_URL="$DATABASE_URL_RUST" \
  SESSION_SECRET="$SESSION_SECRET" \
  BILLING_PORT="$BILLING_PORT" \
  BILLING_LOOPS="${BILLING_LOOPS:-}" \
  FRONTEND_URL="http://127.0.0.1:${BILLING_PORT}" \
  STRIPE_SECRET_KEY=sk_test_buildtest_dummy \
  STRIPE_WEBHOOK_SECRET=whsec_test_secret \
  TEMPORAL_HOST_PORT="$TEMPORAL_HOST_PORT" \
  CONNECT_TESTING_SURFACE=1 \
  "$CARGO_CI_DIR/codewire-billing"

probe_connect_surface billing "$BILLING_PORT"

log "running configured Rust billing Connect contract"
(
  cd "$ROOT"
  BILLING_BASE_URL="http://127.0.0.1:${BILLING_PORT}" \
    BILLING_ADMIN_SESSION_TOKEN=contract-admin-session-token \
    BILLING_USER_SESSION_TOKEN=contract-user-session-token \
    BILLING_SEEDED=1 \
    cargo test --locked --profile ci -p codewire-billing \
      --test wire_contract configured_billing_wire_contract \
      -- --ignored --exact --nocapture | tee "$RUN_DIR/billing-contract.log"
  passed_count="$(sed -nE \
    's/.*test result: ok\\. ([0-9]+) passed.*/\\1/p' \
    "$RUN_DIR/billing-contract.log" | tail -n 1)"
  if [ "$passed_count" != "1" ]; then
    echo "::error::configured Rust billing Connect contract reported ${passed_count:-no} passing tests; expected 1"
    exit 1
  fi
)

start_nats

log "running Rust coordinator NATS/KV smoke"
NATS_URL="$NATS_URL" \
  cargo test -p codewire-coordinator coordination_plane_round_trips_nats_and_kv -- --ignored --nocapture

log "running Rust coordinator mixed Connect/WebSocket cross-replica smoke"
NATS_URL="$NATS_URL" \
  cargo test -p codewire-coordinator mixed_transport_cross_replica_fanout_round_trips_over_nats -- --ignored --nocapture

start_temporal

log "seeding orchestration API-key contract fixture"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f "$ROOT/tests/fixtures/orchestration/seed.sql"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 \
  -f "$ROOT/tests/fixtures/orchestration/runtime-ready.sql"
if [[ "$(psql "$DATABASE_URL" -Atqc \
    "SELECT count(*) FROM sessions WHERE id IN ('ses_apikey_contract_admin', 'ses_apikey_contract_user') AND token_hash IN (encode(digest('apikey-contract-admin-session-token', 'sha256'), 'hex'), encode(digest('apikey-contract-user-session-token', 'sha256'), 'hex'))")" != "2" ]]; then
  echo "::error::orchestration contract session fixtures are not hash-only"
  exit 1
fi

ORCHESTRATION_KUBECONFIG="$RUN_DIR/orchestration-deliberately-missing-kubeconfig"
rm -f "$ORCHESTRATION_KUBECONFIG"
start_proc orchestration "$ORCHESTRATION_PORT" env \
  KUBECONFIG="$ORCHESTRATION_KUBECONFIG" \
  KUBERNETES_SERVICE_HOST= KUBERNETES_SERVICE_PORT= \
  DATABASE_URL="$DATABASE_URL_RUST" \
  SESSION_SECRET="$SESSION_SECRET" \
  ORCHESTRATION_PORT="$ORCHESTRATION_PORT" \
  TEMPORAL_HOST_PORT="$TEMPORAL_HOST_PORT" \
  WORKER_CONSUMERS="${WORKER_CONSUMERS:-}" \
  WORKER_LOOPS="${WORKER_LOOPS:-}" \
  CONNECT_TESTING_SURFACE=1 \
  "$CARGO_CI_DIR/codewire-orchestration"

probe_connect_surface orchestration "$ORCHESTRATION_PORT"

# The selected service gate owns the complete Rust orchestration wire matrix.
# The aggregate diagnostic repeats the explicit kube-unconfigured boundary so
# it cannot accidentally depend on a developer or runner cluster.
log "running Rust orchestration kube-unconfigured contract"
ORCHESTRATION_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
  ORCHESTRATION_GLOBAL_ADMIN_SESSION_TOKEN=orchestration-global-admin-session-token \
  ORCHESTRATION_ADMIN_SESSION_TOKEN=apikey-contract-admin-session-token \
  ORCHESTRATION_USER_SESSION_TOKEN=apikey-contract-user-session-token \
  ORCHESTRATION_SEEDED=1 ORCHESTRATION_KUBE_MODE=unconfigured \
  ORCHESTRATION_CONTRACT_SCOPE=runtime \
  cargo test --locked --profile ci -p codewire-orchestration \
    --test wire_contract --features kind-e2e \
    configured_orchestration_wire_contract -- \
    --ignored --exact --nocapture | tee "$RUN_DIR/orchestration-contract.log"
assert_passed_count \
  "Rust orchestration kube-unconfigured contract" \
  "$RUN_DIR/orchestration-contract.log" 1

log "running billing org-teardown Temporal smoke"
(
  cd "$RUN_DIR"
  wid="org-teardown/smoke-$RANDOM"
  "$RUN_DIR/bin/temporal" workflow start --address "$TEMPORAL_HOST_PORT" \
    --task-queue codewire-billing --type OrgTeardownWorkflow \
    --workflow-id "$wid" --input '{"org_id":"smoke-nonexistent"}'
  if timeout 120 "$RUN_DIR/bin/temporal" workflow result --address "$TEMPORAL_HOST_PORT" \
      --workflow-id "$wid" > "$RUN_DIR/org-teardown-result.txt" 2>&1; then
    cat "$RUN_DIR/org-teardown-result.txt"
  else
    rc=$?
    echo "::error::org-teardown workflow did not complete cleanly (rc=$rc)"
    "$RUN_DIR/bin/temporal" task-queue describe --address "$TEMPORAL_HOST_PORT" \
      --task-queue codewire-billing || true
    exit "$rc"
  fi
)

# The first billing process has completed both its wire and Temporal-worker
# duties. Release its bounded service pool before the dedicated webhook/loop
# process and Rust DB driver start the deploy-shaped phase.
stop_proc billing

start_proc billing-webhook "$BILLING_WEBHOOK_PORT" env \
  DATABASE_URL="$DATABASE_URL_RUST" \
  SESSION_SECRET="$SESSION_SECRET" \
  BILLING_PORT="$BILLING_WEBHOOK_PORT" \
  BILLING_LOOPS=trials \
  STRIPE_SECRET_KEY=sk_test_buildtest_dummy \
  STRIPE_WEBHOOK_SECRET=whsec_test_secret \
  "$CARGO_CI_DIR/codewire-billing"

log "running Rust billing and orchestration deploy-shaped smokes"
DATABASE_URL="$DATABASE_URL_RUST" \
  BILLING_RUNTIME_BASE_URL="http://127.0.0.1:${BILLING_WEBHOOK_PORT}" \
  BILLING_RUNTIME_WEBHOOK_SECRET=whsec_test_secret \
  "$CARGO_CI_DIR/billing-runtime-smoke" | tee "$RUN_DIR/billing-runtime-smoke.log"
DATABASE_URL="$DATABASE_URL_RUST" \
  TEMPORAL_ADDRESS="http://${TEMPORAL_HOST_PORT}" \
  ORCHESTRATION_RUNTIME_BASE_URL="http://127.0.0.1:${ORCHESTRATION_PORT}" \
  ORCHESTRATION_RUNTIME_SESSION_TOKEN=contract-admin-session-token \
  "$CARGO_CI_DIR/deploy-shape-smoke" | tee "$RUN_DIR/deploy-shape-smoke.log"

log "green"
