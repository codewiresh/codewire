#!/usr/bin/env bash
# Local Rust service launcher.
#
# Brings up the same Rust service topology CI's integration job runs against a
# contract-seeded Postgres and a JetStream NATS, then checks service health.
#
# Requirements:
#   - DATABASE_URL pointing at a database initialized by the Rust services'
#     standard SQLx entrypoint, with the billing contract fixture loaded when
#     the selected e2e needs it
#     (default: the dev-sandbox postgres on 127.0.0.1:5433)
#   - Docker or nats-server on PATH for an isolated private NATS, or set
#     NATS_URL to reuse an external JetStream-enabled server
#   - Rust toolchain
#
# Usage:
#   scripts/dev/dev-stack.sh            # build, start, check health, leave stack up
#   scripts/dev/dev-stack.sh down       # stop everything started by this script
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="${ROOT}/.dev-stack"
mkdir -p "$RUN_DIR"

DATABASE_URL="${DATABASE_URL:-postgres://codewire:codewire@127.0.0.1:5433/codewire?sslmode=disable}"
NATS_URL="${NATS_URL:-}"
NATS_HEALTH_URL="${NATS_HEALTH_URL:-}"
DEV_STACK_NATS_CONTAINER="${DEV_STACK_NATS_CONTAINER:-codewire-dev-stack-nats-$(id -u)}"
SESSION_SECRET="${SESSION_SECRET:-dev-stack-not-a-real-secret-32bytes}"

# The flip state comes from the single source of truth shared with CI.
set -a
# shellcheck source=../tests/e2e/flip-state.env
. "$ROOT/tests/e2e/flip-state.env"
set +a
RUST_CONSUMERS="$WORKER_CONSUMERS"
RUST_LOOPS="$WORKER_LOOPS"

ORCH_PORT=8084
BILLING_PORT=8081

stop_all() {
  for pidfile in "$RUN_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
  done
  if [ -f "$RUN_DIR/nats.container" ] && command -v docker >/dev/null 2>&1; then
    docker rm -f "$(cat "$RUN_DIR/nats.container")" >/dev/null 2>&1 || true
    rm -f "$RUN_DIR/nats.container"
  fi
  echo "dev-stack: stopped"
}

if [ "${1:-}" = "down" ]; then
  stop_all
  exit 0
fi

wait_healthz() { # name url
  for _ in $(seq 1 30); do
    if curl --connect-timeout 1 --max-time 2 -fsS "$2" >/dev/null 2>&1; then
      echo "dev-stack: $1 up"
      return 0
    fi
    sleep 1
  done
  echo "dev-stack: $1 did not become healthy at $2" >&2
  tail -20 "$RUN_DIR/$1.log" >&2 || true
  exit 1
}

wait_nats_healthz() { # monitor_port
  local port="$1"
  for _ in $(seq 1 30); do
    if command -v ncat >/dev/null 2>&1 &&
      printf 'GET /healthz HTTP/1.0\r\n\r\n' | ncat -w 2 127.0.0.1 "$port" | grep -q '"status":"ok"'; then
      echo "dev-stack: nats up"
      return 0
    fi
    if curl --connect-timeout 1 --max-time 2 -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      echo "dev-stack: nats up"
      return 0
    fi
    sleep 1
  done
  echo "dev-stack: nats did not become healthy at 127.0.0.1:${port}" >&2
  tail -20 "$RUN_DIR/nats.log" >&2 || true
  exit 1
}

# ── NATS ────────────────────────────────────────────────────────────────
docker_host_port() {
  local container="$1" container_port="$2" mapping port
  mapping="$(docker port "$container" "${container_port}/tcp" | head -n1 || true)"
  port="${mapping##*:}"
  if [ -z "$mapping" ] || [ "$port" = "$mapping" ]; then
    echo "dev-stack: could not resolve ${container_port}/tcp host port for ${container}" >&2
    return 1
  fi
  printf '%s\n' "$port"
}

port_in_use() {
  local port="$1"
  (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
}

choose_free_port() {
  local low="${1:-24000}" high="${2:-45000}" port
  for _ in $(seq 1 100); do
    if command -v shuf >/dev/null 2>&1; then
      port="$(shuf -i "${low}-${high}" -n 1)"
    else
      port=$((low + (RANDOM % (high - low + 1))))
    fi
    if ! port_in_use "$port"; then
      printf '%s\n' "$port"
      return 0
    fi
  done
  echo "dev-stack: could not find a free loopback port" >&2
  return 1
}

start_private_nats_docker() {
  docker rm -f "$DEV_STACK_NATS_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$DEV_STACK_NATS_CONTAINER" \
    -p "127.0.0.1::4222" \
    -p "127.0.0.1::8222" \
    nats:2.12-alpine -js -m 8222 \
    > "$RUN_DIR/nats.container"
  docker logs -f "$DEV_STACK_NATS_CONTAINER" > "$RUN_DIR/nats.log" 2>&1 &
  echo $! > "$RUN_DIR/nats-logs.pid"

  local nats_client_port nats_monitor_port
  nats_client_port="$(docker_host_port "$DEV_STACK_NATS_CONTAINER" 4222)"
  nats_monitor_port="$(docker_host_port "$DEV_STACK_NATS_CONTAINER" 8222)"
  NATS_URL="nats://127.0.0.1:${nats_client_port}"
  wait_nats_healthz "$nats_monitor_port"
}

start_private_nats_binary() {
  local nats_client_port nats_monitor_port
  nats_client_port="$(choose_free_port)"
  nats_monitor_port="$(choose_free_port)"
  while [ "$nats_monitor_port" = "$nats_client_port" ]; do
    nats_monitor_port="$(choose_free_port)"
  done
  nats-server -js -p "$nats_client_port" -m "$nats_monitor_port" > "$RUN_DIR/nats.log" 2>&1 &
  echo $! > "$RUN_DIR/nats.pid"
  NATS_URL="nats://127.0.0.1:${nats_client_port}"
  wait_nats_healthz "$nats_monitor_port"
}

start_nats() {
  if [ -n "$NATS_URL" ]; then
    echo "dev-stack: using external NATS at $NATS_URL"
    if [ -n "$NATS_HEALTH_URL" ]; then
      wait_healthz nats "$NATS_HEALTH_URL"
    fi
    return 0
  fi

  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    start_private_nats_docker
  elif command -v nats-server >/dev/null 2>&1; then
    start_private_nats_binary
  else
    echo "dev-stack: need Docker or nats-server for private NATS, or set NATS_URL to an external JetStream server" >&2
    exit 1
  fi
  echo "dev-stack: private NATS at $NATS_URL"
}

start_nats

# ── Temporal (required: flip state is temporal-primary) ────────────────
if [ "${ENVIRONMENT_ORCHESTRATOR:-}" = "temporal-primary" ] && [ -z "${TEMPORAL_HOST_PORT:-}" ]; then
  TEMPORAL_BIN="${TEMPORAL_BIN:-$(command -v temporal || true)}"
  if [ -z "$TEMPORAL_BIN" ]; then
    echo "dev-stack: flip state is temporal-primary but no 'temporal' CLI found (set TEMPORAL_BIN or TEMPORAL_HOST_PORT)" >&2
    exit 1
  fi
  if ! "$TEMPORAL_BIN" operator cluster health --address 127.0.0.1:7233 >/dev/null 2>&1; then
    "$TEMPORAL_BIN" server start-dev --headless --ip 127.0.0.1 --port 7233 \
      --db-filename "$RUN_DIR/temporal-dev.db" > "$RUN_DIR/temporal.log" 2>&1 &
    echo $! > "$RUN_DIR/temporal.pid"
    for _ in $(seq 1 30); do
      "$TEMPORAL_BIN" operator cluster health --address 127.0.0.1:7233 >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  export TEMPORAL_HOST_PORT=127.0.0.1:7233
  echo "dev-stack: temporal dev server up"
fi

# ── Builds ──────────────────────────────────────────────────────────────
echo "dev-stack: building Rust services..."
# shellcheck source=scripts/ci/verify/local-rust-cache.sh
source "$ROOT/scripts/ci/verify/local-rust-cache.sh"
select_local_rust_cache "$ROOT" || true
(cd "$ROOT" && cargo build --profile ci -p codewire-orchestration -p codewire-billing >/dev/null)
RUST_BIN_DIR="$ROOT/target/ci"

# ── Rust orchestration (consumers + loops) ──────────────────────────────
# CONNECT_TESTING_SURFACE mounts the Connect conformance probe
# (connect-rpc/03, D8) — dev/CI/kind surfaces only.
DATABASE_URL="$DATABASE_URL" SESSION_SECRET="$SESSION_SECRET" NATS_URL="$NATS_URL" \
ORCHESTRATION_PORT="$ORCH_PORT" \
TEMPORAL_HOST_PORT="${TEMPORAL_HOST_PORT:-}" \
CONNECT_TESTING_SURFACE=1 \
WORKER_CONSUMERS="$RUST_CONSUMERS" WORKER_LOOPS="$RUST_LOOPS" \
  "$RUST_BIN_DIR/codewire-orchestration" > "$RUN_DIR/orchestration.log" 2>&1 &
echo $! > "$RUN_DIR/orchestration.pid"

# ── Rust billing (HTTP + billing loops) ─────────────────────────────────
DATABASE_URL="$DATABASE_URL" SESSION_SECRET="$SESSION_SECRET" \
BILLING_PORT="$BILLING_PORT" BILLING_LOOPS="$BILLING_LOOPS" \
CONNECT_TESTING_SURFACE=1 \
  "$RUST_BIN_DIR/codewire-billing" > "$RUN_DIR/billing.log" 2>&1 &
echo $! > "$RUN_DIR/billing.pid"

wait_healthz orchestration "http://localhost:$ORCH_PORT/healthz"
wait_healthz billing "http://localhost:$BILLING_PORT/healthz"

echo "dev-stack: Rust services healthy. Stack left running (logs in .dev-stack/); 'scripts/dev/dev-stack.sh down' to stop."
echo "dev-stack: run scripts/ci/verify/run-integration-verification.sh services-control and services-runtime for selected Rust service proof."
