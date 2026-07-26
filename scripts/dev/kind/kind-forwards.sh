#!/bin/bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"
NAMESPACE="${NAMESPACE:-default}"
STATE_DIR="${STATE_DIR:-/tmp/codewire-kind-forwards}"
READY_ATTEMPTS="${KIND_FORWARD_READY_ATTEMPTS:-30}"

usage() {
  cat <<'EOF'
Usage: kind-forwards.sh <start|stop|status|env|cleanup|restart|supervise> [postgres|nats|billing|orchestration|temporal|all]

Managed local-kind port-forwards for host-side tests.
The default "all" set follows the Rust local-kind stack and excludes NATS.
Use "supervise" in a background process for long e2e runs; it restarts managed
forwards if kubectl loses the selected service pod connection.
EOF
}

service_resource() {
  case "$1" in
    postgres) echo "service/postgres" ;;
    nats) echo "service/nats" ;;
    billing) echo "service/codewire-billing" ;;
    orchestration) echo "service/codewire-orchestration" ;;
    temporal) echo "service/temporal-frontend" ;;
    *) echo "unknown service: $1" >&2; exit 1 ;;
  esac
}

service_namespace() {
  case "$1" in
    temporal) echo "temporal-system" ;;
    *) echo "$NAMESPACE" ;;
  esac
}

service_local_port() {
  case "$1" in
    postgres) echo "25432" ;;
    nats) echo "24222" ;;
    billing) echo "28081" ;;
    orchestration) echo "28084" ;;
    temporal) echo "27233" ;;
    *) echo "unknown service: $1" >&2; exit 1 ;;
  esac
}

service_remote_port() {
  case "$1" in
    postgres) echo "5432" ;;
    nats) echo "4222" ;;
    billing) echo "8081" ;;
    orchestration) echo "8084" ;;
    temporal) echo "7233" ;;
    *) echo "unknown service: $1" >&2; exit 1 ;;
  esac
}

service_env() {
  case "$1" in
    postgres)
      echo "DATABASE_URL=postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable"
      echo "E2E_DATABASE_URL=postgres://codewire:codewire@127.0.0.1:25432/codewire?sslmode=disable"
      ;;
    nats)
      echo "NATS_URL=nats://127.0.0.1:24222"
      echo "E2E_NATS_URL=nats://127.0.0.1:24222"
      ;;
    billing) echo "E2E_BILLING_URL=http://127.0.0.1:28081" ;;
    orchestration) echo "E2E_ORCH_URL=http://127.0.0.1:28084" ;;
    temporal) echo "E2E_TEMPORAL_HOST_PORT=127.0.0.1:27233" ;;
    *) echo "unknown service: $1" >&2; exit 1 ;;
  esac
}

pid_file() {
  echo "$STATE_DIR/$1.pid"
}

log_file() {
  echo "$STATE_DIR/$1.log"
}

lock_file() {
  echo "$STATE_DIR/$1.lock"
}

with_service_lock() {
  local service="$1"
  local lock
  shift

  mkdir -p "$STATE_DIR"
  lock="$(lock_file "$service")"
  (
    flock 9
    "$@"
  ) 9>"$lock"
}

read_state() {
  local service="$1" file extra
  STATE_PID=""
  STATE_START_TOKEN=""
  file="$(pid_file "$service")"
  [ -f "$file" ] || return 1
  read -r STATE_PID STATE_START_TOKEN extra <"$file" || return 1
  [[ "$STATE_PID" =~ ^[0-9]+$ ]] || return 1
  [[ "$STATE_START_TOKEN" =~ ^[0-9]+$ ]] || return 1
  [ -z "${extra:-}" ] || return 1
}

process_start_token() {
  local pid="$1"
  if [ -r "/proc/$pid/stat" ]; then
    awk '{print $22}' "/proc/$pid/stat" 2>/dev/null
    return
  fi
  ps -p "$pid" -o lstart= 2>/dev/null | cksum | awk '{print $1 $2}'
}

process_is_live() {
  local pid="$1" state
  kill -0 "$pid" 2>/dev/null || return 1
  state="$(ps -p "$pid" -o stat= 2>/dev/null | tr -d '[:space:]')"
  [ -n "$state" ] && [[ "$state" != Z* ]]
}

managed_command_matches() {
  local service="$1" args resource namespace local_port remote_port
  args="$(ps -ww -p "$STATE_PID" -o args= 2>/dev/null || true)"
  resource="$(service_resource "$service")"
  namespace="$(service_namespace "$service")"
  local_port="$(service_local_port "$service")"
  remote_port="$(service_remote_port "$service")"

  [[ "$args" == *kubectl* ]] &&
    [[ "$args" == *"--context $KUBE_CONTEXT"* ]] &&
    [[ "$args" == *"-n $namespace"* ]] &&
    [[ "$args" == *"port-forward --address 127.0.0.1 $resource ${local_port}:${remote_port}"* ]]
}

have_live_pid() {
  local current_start
  read_state "$1" || return 1
  process_is_live "$STATE_PID" || return 1
  current_start="$(process_start_token "$STATE_PID")"
  [ -n "$current_start" ] && [ "$current_start" = "$STATE_START_TOKEN" ] || return 1
  managed_command_matches "$1"
}

clear_dead_state() {
  local service="$1" file
  file="$(pid_file "$service")"
  [ -f "$file" ] || return 0
  if ! read_state "$service" || ! process_is_live "$STATE_PID"; then
    rm -f "$file"
  fi
}

refuse_unowned_state() {
  local service="$1" file
  file="$(pid_file "$service")"
  [ -f "$file" ] || return 1
  read_state "$service" || {
    local legacy_pid
    read -r legacy_pid _ <"$file" || true
    if [[ "$legacy_pid" =~ ^[0-9]+$ ]] && process_is_live "$legacy_pid"; then
      echo "$service: refusing to trust live legacy state $file; it has no helper ownership token" >&2
      return 0
    fi
    rm -f "$file"
    echo "$service: removed dead legacy managed-forward state" >&2
    return 1
  }
  if process_is_live "$STATE_PID" && ! have_live_pid "$service"; then
    echo "$service: refusing to control live pid $STATE_PID from $file; it is not this helper's exact IPv4 forward" >&2
    return 0
  fi
  return 1
}

wait_ready() {
  local service="$1"
  local port log
  port="$(service_local_port "$service")"
  log="$(log_file "$service")"

  for _ in $(seq 1 "$READY_ATTEMPTS"); do
    if ! have_live_pid "$service"; then
      echo "kind forward for $service exited unexpectedly" >&2
      [ -f "$log" ] && cat "$log" >&2
      return 1
    fi
    if grep -Fq "Forwarding from 127.0.0.1:${port} ->" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done

  echo "kind forward for $service did not become ready at 127.0.0.1:${port}; leaving any unrelated listener untouched" >&2
  [ -f "$log" ] && cat "$log" >&2
  return 1
}

start_service() {
  local service="$1"
  local resource local_port remote_port log pid start_token
  local namespace

  mkdir -p "$STATE_DIR"
  if have_live_pid "$service"; then
    echo "$service forward already running on 127.0.0.1:$(service_local_port "$service")"
    return 0
  fi
  if refuse_unowned_state "$service"; then
    return 1
  fi
  clear_dead_state "$service"

  resource="$(service_resource "$service")"
  namespace="$(service_namespace "$service")"
  local_port="$(service_local_port "$service")"
  remote_port="$(service_remote_port "$service")"
  log="$(log_file "$service")"

  nohup kubectl --context "$KUBE_CONTEXT" -n "$namespace" port-forward --address 127.0.0.1 "$resource" "${local_port}:${remote_port}" 9>&- </dev/null >"$log" 2>&1 &
  pid=$!
  disown "$pid" 2>/dev/null || true
  start_token="$(process_start_token "$pid")"
  if [ -z "$start_token" ]; then
    echo "$service: forward exited before helper ownership could be recorded for 127.0.0.1:${local_port}; leaving any unrelated listener untouched" >&2
    [ -f "$log" ] && cat "$log" >&2
    return 1
  fi
  printf '%s %s\n' "$pid" "$start_token" >"$(pid_file "$service")"
  if ! wait_ready "$service"; then
    stop_service "$service" || true
    return 1
  fi
  echo "started $service forward on 127.0.0.1:${local_port} (pid $pid)"
}

stop_service() {
  local service="$1"
  local file

  file="$(pid_file "$service")"
  if [ ! -f "$file" ]; then
    echo "$service forward not managed here"
    return 0
  fi

  if ! read_state "$service"; then
    local legacy_pid
    read -r legacy_pid _ <"$file" || true
    if [[ "$legacy_pid" =~ ^[0-9]+$ ]] && process_is_live "$legacy_pid"; then
      echo "$service: refusing to remove live legacy state $file; it has no helper ownership token" >&2
      return 1
    fi
    rm -f "$file"
    echo "removed dead legacy $service forward state"
    return 0
  fi
  if ! process_is_live "$STATE_PID"; then
    rm -f "$file"
    echo "removed stale $service forward state"
    return 0
  fi
  if ! have_live_pid "$service"; then
    echo "$service: refusing to stop live pid $STATE_PID; it is not this helper's exact IPv4 forward" >&2
    return 1
  fi
  kill "$STATE_PID" 2>/dev/null || true
  wait "$STATE_PID" 2>/dev/null || true
  rm -f "$file"
  echo "stopped $service forward (pid $STATE_PID)"
}

status_service() {
  local service="$1"
  local port

  port="$(service_local_port "$service")"
  if have_live_pid "$service"; then
    echo "$service: running on 127.0.0.1:${port} (pid $(cat "$(pid_file "$service")"))"
    return 0
  fi

  if [ -f "$(pid_file "$service")" ]; then
    echo "$service: state exists but is not a helper-owned live IPv4 forward"
    return 1
  fi

  echo "$service: stopped"
}

cleanup_service() {
  local service="$1"

  stop_service "$service"
  echo "$service: helper-owned forward cleanup complete; unrelated listeners are never terminated"
}

restart_service() {
  local service="$1"

  cleanup_service "$service"
  start_service "$service"
}

supervise_start_service() {
  local service="$1"

  if have_live_pid "$service"; then
    return 0
  fi
  echo "$service forward is not running; restarting" >&2
  if ! start_service "$service" >&2; then
    echo "$service forward restart failed; will retry" >&2
    return 1
  fi
}

supervise_services() {
  local services="$1"
  local service
  local interval="${KIND_FORWARD_SUPERVISE_INTERVAL:-2}"

  while true; do
    for service in $services; do
      if ! have_live_pid "$service"; then
        with_service_lock "$service" supervise_start_service "$service" || true
      fi
    done
    sleep "$interval"
  done
}

expand_services() {
  case "${1:-all}" in
    ""|all) echo "postgres billing orchestration temporal" ;;
    postgres|nats|billing|orchestration|temporal) echo "$1" ;;
    *) echo "unknown service: $1" >&2; exit 1 ;;
  esac
}

main() {
  [ $# -ge 1 ] || { usage; exit 1; }
  local action="$1"
  local services service
  shift || true
  services="$(expand_services "${1:-all}")"

  case "$action" in
    start)
      for service in $services; do with_service_lock "$service" start_service "$service"; done
      ;;
    stop)
      for service in $services; do with_service_lock "$service" stop_service "$service"; done
      ;;
    status)
      for service in $services; do status_service "$service"; done
      ;;
    env)
      for service in $services; do service_env "$service"; done
      ;;
    cleanup)
      for service in $services; do with_service_lock "$service" cleanup_service "$service"; done
      ;;
    restart)
      for service in $services; do with_service_lock "$service" restart_service "$service"; done
      ;;
    supervise)
      supervise_services "$services"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
