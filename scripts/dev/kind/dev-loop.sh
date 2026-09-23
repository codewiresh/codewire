#!/usr/bin/env bash
# Manual testing against the retained local Kind cluster that `make e2e-kind`
# creates (KEEP_KIND_CLUSTER=1). The cluster is never created, deleted or
# reconfigured here; `kind-e2e.sh credentials real|fake` selects the
# credential-service.
#
#   seed-login  seed e2e-owner@codewire.sh / SecureTestPass9#
#   watch       serve the current dashboard source against the cluster at
#               KIND_PUBLIC_ORIGIN (the GitHub App callback origin)
#   status      cluster, ingress, dashboard, credential mode and origins
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"
KIND_PUBLIC_ORIGIN="${KIND_PUBLIC_ORIGIN:-}"
WATCH_ADDR="${KIND_WATCH_ADDR:-127.0.0.1:5182}"
# Dashboard source to serve; set to another worktree to review stacked UI work.
SOURCE_ROOT="${KIND_WATCH_SOURCE_ROOT:-$ROOT}"
INGRESS="http://127.0.0.1:8090"
CONTEXT="kind-${KIND_CLUSTER_NAME}"
NAMESPACE=codewire-e2e

log() { printf '[kind-dev] %s\n' "$*" >&2; }
die() { printf '[kind-dev] error: %s\n' "$*" >&2; exit 1; }
kube() { kubectl --context "$CONTEXT" --request-timeout=30s -n "$NAMESPACE" "$@"; }

require_cluster() {
  kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME" \
    || die "cluster ${KIND_CLUSTER_NAME} does not exist; create it with KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME} KEEP_KIND_CLUSTER=1 make e2e-kind"
  kube get deployment codewire-credential-service >/dev/null \
    || die "cluster ${KIND_CLUSTER_NAME} was not prepared by the Kind gate"
}

require_origin() {
  [ -n "$KIND_PUBLIC_ORIGIN" ] || die "set KIND_PUBLIC_ORIGIN to the browser origin registered for the GitHub App callback"
}

http_status() {
  curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || true
}

credential_mode() {
  local command
  command="$(kube get deployment codewire-credential-service \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="credential-service")].command[0]}')"
  case "$command" in
    /codewire-kind-fixtures/credential-service) echo fake ;;
    "") echo real ;;
    *) echo "unknown (${command})" ;;
  esac
}

credential_origin() {
  kube get deployment codewire-credential-service \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="credential-service")].env[?(@.name=="CREDENTIAL_PUBLIC_ORIGIN")].value}'
}

app_public_value() {
  # Only the public client ID and slug are read back; never client-secret.
  kube get secret codewire-github-app-authorization -o "jsonpath={.data.$1}" 2>/dev/null \
    | base64 -d 2>/dev/null || true
}

cmd_seed_login() {
  require_cluster
  log "seeding the synthetic owner login"
  (
    cd "$ROOT/apps/dashboard"
    DATABASE_URL="postgres://codewire:codewire@127.0.0.1:${KIND_POSTGRES_HOST_PORT}/codewire" \
      bun "$ROOT/scripts/dev/kind/seed-login.ts"
  )
}

release_watch_port() {
  # A dashboard left behind by an earlier session holds the watcher's port.
  # Stop only a codewire-dashboard-web listener on exactly this address.
  local port="${WATCH_ADDR##*:}" pid
  # An unused port is the normal case: no match must not end the script.
  pid="$(ss -Hltnp "sport = :${port}" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 || true)"
  [ -n "$pid" ] || return 0
  if [ "$(cat "/proc/${pid}/comm" 2>/dev/null)" = "codewire-dashbo" ]; then
    log "stopping stale dashboard (pid ${pid}) on ${WATCH_ADDR}"
    kill "$pid"
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.5; done
    die "stale dashboard pid ${pid} did not stop"
  fi
  die "${WATCH_ADDR} is held by another process (pid ${pid}); stop it or set KIND_WATCH_ADDR"
}

cmd_watch() {
  [ -f "${SOURCE_ROOT}/scripts/dev/dashboard-watch.py" ] \
    || die "KIND_WATCH_SOURCE_ROOT ${SOURCE_ROOT} is not a Codewire checkout"
  require_origin
  require_cluster
  release_watch_port
  [ "$(http_status "${INGRESS}/login")" = 200 ] || die "the cluster ingress ${INGRESS} is not serving"
  if [ "$(credential_mode)" = real ] && [ "$(credential_origin)" != "$KIND_PUBLIC_ORIGIN" ]; then
    die "credential-service origin $(credential_origin) differs from KIND_PUBLIC_ORIGIN ${KIND_PUBLIC_ORIGIN}"
  fi
  log "dashboard ${WATCH_ADDR} for ${KIND_PUBLIC_ORIGIN}/ (source ${SOURCE_ROOT}), credential-service $(credential_mode)"
  log "login e2e-owner@codewire.sh / SecureTestPass9#"
  export CODEWIRE_DASHBOARD_LISTEN_ADDR="$WATCH_ADDR"
  export CODEWIRE_PUBLIC_ORIGIN="$KIND_PUBLIC_ORIGIN"
  export CODEWIRE_API_ORIGIN="$INGRESS"
  export CODEWIRE_CREDENTIAL_ORIGIN="$INGRESS"
  export CODEWIRE_IDENTITY_ORIGIN="$INGRESS"
  export CODEWIRE_BILLING_ORIGIN="$INGRESS"
  export CODEWIRE_BROWSER_API_ORIGIN="$INGRESS"
  GITHUB_APP_CLIENT_ID="$(app_public_value client-id)"
  GITHUB_APP_SLUG="$(app_public_value slug)"
  export GITHUB_APP_CLIENT_ID GITHUB_APP_SLUG
  # exec so HUP/INT/TERM reach the watcher, which owns and stops its dashboard.
  exec python3 "${SOURCE_ROOT}/scripts/dev/dashboard-watch.py"
}

cmd_status() {
  if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; then
    echo "cluster ${KIND_CLUSTER_NAME}: absent"
    return 1
  fi
  echo "cluster ${KIND_CLUSTER_NAME}: present (context ${CONTEXT})"
  echo "ingress ${INGRESS}/login: $(http_status "${INGRESS}/login")"
  echo "dashboard ${WATCH_ADDR}/login: $(http_status "http://${WATCH_ADDR}/login")"
  echo "credential-service: $(credential_mode), origin $(credential_origin)"
  echo "GitHub App: $(app_public_value slug)"
  echo "public origin: ${KIND_PUBLIC_ORIGIN:-unset}"
}

case "${1:-}" in
  seed-login) cmd_seed_login ;;
  watch) cmd_watch ;;
  status) cmd_status ;;
  *) echo "usage: $0 <seed-login|watch|status>" >&2; exit 2 ;;
esac
