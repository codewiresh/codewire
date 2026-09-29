#!/usr/bin/env bash
# Manual testing against the retained local Kind cluster that `make e2e-kind`
# creates (KEEP_KIND_CLUSTER=1). The cluster is never created or deleted here;
# `kind-e2e.sh credentials real|fake` selects the credential-service.
#
#   seed-login      seed e2e-owner@codewire.sh / SecureTestPass9#
#   runtime-images  load the product's default workspace image, as Dev runs it
#   watch           make the cluster serve KIND_PUBLIC_ORIGIN like Dev (browser
#                   origin, default images), then serve the current dashboard
#                   source there
#   status          cluster, ingress, dashboard, credential mode and origins
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"
KIND_PUBLIC_ORIGIN="${KIND_PUBLIC_ORIGIN:-}"
WATCH_ADDR="${KIND_WATCH_ADDR:-127.0.0.1:5182}"
# Dashboard source to serve; set to another worktree to review stacked UI work.
SOURCE_ROOT="${KIND_WATCH_SOURCE_ROOT:-$ROOT}"
INGRESS="http://127.0.0.1:8090"
# Where the browser reaches the cluster API (terminals, streams). It must share
# KIND_PUBLIC_ORIGIN's host; expose the ingress there over the Tailnet with
# `sudo tailscale serve --bg --http=8090 http://127.0.0.1:8090`.
BROWSER_API="${KIND_BROWSER_API_ORIGIN:-$INGRESS}"
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
    /codewire-credential-service) echo real ;;
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
  [ -d "$ROOT/apps/dashboard/node_modules/postgres" ] \
    || die "install the dashboard dependencies first: (cd apps/dashboard && bun install --frozen-lockfile --ignore-scripts)"
  log "seeding the synthetic owner login"
  (
    cd "$ROOT/apps/dashboard"
    # The seed script lives outside apps/dashboard; resolve its imports from
    # the dashboard's dependencies, as the helpers it imports do.
    NODE_PATH="$ROOT/apps/dashboard/node_modules" \
      DATABASE_URL="postgres://codewire:codewire@127.0.0.1:${KIND_POSTGRES_HOST_PORT}/codewire" \
      bun "$ROOT/scripts/dev/kind/seed-login.ts"
  )
}

frontend_url() {
  kube get configmap codewire-config -o 'jsonpath={.data.FRONTEND_URL}'
}

# The IdP, orchestration and billing accept one browser origin (terminal
# attach, redirects). Reviewing through the watcher uses KIND_PUBLIC_ORIGIN;
# `kind-e2e.sh credentials fake` restores the ingress origin the gate's suites
# browse from.
ensure_review_origin() {
  [ "$(frontend_url)" != "$KIND_PUBLIC_ORIGIN" ] || return 0
  log "setting the cluster browser origin to ${KIND_PUBLIC_ORIGIN}"
  kube patch configmap codewire-config --type=merge \
    -p "$(jq -cn --arg url "$KIND_PUBLIC_ORIGIN" '{data: {FRONTEND_URL: $url}}')" >/dev/null
  kube rollout restart deployment/codewire-orchestration deployment/codewire-idp \
    deployment/codewire-billing >/dev/null
  for deployment in codewire-orchestration codewire-idp codewire-billing; do
    kube rollout status "deployment/${deployment}" --timeout=180s >/dev/null
  done
}

# Create's default workspace image is a Harbor digest that Dev pulls with its
# registry credential. The public GHCR mirror publishes the same digest, so
# load that into every node under the Harbor reference the product uses; the
# identical digest makes it the same image, and no credential is involved.
cmd_runtime_images() {
  require_cluster
  local harbor mirror node
  harbor="$(sed -n 's/^pub const DEFAULT_WORKSPACE_IMAGE: &str = "\(.*\)";$/\1/p' \
    "$ROOT/crates/codewire-server-core/src/runtime_images.rs")"
  [[ "$harbor" =~ ^registry\.example\.invalid/codewire/[a-z0-9-]+@sha256:[0-9a-f]{64}$ ]] \
    || die "could not read DEFAULT_WORKSPACE_IMAGE from runtime_images.rs"
  mirror="ghcr.io/codewiresh/${harbor#registry.example.invalid/codewire/}"
  for node in $(kind get nodes --name "$KIND_CLUSTER_NAME"); do
    if docker exec "$node" crictl inspecti "$harbor" >/dev/null 2>&1; then
      continue
    fi
    log "loading the default workspace image ${harbor##*@} into ${node} from ${mirror%@*}"
    docker exec "$node" crictl pull "$mirror" >/dev/null \
      || die "the public GHCR mirror does not serve ${mirror}"
    docker exec "$node" ctr -n k8s.io images tag --force "$mirror" "$harbor" >/dev/null
  done
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
  if [ "$(credential_mode)" = fake ]; then
    log "WARNING: the credential-service is the gate's synthetic fixture; connecting GitHub, Codex or any provider will fail. Run make kind-credentials-real (needs an OpenBao login) before reviewing credentials."
  fi
  ensure_review_origin
  cmd_runtime_images
  log "dashboard ${WATCH_ADDR} for ${KIND_PUBLIC_ORIGIN}/ (source ${SOURCE_ROOT}), credential-service $(credential_mode), browser API ${BROWSER_API}"
  log "login e2e-owner@codewire.sh / SecureTestPass9#"
  export CODEWIRE_DASHBOARD_LISTEN_ADDR="$WATCH_ADDR"
  export CODEWIRE_PUBLIC_ORIGIN="$KIND_PUBLIC_ORIGIN"
  export CODEWIRE_API_ORIGIN="$INGRESS"
  export CODEWIRE_CREDENTIAL_ORIGIN="$INGRESS"
  export CODEWIRE_IDENTITY_ORIGIN="$INGRESS"
  export CODEWIRE_BILLING_ORIGIN="$INGRESS"
  export CODEWIRE_BROWSER_API_ORIGIN="$BROWSER_API"
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
  echo "browser origin: $(frontend_url)"
  echo "GitHub App: $(app_public_value slug)"
  echo "public origin: ${KIND_PUBLIC_ORIGIN:-unset}"
}

case "${1:-}" in
  seed-login) cmd_seed_login ;;
  runtime-images) cmd_runtime_images ;;
  watch) cmd_watch ;;
  status) cmd_status ;;
  *) echo "usage: $0 <seed-login|runtime-images|watch|status>" >&2; exit 2 ;;
esac
