#!/usr/bin/env bash
# Manual testing against the retained local Kind cluster that `make e2e-kind`
# creates (KEEP_KIND_CLUSTER=1). The cluster is never created or deleted here;
# `kind-e2e.sh credentials real|fake` selects the credential-service.
#
#   seed-login      seed e2e-owner@codewire.sh / SecureTestPass9#
#   runtime-images  load the product's default workspace and DinD images, by
#                   digest, as Dev runs them (--dry-run prints the plan)
#   watch           make the cluster serve KIND_PUBLIC_ORIGIN like Dev (browser
#                   origin, default images), then serve the current dashboard
#                   source there
#   status          cluster, ingress, dashboard, credential mode and origins
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/dev/kind/profile.sh
source "$ROOT/scripts/dev/kind/profile.sh"
kind_profile_load "$ROOT" || exit $?
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-codewire-e2e-ci}"
KIND_INGRESS_HOST_PORT="${KIND_INGRESS_HOST_PORT:-8090}"
KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"
KIND_PUBLIC_ORIGIN="${KIND_PUBLIC_ORIGIN:-}"
WATCH_ADDR="${KIND_WATCH_ADDR:-127.0.0.1:5182}"
# Dashboard source to serve; set to another worktree to review stacked UI work.
SOURCE_ROOT="${KIND_WATCH_SOURCE_ROOT:-$ROOT}"
INGRESS="${KIND_INGRESS_URL:-http://127.0.0.1:${KIND_INGRESS_HOST_PORT}}"
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
  kind_profile_verify_node "$ROOT" || exit $?
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
  kind_profile_lock "$ROOT" || exit $?
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

# Every image a default Sandbox runs that the Kind gate does not build; the
# daemon comes from the locally built daemon image. Each row is the product
# constant a default Sandbox renders (the Kind overlay's
# SANDBOX_DIND_IMAGE names the same reference):
#
#   name  file defining it  constant  accepted reference  public source
#
# The public source serves the same digest without a credential; \N is the
# Nth group of the accepted reference, whose last group is its digest.
# - workspace: a Harbor digest Dev pulls with its registry credential; the
#   public GHCR mirror publishes the same digests.
# - dind: Docker Hub's official image, pulled by its index digest alone.
RUNTIME_IMAGES=(
  'workspace crates/codewire-workspace-image/src/pin.rs HARBOR_IMAGE ^registry\.example\.invalid/codewire/([a-z0-9-]+)@(sha256:[0-9a-f]{64})$ ghcr.io/codewiresh/\1@\2'
  'dind crates/codewire-orchestration/src/sandbox/template/mod.rs DEFAULT_DIND_IMAGE ^docker\.io/library/docker:[0-9]+\.[0-9]+\.[0-9]+-dind@(sha256:[0-9a-f]{64})$ docker.io/library/docker@\1'
)

# Print "<name> <reference> <source>" for every row, or fail closed when a
# constant is missing, repeated or not the shape its row accepts, or when the
# source would not name the reference's exact digest.
resolve_runtime_images() {
  local row name file constant pattern template reference source group
  for row in "${RUNTIME_IMAGES[@]}"; do
    read -r name file constant pattern template <<<"$row"
    reference="$(sed -n "s/^pub const ${constant}: &str = \"\\(.*\\)\";\$/\\1/p" \
      "$ROOT/$file" 2>/dev/null)" || true
    [[ -n "$reference" && "$reference" != *$'\n'* ]] \
      || die "${file} must define ${constant} once, on one line"
    [[ "$reference" =~ $pattern ]] \
      || die "${constant} is not a reference the ${name} row accepts: ${reference}"
    source="$template"
    for group in $(seq $((${#BASH_REMATCH[@]} - 1)) -1 1); do
      source="${source//\\${group}/${BASH_REMATCH[group]}}"
    done
    [[ "$source" =~ ^[a-z0-9.-]+(/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$ \
      && "${source##*@}" == "${reference##*@}" ]] \
      || die "the ${name} source ${source} does not pin ${constant}'s digest"
    printf '%s %s %s\n' "$name" "$reference" "$source"
  done
}

# containerd records a reference that carries both a tag and a digest under the
# digest alone, which is also how the kubelet resolves it.
image_record() {
  local repository="${1%@*}"
  case "${repository##*/}" in
    *:*) repository="${repository%:*}" ;;
  esac
  printf '%s@%s\n' "$repository" "${1##*@}"
}

# The digest the node's image record <ref> points at; empty when absent.
# Read the whole listing: stopping early would fail the pipe.
node_image_digest() {
  docker exec "$1" ctr -n k8s.io images ls \
    | awk -v ref="$2" '$1 == ref && !found { print $3; found = 1 }'
}

# Pull every row's public source into every node by digest and name it as
# the product renders it. An image already present at its digest is skipped;
# any record that names a different digest fails the load.
cmd_runtime_images() {
  local dry_run=false resolved name reference source record digest node have
  case "${1:-}" in
    '') ;;
    --dry-run) dry_run=true ;;
    *) die "usage: $0 runtime-images [--dry-run]" ;;
  esac
  resolved="$(resolve_runtime_images)" || exit 1
  if [ "$dry_run" = true ]; then
    while read -r name reference source; do
      printf '%s %s <- %s\n' "$name" "$reference" "$source"
    done <<<"$resolved"
    return 0
  fi
  kind_profile_lock "$ROOT" || exit $?
  require_cluster
  for node in $(kind get nodes --name "$KIND_CLUSTER_NAME"); do
    while read -r name reference source; do
      record="$(image_record "$reference")"
      digest="${reference##*@}"
      have="$(node_image_digest "$node" "$record")" \
        || die "could not list the images on ${node}"
      [ "$have" != "$digest" ] || continue
      [ -z "$have" ] || die "${node} names ${record} for ${have}, not ${digest}"
      log "loading the ${name} image ${digest} into ${node} from ${source%@*}"
      docker exec "$node" crictl pull "$source" >/dev/null \
        || die "${source%@*} does not serve ${digest}"
      have="$(node_image_digest "$node" "$source")" || have=''
      [ "$have" = "$digest" ] \
        || die "${node} pulled ${source} as ${have:-nothing}, not ${digest}"
      if [ "$record" != "$source" ]; then
        docker exec "$node" ctr -n k8s.io images tag "$source" "$record" >/dev/null \
          || die "could not name ${source} as ${record} on ${node}"
        have="$(node_image_digest "$node" "$record")" || have=''
        [ "$have" = "$digest" ] \
          || die "${node} names ${record} for ${have:-nothing}, not ${digest}"
      fi
    done <<<"$resolved"
  done
}

release_watch_port() {
  # A process name and a listening port do not establish ownership. A retained
  # review watcher may belong to another session; leave every listener intact.
  local port="${WATCH_ADDR##*:}" listeners
  command -v ss >/dev/null || die 'ss is required to inspect the watcher port'
  listeners="$(ss -Hltn "sport = :${port}")" || die 'could not inspect the watcher port'
  [ -z "$listeners" ] || die "${WATCH_ADDR} is already listening; stop its owning watcher before starting another"
}

cmd_watch() {
  [ -f "${SOURCE_ROOT}/scripts/dev/dashboard-watch.py" ] \
    || die "KIND_WATCH_SOURCE_ROOT ${SOURCE_ROOT} is not a Codewire checkout"
  require_origin
  kind_profile_lock "$ROOT" || exit $?
  require_cluster
  release_watch_port
  [ "$(http_status "${INGRESS}/login")" = 200 ] || die "the cluster ingress ${INGRESS} is not serving"
  if [ "$(credential_mode)" = real ] && [ "$(credential_origin)" != "$KIND_PUBLIC_ORIGIN" ]; then
    die "credential-service origin $(credential_origin) differs from KIND_PUBLIC_ORIGIN ${KIND_PUBLIC_ORIGIN}"
  fi
  # The dashboard reads the GitHub App's public values once, at start; a real
  # credential-service without them would leave Connect GitHub unconfigured.
  GITHUB_APP_CLIENT_ID="$(app_public_value client-id)"
  GITHUB_APP_SLUG="$(app_public_value slug)"
  if [ "$(credential_mode)" = real ] && { [ -z "$GITHUB_APP_CLIENT_ID" ] || [ -z "$GITHUB_APP_SLUG" ]; }; then
    die "credential-service is real but the GitHub App public values are missing from codewire-github-app-authorization; rerun make kind-credentials-real"
  fi
  if [ "$(credential_mode)" = fake ]; then
    log "WARNING: the credential-service is the gate's synthetic fixture; connecting GitHub, Codex or any provider will fail. Run make kind-credentials-real (needs an OpenBao login), then restart make kind-watch, before reviewing credentials."
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
  if [ "$KIND_PROFILE" = 1 ]; then
    # The watcher builds mutable current source; keep that build cache separate
    # from the sealed executables that a concurrent retained suite consumes.
    CARGO_TARGET_DIR="$(dirname "$KIND_PROFILE_PATH")/watch-target"
    kind_profile_private_dir "$CARGO_TARGET_DIR" || exit $?
    export CARGO_TARGET_DIR
  fi
  export GITHUB_APP_CLIENT_ID GITHUB_APP_SLUG
  kind_profile_unlock
  # exec so HUP/INT/TERM reach the watcher, which owns and stops its dashboard.
  exec python3 "${SOURCE_ROOT}/scripts/dev/dashboard-watch.py"
}

cmd_status() {
  kind_profile_verify_node "$ROOT" || return $?
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
  runtime-images) shift; cmd_runtime_images "$@" ;;
  watch) cmd_watch ;;
  status) cmd_status ;;
  *) echo "usage: $0 <seed-login|runtime-images [--dry-run]|watch|status>" >&2; exit 2 ;;
esac
