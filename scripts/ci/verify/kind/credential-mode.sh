#!/usr/bin/env bash
# Switch a retained Kind cluster's credential-service between the gate's fake
# fixture and the real production binary. Sourced by kind-e2e.sh after
# common.sh and credentials.sh.
#
# real: the production entrypoint with the Kind image's test KEK (no OpenBao),
#       Postgres over verified TLS, the real GitHub App copied from OpenBao KV
#       through pipes, and the browser origin that GitHub's callback uses.
# fake: the gate's synthetic fixture, exactly as `make e2e-kind` leaves it.

KIND_PUBLIC_ORIGIN="${KIND_PUBLIC_ORIGIN:-}"
KIND_GITHUB_APP_OPENBAO_ADDR="https://openbao.example.invalid"
KIND_GITHUB_APP_OPENBAO_PATH="${KIND_GITHUB_APP_OPENBAO_PATH:-apps/codewire/dev/runtime}"
KIND_REAL_CREDENTIAL_DATABASE_URL="postgres://codewire_credential_broker:kind-credential-broker-synthetic-only@postgres.${NS}.svc.cluster.local:5432/codewire?sslmode=verify-full&sslrootcert=/run/codewire-credential-db-roots/ca.pem"

require_kind_services_ci_image() {
  local profile promotable
  profile="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.build.profile" }}' codewire-services:e2e)"
  promotable="$(docker image inspect --format '{{ index .Config.Labels "dev.codewire.promotable" }}' codewire-services:e2e)"
  if [ "$profile" != ci ] || [ "$promotable" != false ]; then
    echo '::error::credential modes require the exact non-promotable services-ci image' >&2
    return 1
  fi
}

# Copy the GitHub App identity from OpenBao KV into the Secret the production
# Deployment reads. Values flow only through pipes: never argv, a shell
# variable, a file, or output.
load_kind_github_app() {
  local field
  require_tool bao
  BAO_ADDR="$KIND_GITHUB_APP_OPENBAO_ADDR" bao kv metadata get "$KIND_GITHUB_APP_OPENBAO_PATH" >/dev/null 2>&1 || {
    echo "::error::OpenBao ${KIND_GITHUB_APP_OPENBAO_PATH} is not readable; refresh the owner's OpenBao login (docs/dev/INFRA-REFERENCE.md), then rerun" >&2
    return 1
  }
  openbao_app_field() {
    BAO_ADDR="$KIND_GITHUB_APP_OPENBAO_ADDR" bao kv get -field="$1" "$KIND_GITHUB_APP_OPENBAO_PATH" | tr -d '\n'
  }
  log "copying the GitHub App from OpenBao ${KIND_GITHUB_APP_OPENBAO_PATH} (values are never printed)"
  kubectl -n "$NS" create secret generic codewire-github-app-authorization \
    --from-file=client-id=<(openbao_app_field GITHUB_APP_CLIENT_ID) \
    --from-file=client-secret=<(openbao_app_field GITHUB_APP_CLIENT_SECRET) \
    --from-file=slug=<(openbao_app_field GITHUB_APP_SLUG) \
    --dry-run=client -o yaml | kubectl_apply -f -
  for field in client-id client-secret slug; do
    [ "$(kubectl -n "$NS" get secret codewire-github-app-authorization \
      -o "jsonpath={.data.${field}}" | wc -c)" -gt 0 ] || {
      echo "::error::OpenBao returned an incomplete GitHub App identity" >&2
      return 1
    }
  done
}

# Rewrite only the credential-service container: restore the production
# entrypoint (the fixture patch replaced it), drop the fixture arguments and
# markers, then add the given environment entries.
patch_kind_credential_container() {
  local env_json="$1"
  kubectl -n "$NS" get deployment codewire-credential-service -o json |
    jq --argjson add "$env_json" '
      .spec.template.spec.containers |= map(
        if .name == "credential-service" then
          .command = ["/codewire-credential-service"]
          | del(.args)
          | .env |= (map(select(.name as $n | [
              "CODEWIRE_KIND_CREDENTIAL_FIXTURE",
              "CODEWIRE_KIND_CREDENTIAL_TEST_KEK",
              "CREDENTIAL_PUBLIC_ORIGIN",
              "CREDENTIAL_OAUTH_KEEPALIVE_ENABLED"
            ] | index($n) | not)) + $add)
        else . end)' |
    kubectl replace -f - >/dev/null
}

# The browser origin the IdP, orchestration and billing accept (terminal
# attach, redirects). Real mode serves the owner at KIND_PUBLIC_ORIGIN; the gate
# keeps its ingress origin.
set_kind_frontend_url() {
  local current
  current="$(kubectl -n "$NS" get configmap codewire-config -o 'jsonpath={.data.FRONTEND_URL}')"
  [ "$current" != "$1" ] || return 0
  log "setting the cluster frontend origin to $1"
  kubectl -n "$NS" patch configmap codewire-config --type=merge \
    -p "$(jq -cn --arg url "$1" '{data: {FRONTEND_URL: $url}}')" >/dev/null
  kubectl -n "$NS" rollout restart deployment/codewire-orchestration deployment/codewire-idp \
    deployment/codewire-billing >/dev/null
  kubectl -n "$NS" rollout status deployment/codewire-orchestration --timeout=180s
  kubectl -n "$NS" rollout status deployment/codewire-idp --timeout=180s
  kubectl -n "$NS" rollout status deployment/codewire-billing --timeout=180s
}

# A `make kind-watch` dashboard (scripts/dev/kind/dev-loop.sh) reads the
# GitHub App's public values once, at start, so one started before a switch
# keeps the old ones. Find it as that script's release_watch_port does: the
# codewire-dashboard-web listener (comm truncated to 15 characters) on
# KIND_WATCH_ADDR's port. Without one, as in CI, print nothing; never fail.
kind_watch_restart_hint() {
  local addr="${KIND_WATCH_ADDR:-127.0.0.1:5182}" pid
  pid="$(ss -Hltnp "sport = :${addr##*:}" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 || true)"
  [ -n "$pid" ] || return 0
  [ "$(cat "/proc/${pid}/comm" 2>/dev/null)" = codewire-dashbo ] || return 0
  log "A make kind-watch dashboard is running from before this switch; restart it (stop it, then make kind-watch) so it reads the GitHub App settings."
}

switch_kind_credentials_real() {
  local roots
  [ -n "$KIND_PUBLIC_ORIGIN" ] || {
    echo '::error::set KIND_PUBLIC_ORIGIN to the browser origin registered as the GitHub App callback origin' >&2
    return 1
  }
  require_kind_services_ci_image
  log "publishing the Kind Postgres root for verified credential-service TLS"
  # Only the public root certificate leaves its controller-owned Secret.
  roots="$(kubectl -n "$NS" get secret codewire-kind-postgres-root -o 'jsonpath={.data.tls\.crt}' | base64 -d)"
  [ -n "$roots" ] || { echo '::error::Kind Postgres root certificate is missing' >&2; return 1; }
  kubectl -n "$NS" create configmap codewire-credential-database-roots \
    --from-literal="ca.pem=$roots" --dry-run=client -o yaml | kubectl_apply -f -
  kubectl -n "$NS" create secret generic codewire-credential-database \
    --from-literal="url=$KIND_REAL_CREDENTIAL_DATABASE_URL" --dry-run=client -o yaml | kubectl_apply -f -
  load_kind_github_app
  log "switching credential-service to the production binary (Kind test KEK, origin ${KIND_PUBLIC_ORIGIN})"
  patch_kind_credential_container "$(jq -cn --arg origin "$KIND_PUBLIC_ORIGIN" \
    '[{name: "CODEWIRE_KIND_CREDENTIAL_TEST_KEK", value: "true"},
      {name: "CREDENTIAL_PUBLIC_ORIGIN", value: $origin}]')"
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s
  set_kind_frontend_url "$KIND_PUBLIC_ORIGIN"
  log "credential-service is real; use the dashboard at ${KIND_PUBLIC_ORIGIN}"
  kind_watch_restart_hint
}

switch_kind_credentials_fake() {
  local fixture_patch
  require_kind_services_ci_image
  log "restoring the gate's synthetic credential fixture"
  kubectl_apply -f "$ROOT/tests/e2e/kind/credential-fixture-config.yaml"
  patch_kind_credential_container '[]'
  fixture_patch="$(render_kind_credential_fixture_patch)"
  kubectl -n "$NS" patch deployment codewire-credential-service --type=strategic \
    --patch-file "$fixture_patch"
  kubectl -n "$NS" rollout status deployment/codewire-credential-service --timeout=180s
  set_kind_frontend_url "$KIND_INGRESS_URL"
  kind_watch_restart_hint
}

run_retained_credential_mode() {
  require_kind_errexit
  require_tool jq
  require_tool kind
  require_tool kubectl
  trap retained_suite_cleanup EXIT
  # Switching modes uses no workspace image, so it needs the cluster's identity
  # and runtime, not a verified-source receipt matching this worktree.
  validate_retained_cluster_identity
  case "$1" in
    real) switch_kind_credentials_real ;;
    fake) switch_kind_credentials_fake ;;
  esac
}
