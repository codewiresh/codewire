#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

KUBE_CONTEXT="${KUBE_CONTEXT:-csrke2}"
PROD_NAMESPACE="${PROD_NAMESPACE:-prod}"
CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire.sh}"
CODEWIRE_IDP_URL="${CODEWIRE_IDP_URL:-$CODEWIRE_SERVER_URL}"
CODEWIRE_DERP_URL="${CODEWIRE_DERP_URL:-https://derp.codewire.sh}"
CW_BIN="${CW_BIN:-cw}"
SMOKE_NAME="${SMOKE_NAME:-prod-rc-$(date -u +%Y%m%d%H%M%S)}"
SMOKE_TTL="${SMOKE_TTL:-2h}"
SMOKE_TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-1200}"
SMOKE_KEEP_ENV="${SMOKE_KEEP_ENV:-0}"
SMOKE_SKIP_KUBE="${SMOKE_SKIP_KUBE:-0}"
SMOKE_SKIP_PUBLIC="${SMOKE_SKIP_PUBLIC:-0}"
SMOKE_SKIP_AUTHENTICATED="${SMOKE_SKIP_AUTHENTICATED:-1}"
SMOKE_PRESET="${SMOKE_PRESET:-}"
SMOKE_REPO="${SMOKE_REPO:-}"
SMOKE_ENV_ID="${SMOKE_ENV_ID:-}"
ALLOW_PROD_MUTATION=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/ci/verify/smoke-prod.sh [options]
  scripts/ci/verify/smoke-prod.sh --authenticated --allow-prod-mutation --preset PRESET --repo REPO

Runs the production Rust release-candidate smoke checks. By default this runs
only read-only Kubernetes rollout and public endpoint checks. The authenticated
environment smoke is opt-in and requires both --authenticated and
--allow-prod-mutation, plus CODEWIRE_PROD_SMOKE_API_KEY or CODEWIRE_API_KEY.

Options:
  --authenticated          Run the authenticated environment smoke.
  --allow-prod-mutation    Required with --authenticated before creating or
                           deleting a production smoke environment.
  --preset PRESET          Preset slug for the smoke environment.
  --repo REPO              Repository URL for the smoke environment.
  --existing-env ID        Reuse an existing environment and keep it.
  --name NAME              Environment name for a new smoke environment.
  --ttl TTL                TTL for a new smoke environment (default: 2h).
  --timeout-seconds N      Wait budget for environment startup (default: 1200).
  --keep-env               Keep a newly-created smoke environment.
  --skip-kube              Skip production Kubernetes rollout checks.
  --skip-public            Skip public HTTP endpoint checks.
  --server URL             Codewire platform URL (default: https://codewire.sh).
  --idp-url URL            IdP URL (default: same as --server).
  --derp-url URL           DERP URL (default: https://derp.codewire.sh).
  --cw-bin PATH            cw binary to use (default: cw on PATH).
  -h, --help               Show this help.

Environment:
  KUBE_CONTEXT             Production kube context (default: csrke2).
  PROD_NAMESPACE           Production namespace (default: prod).
  CODEWIRE_PROD_SMOKE_API_KEY
                           Preferred API key for authenticated production smoke.
  CODEWIRE_API_KEY         Accepted when CODEWIRE_PROD_SMOKE_API_KEY is unset.

Safety:
  - refuses to run with shell tracing enabled
  - does not print API keys
  - deletes only the environment it created unless --keep-env is set
  - does not tag, deploy, or roll back production
USAGE
}

log() {
  printf '[prod-smoke] %s\n' "$*" >&2
}

die() {
  printf '[prod-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_uint() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an unsigned integer, got '$value'"
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --authenticated)
      SMOKE_SKIP_AUTHENTICATED=0
      shift
      ;;
    --allow-prod-mutation)
      ALLOW_PROD_MUTATION=1
      shift
      ;;
    --preset)
      [[ "$#" -ge 2 ]] || die "--preset requires a value"
      SMOKE_PRESET="$2"
      shift 2
      ;;
    --repo)
      [[ "$#" -ge 2 ]] || die "--repo requires a value"
      SMOKE_REPO="$2"
      shift 2
      ;;
    --existing-env)
      [[ "$#" -ge 2 ]] || die "--existing-env requires a value"
      SMOKE_ENV_ID="$2"
      SMOKE_KEEP_ENV=1
      shift 2
      ;;
    --name)
      [[ "$#" -ge 2 ]] || die "--name requires a value"
      SMOKE_NAME="$2"
      shift 2
      ;;
    --ttl)
      [[ "$#" -ge 2 ]] || die "--ttl requires a value"
      SMOKE_TTL="$2"
      shift 2
      ;;
    --timeout-seconds)
      [[ "$#" -ge 2 ]] || die "--timeout-seconds requires a value"
      SMOKE_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --keep-env)
      SMOKE_KEEP_ENV=1
      shift
      ;;
    --skip-kube)
      SMOKE_SKIP_KUBE=1
      shift
      ;;
    --skip-public)
      SMOKE_SKIP_PUBLIC=1
      shift
      ;;
    --server)
      [[ "$#" -ge 2 ]] || die "--server requires a value"
      CODEWIRE_SERVER_URL="$2"
      shift 2
      ;;
    --idp-url)
      [[ "$#" -ge 2 ]] || die "--idp-url requires a value"
      CODEWIRE_IDP_URL="$2"
      shift 2
      ;;
    --derp-url)
      [[ "$#" -ge 2 ]] || die "--derp-url requires a value"
      CODEWIRE_DERP_URL="$2"
      shift 2
      ;;
    --cw-bin)
      [[ "$#" -ge 2 ]] || die "--cw-bin requires a value"
      CW_BIN="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

require_uint SMOKE_TIMEOUT_SECONDS "$SMOKE_TIMEOUT_SECONDS"

if [[ "$SMOKE_SKIP_AUTHENTICATED" == "0" ]]; then
  [[ "$ALLOW_PROD_MUTATION" == "1" ]] || \
    die "--authenticated requires --allow-prod-mutation"
  [[ -n "$SMOKE_ENV_ID" || -n "$SMOKE_PRESET" ]] || \
    die "--authenticated requires --preset unless --existing-env is used"
  [[ -n "$SMOKE_ENV_ID" || -n "$SMOKE_REPO" ]] || \
    die "--authenticated requires --repo unless --existing-env is used"
fi

kubectl_prod() {
  kubectl --context "$KUBE_CONTEXT" "$@"
}

curl_status() {
  local url="$1"
  curl -sS -o /dev/null -w '%{http_code}' "$url"
}

assert_http_status() {
  local label="$1"
  local url="$2"
  shift 2
  local status allowed

  status="$(curl_status "$url")"
  for allowed in "$@"; do
    if [[ "$status" == "$allowed" ]]; then
      printf '%-28s %s %s\n' "$label" "$status" "$url"
      return 0
    fi
  done
  die "$label returned HTTP $status for $url; expected one of: $*"
}

run_kube_checks() {
  local deployment

  require_cmd kubectl
  log "checking production rollouts in namespace $PROD_NAMESPACE on context $KUBE_CONTEXT"
  for deployment in \
    codewire-orchestration \
    codewire-billing \
    codewire-idp \
    codewire-mesh \
    codewire-derp
  do
    kubectl_prod -n "$PROD_NAMESPACE" rollout status "deployment/$deployment" --timeout=300s
  done
  kubectl_prod -n "$PROD_NAMESPACE" get deploy,svc
}

run_public_checks() {
  require_cmd curl
  require_cmd jq

  log "checking public production endpoints"
  assert_http_status "platform healthz" "$CODEWIRE_SERVER_URL/healthz" 200
  assert_http_status "platform readyz" "$CODEWIRE_SERVER_URL/readyz" 200

  curl -fsS "$CODEWIRE_IDP_URL/.well-known/openid-configuration" |
    jq -e --arg issuer "$CODEWIRE_IDP_URL" '.issuer == $issuer' >/dev/null
  printf '%-28s %s %s\n' "idp discovery" "ok" "$CODEWIRE_IDP_URL/.well-known/openid-configuration"

  assert_http_status "derp latency" "$CODEWIRE_DERP_URL/derp/latency-check" 200
}

configure_cw_auth() {
  local token="${CODEWIRE_PROD_SMOKE_API_KEY:-${CODEWIRE_API_KEY:-}}"
  [[ -n "$token" ]] || die "CODEWIRE_PROD_SMOKE_API_KEY or CODEWIRE_API_KEY is required"
  export CODEWIRE_API_KEY="$token"
}

cw_prod() {
  "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"
}

create_environment() {
  local output
  output="$(mktemp "$ROOT/.tmp/prod-smoke-create.XXXXXX")"
  log "creating production smoke environment $SMOKE_NAME"
  if ! cw_prod env create \
      --preset "$SMOKE_PRESET" \
      --repo "$SMOKE_REPO" \
      --name "$SMOKE_NAME" \
      --ttl "$SMOKE_TTL" \
      --no-org-secrets \
      --no-user-secrets \
      --no-network \
      --no-wait \
      --yes >"$output" 2>&1; then
    sed 's/[[:cntrl:]]//g' "$output" >&2 || true
    rm -f "$output"
    die "cw env create failed"
  fi

  SMOKE_ENV_ID="$(awk '/^[[:space:]]*ID:/ {print $2; exit}' "$output")"
  if [[ -z "$SMOKE_ENV_ID" ]]; then
    sed 's/[[:cntrl:]]//g' "$output" >&2 || true
    rm -f "$output"
    die "failed to parse environment ID from cw env create output"
  fi
  rm -f "$output"
  log "production smoke environment id $SMOKE_ENV_ID"
}

cleanup_environment() {
  if [[ -z "${SMOKE_CREATED_ENV_ID:-}" || "$SMOKE_KEEP_ENV" == "1" ]]; then
    return 0
  fi
  log "deleting production smoke environment $SMOKE_CREATED_ENV_ID"
  cw_prod env rm "$SMOKE_CREATED_ENV_ID" --yes >/dev/null || true
}

environment_state() {
  local info_out="$1"
  awk '$1 == "State:" {print $2; exit}' "$info_out"
}

environment_error_reason() {
  local info_out="$1"
  awk '$1 == "ErrorReason:" {print substr($0, index($0, $2)); exit}' "$info_out"
}

wait_environment_running() {
  local deadline info state error_reason
  deadline=$(( $(date +%s) + SMOKE_TIMEOUT_SECONDS ))
  info="$(mktemp "$ROOT/.tmp/prod-smoke-info.XXXXXX")"

  log "waiting for environment $SMOKE_ENV_ID to reach running"
  while (( $(date +%s) < deadline )); do
    if cw_prod env info "$SMOKE_ENV_ID" >"$info" 2>&1; then
      state="$(environment_state "$info")"
      error_reason="$(environment_error_reason "$info")"
      if [[ -n "$error_reason" ]]; then
        sed 's/[[:cntrl:]]//g' "$info" >&2 || true
        rm -f "$info"
        die "environment entered error state"
      fi
      if [[ "$state" == "running" ]]; then
        rm -f "$info"
        log "environment $SMOKE_ENV_ID is running"
        return 0
      fi
    fi
    sleep 10
  done

  sed 's/[[:cntrl:]]//g' "$info" >&2 || true
  rm -f "$info"
  die "environment $SMOKE_ENV_ID did not reach running within ${SMOKE_TIMEOUT_SECONDS}s"
}

run_authenticated_checks() {
  local tmp_local
  local remote_path="/workspace/.codewire-prod-smoke"

  require_cmd "$CW_BIN"
  require_cmd jq
  configure_cw_auth
  tmp_local="$(mktemp "$ROOT/.tmp/prod-smoke-file.XXXXXX")"

  cw_prod whoami --output json | jq -e '.email and .email != ""' >/dev/null
  printf '%-28s %s\n' "cw whoami" "ok"

  if [[ -z "$SMOKE_ENV_ID" ]]; then
    create_environment
    SMOKE_CREATED_ENV_ID="$SMOKE_ENV_ID"
    trap cleanup_environment EXIT
  else
    log "using existing production smoke environment $SMOKE_ENV_ID"
  fi

  wait_environment_running

  cw_prod run --no-tty "$SMOKE_ENV_ID" -- pwd
  printf 'prod-smoke\n' >"$tmp_local"
  cw_prod env cp "$tmp_local" "$SMOKE_ENV_ID:$remote_path"
  rm -f "$tmp_local"
  cw_prod run --no-tty "$SMOKE_ENV_ID" -- sh -lc "test \"\$(cat '$remote_path')\" = prod-smoke"
  cw_prod doctor tailnet "$SMOKE_ENV_ID" --output json --expect any
}

mkdir -p "$ROOT/.tmp"

if [[ "$SMOKE_SKIP_KUBE" != "1" ]]; then
  run_kube_checks
fi

if [[ "$SMOKE_SKIP_PUBLIC" != "1" ]]; then
  run_public_checks
fi

if [[ "$SMOKE_SKIP_AUTHENTICATED" != "1" ]]; then
  run_authenticated_checks
else
  log "authenticated environment smoke skipped; pass --authenticated --allow-prod-mutation to run it"
fi

log "production smoke completed"
