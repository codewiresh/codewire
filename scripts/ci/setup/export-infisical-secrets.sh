#!/usr/bin/env bash
set -euo pipefail

die() {
  printf '[ci-infisical] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[ci-infisical] %s\n' "$*" >&2
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

if [[ "$#" -lt 1 ]]; then
  die "usage: scripts/ci/setup/export-infisical-secrets.sh SECRET_NAME [SECRET_NAME...]"
fi

: "${INFISICAL_API_URL:?INFISICAL_API_URL is required}"
: "${INFISICAL_IDENTITY_ID:?INFISICAL_IDENTITY_ID is required}"
: "${INFISICAL_SA_TOKEN_PATH:?INFISICAL_SA_TOKEN_PATH is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

[[ -f "$INFISICAL_SA_TOKEN_PATH" ]] || die "INFISICAL_SA_TOKEN_PATH does not point to a file"
command -v curl >/dev/null 2>&1 || die "missing required command: curl"
command -v jq >/dev/null 2>&1 || die "missing required command: jq"

INFISICAL_WORKSPACE_SLUG="${INFISICAL_WORKSPACE_SLUG:-codewire}"
INFISICAL_ENVIRONMENT="${INFISICAL_ENVIRONMENT:-dev}"
INFISICAL_SECRET_PATH="${INFISICAL_SECRET_PATH:-/}"
INFISICAL_API_BASE="${INFISICAL_API_URL%/}"

TMPDIR_INFISICAL="$(mktemp -d "${TMPDIR:-/tmp}/codewire-ci-infisical.XXXXXX")"
chmod 0700 "$TMPDIR_INFISICAL"
cleanup() {
  rm -rf "$TMPDIR_INFISICAL"
}
trap cleanup EXIT

urlencode() {
  jq -rn --arg v "$1" '$v|@uri'
}

auth_response="$TMPDIR_INFISICAL/auth.json"
auth_payload="$TMPDIR_INFISICAL/auth-payload.json"
jq -n \
  --arg identityId "$INFISICAL_IDENTITY_ID" \
  --arg jwt "$(<"$INFISICAL_SA_TOKEN_PATH")" \
  '{identityId: $identityId, jwt: $jwt}' >"$auth_payload"
auth_status="$(
  curl -sS -o "$auth_response" -w "%{http_code}" \
    -X POST "${INFISICAL_API_BASE}/v1/auth/oidc-auth/login" \
    -H "Content-Type: application/json" \
    --data @"$auth_payload"
)"
if [[ ! "$auth_status" =~ ^2 ]]; then
  die "failed to authenticate to Infisical (HTTP ${auth_status})"
fi

access_token="$(jq -er '.accessToken // empty' "$auth_response")" || \
  die "failed to authenticate to Infisical: missing access token"

workspace_q="$(urlencode "$INFISICAL_WORKSPACE_SLUG")"
environment_q="$(urlencode "$INFISICAL_ENVIRONMENT")"
path_q="$(urlencode "$INFISICAL_SECRET_PATH")"

for secret_name in "$@"; do
  [[ "$secret_name" =~ ^[A-Z0-9_]+$ ]] || die "invalid secret env name: $secret_name"

  secret_response="$TMPDIR_INFISICAL/${secret_name}.json"
  secret_name_q="$(urlencode "$secret_name")"
  secret_status="$(
    curl -sS -o "$secret_response" -w "%{http_code}" \
      "${INFISICAL_API_BASE}/v3/secrets/raw/${secret_name_q}?workspaceSlug=${workspace_q}&environment=${environment_q}&secretPath=${path_q}" \
      -H "Authorization: Bearer ${access_token}"
  )"
  if [[ ! "$secret_status" =~ ^2 ]]; then
    die "failed to fetch $secret_name from Infisical (HTTP ${secret_status})"
  fi

  secret_value="$(jq -er '.secret.secretValue // empty' "$secret_response")" || \
    die "failed to fetch $secret_name from Infisical: missing secret value"

  delimiter="CODEWIRE_SECRET_${secret_name}_EOF_$(date +%s)_${RANDOM}"
  {
    printf '%s<<%s\n' "$secret_name" "$delimiter"
    printf '%s\n' "$secret_value"
    printf '%s\n' "$delimiter"
  } >>"$GITHUB_ENV"
  unset secret_value
  log "exported $secret_name from Infisical env=$INFISICAL_ENVIRONMENT path=$INFISICAL_SECRET_PATH"
done

unset access_token
