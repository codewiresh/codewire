#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PLATFORM_INFISICAL_DOMAIN="https://infisical.example.invalid"
PLATFORM_INFISICAL_PROJECT_ID="00000000-0000-0000-0000-000000000000"
PLATFORM_INFISICAL_PATH="/"

TARGET=""
TMPDIR_AUTH=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/apikey/with-apikey-smoke-auth.sh --target dev|prod|prod-evidence-secondary [--] [command args...]

Loads exactly one target-scoped ApiKey smoke bootstrap key from the canonical
platform Infisical project, removes Infisical credentials, and execs the
command in the same short-lived process environment. With no command, runs
the ApiKey lifecycle smoke for the selected target.

Supports either local Infisical CLI authentication or the Gitea runner's
INFISICAL_API_URL / INFISICAL_IDENTITY_ID / INFISICAL_SA_TOKEN_PATH OIDC
environment. It never writes the raw key to GITHUB_ENV or stdout.
USAGE
}

log() {
  printf '[apikey-smoke-auth] %s\n' "$*" >&2
}

die() {
  printf '[apikey-smoke-auth] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TMPDIR_AUTH" && -d "$TMPDIR_AUTH" ]]; then
    rm -rf "$TMPDIR_AUTH"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while (($# > 0)); do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || die "--target requires dev, prod, or prod-evidence-secondary"
      TARGET="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

case "$TARGET" in
  dev)
    INFISICAL_ENVIRONMENT="dev"
    INFISICAL_SECRET_NAME="CODEWIRE_APIKEY_DEV_SMOKE_BOOTSTRAP_KEY"
    ;;
  prod)
    INFISICAL_ENVIRONMENT="prod"
    INFISICAL_SECRET_NAME="CODEWIRE_APIKEY_PROD_SMOKE_BOOTSTRAP_KEY"
    ;;
  prod-evidence-secondary)
    INFISICAL_ENVIRONMENT="prod"
    INFISICAL_SECRET_NAME="CODEWIRE_APIKEY_PROD_EVIDENCE_SECONDARY_BOOTSTRAP_KEY"
    ;;
  *)
    die "--target must be dev, prod, or prod-evidence-secondary"
    ;;
esac

if (($# == 0)); then
  set -- "$ROOT/scripts/runtime/apikey/smoke-apikey-lifecycle.sh" --target "$TARGET"
fi

umask 077
TMPDIR_AUTH="$(mktemp -d "${TMPDIR:-/tmp}/codewire-apikey-smoke-auth.XXXXXX")"
chmod 0700 "$TMPDIR_AUTH"
KEY_FILE="$TMPDIR_AUTH/bootstrap-key"
touch "$KEY_FILE"
chmod 0600 "$KEY_FILE"

oidc_fields=0
for name in INFISICAL_API_URL INFISICAL_IDENTITY_ID INFISICAL_SA_TOKEN_PATH; do
  [[ -n "${!name:-}" ]] && oidc_fields=$((oidc_fields + 1))
done

if [[ "$oidc_fields" == "3" ]]; then
  for command in curl jq; do
    command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
  done
  [[ -f "$INFISICAL_SA_TOKEN_PATH" ]] || \
    die "INFISICAL_SA_TOKEN_PATH does not point to a file"

  auth_payload="$TMPDIR_AUTH/auth-payload.json"
  auth_response="$TMPDIR_AUTH/auth-response.json"
  jq -n \
    --arg identityId "$INFISICAL_IDENTITY_ID" \
    --rawfile jwt "$INFISICAL_SA_TOKEN_PATH" \
    '{identityId: $identityId, jwt: ($jwt | rtrimstr("\n"))}' \
    >"$auth_payload"
  auth_status="$(
    curl -sS -o "$auth_response" -w '%{http_code}' \
      -X POST "${INFISICAL_API_URL%/}/v1/auth/oidc-auth/login" \
      -H 'Content-Type: application/json' \
      --data-binary "@$auth_payload"
  )"
  [[ "$auth_status" =~ ^2 ]] || die "Infisical OIDC authentication failed (HTTP $auth_status)"
  access_token="$(jq -er '.accessToken // empty' "$auth_response")" || \
    die "Infisical OIDC authentication returned no access token"

  urlencode() {
    jq -rn --arg value "$1" '$value|@uri'
  }
  project_q="$(urlencode "$PLATFORM_INFISICAL_PROJECT_ID")"
  environment_q="$(urlencode "$INFISICAL_ENVIRONMENT")"
  path_q="$(urlencode "$PLATFORM_INFISICAL_PATH")"
  secret_q="$(urlencode "$INFISICAL_SECRET_NAME")"
  secret_response="$TMPDIR_AUTH/secret-response.json"
  curl_config="$TMPDIR_AUTH/secret-fetch.curl"
  : >"$curl_config"
  chmod 0600 "$curl_config"
  {
    printf 'url = "%s/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s"\n' \
      "${INFISICAL_API_URL%/}" "$secret_q" "$project_q" "$environment_q" "$path_q"
    printf 'header = "Authorization: Bearer %s"\n' "$access_token"
    printf 'output = "%s"\n' "$secret_response"
    printf 'silent\nshow-error\n'
  } >"$curl_config"
  secret_status="$(curl --config "$curl_config" --write-out '%{http_code}')"
  [[ "$secret_status" =~ ^2 ]] || \
    die "failed to fetch target=$TARGET ApiKey smoke secret (HTTP $secret_status)"
  jq -er '.secret.secretValue // empty' "$secret_response" >"$KEY_FILE" || \
    die "target=$TARGET ApiKey smoke secret was missing"
  unset access_token
elif [[ "$oidc_fields" == "0" ]]; then
  command -v infisical >/dev/null 2>&1 || die "missing required command: infisical"
  if ! infisical secrets get "$INFISICAL_SECRET_NAME" \
    --env "$INFISICAL_ENVIRONMENT" \
    --path "$PLATFORM_INFISICAL_PATH" \
    --domain "$PLATFORM_INFISICAL_DOMAIN" \
    --projectId "$PLATFORM_INFISICAL_PROJECT_ID" \
    --plain \
    --silent \
    --log-level error \
    >"$KEY_FILE" 2>"$TMPDIR_AUTH/infisical.err"; then
    die "failed to fetch target=$TARGET ApiKey smoke secret; output suppressed"
  fi
else
  die "Gitea Infisical OIDC environment is incomplete"
fi

if ! awk 'BEGIN { ok=0 } /^cw_[0-9a-f]{64}$/ { ok++ } END { exit ok == 1 ? 0 : 1 }' "$KEY_FILE"; then
  die "target=$TARGET ApiKey smoke secret has an unexpected shape"
fi

CODEWIRE_API_KEY="$(awk 'NR == 1 { print; exit }' "$KEY_FILE")"
export CODEWIRE_API_KEY
unset INFISICAL_TOKEN INFISICAL_ACCESS_TOKEN INFISICAL_IDENTITY_ID INFISICAL_SA_TOKEN_PATH
unset access_token

# The raw key now lives only in the child process environment. Remove every
# on-disk copy before exec; an exec does not run the EXIT trap.
cleanup
TMPDIR_AUTH=""
trap - EXIT HUP INT TERM

log "loaded target=$TARGET bootstrap key into a same-process environment"
exec "$@"
