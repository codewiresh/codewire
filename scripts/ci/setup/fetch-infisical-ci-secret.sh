#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 SECRET_NAME OUTPUT_FILE" >&2
  exit 2
fi

secret_name="$1"
output_file="$2"
case "$secret_name" in
  GITEA_REGISTRY_TOKEN|GHCR_PUBLISH_TOKEN) ;;
  *)
    echo "Unsupported CI secret name" >&2
    exit 1
    ;;
esac

: "${INFISICAL_IDENTITY_ID:?INFISICAL_IDENTITY_ID is required}"
: "${INFISICAL_SA_TOKEN_PATH:?INFISICAL_SA_TOKEN_PATH is required}"
if [ ! -f "$INFISICAL_SA_TOKEN_PATH" ] \
  || [ ! -s "$INFISICAL_SA_TOKEN_PATH" ]; then
  echo "Infisical service-account token file is missing or empty" >&2
  exit 1
fi
# System runners reach CI-only secrets through the network-policy-limited
# Infisical service. The public HTTPS ingress intentionally cannot read them.
if [ -n "${INFISICAL_API_URL:-}" ]; then
  infisical_api_url="${INFISICAL_API_URL%/}"
elif [ -n "${INFISICAL_HOST:-}" ]; then
  infisical_api_url="${INFISICAL_HOST%/}"
  case "$infisical_api_url" in
    */api) ;;
    *) infisical_api_url="$infisical_api_url/api" ;;
  esac
else
  infisical_api_url=''
fi
if [[ "$infisical_api_url" == *[$'\r\n']* ]]; then
  echo "Infisical CI API endpoint is malformed" >&2
  exit 1
fi
case "$infisical_api_url" in
  https://*) ;;
  http://infisical-backend.infisical.svc:8080/api) ;;
  http://infisical-backend.infisical.svc.cluster.local:8080/api) ;;
  *)
    if [[ "$infisical_api_url" =~ ^http://10\.43\.([0-9]{1,3})\.([0-9]{1,3}):8080/api$ ]] \
      && ((10#${BASH_REMATCH[1]} <= 255)) \
      && ((10#${BASH_REMATCH[2]} <= 255)); then
      :
    else
      echo "Infisical CI API endpoint is not a reviewed system service" >&2
      exit 1
    fi
    ;;
esac
if [[ "$infisical_api_url" == *'?'* ]] \
  || [[ "$infisical_api_url" == *'#'* ]]; then
  echo "Infisical CI API endpoint must not contain a query or fragment" >&2
  exit 1
fi
if [[ ! "$INFISICAL_IDENTITY_ID" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "INFISICAL_IDENTITY_ID is malformed" >&2
  exit 1
fi

output_dir="$(dirname -- "$output_file")"
output_name="$(basename -- "$output_file")"
if [ ! -d "$output_dir" ] || [ "$output_name" = . ] \
  || [ "$output_name" = .. ]; then
  echo "Secret output directory does not exist" >&2
  exit 1
fi

curl_bin="${CURL_BIN:-curl}"
if [[ "$curl_bin" == */* ]]; then
  [ -x "$curl_bin" ] || {
    echo "curl is required for Infisical secret retrieval" >&2
    exit 1
  }
elif ! command -v "$curl_bin" >/dev/null 2>&1; then
  echo "curl is required for Infisical secret retrieval" >&2
  exit 1
fi
command -v jq >/dev/null 2>&1 || {
  echo "jq is required for Infisical secret retrieval" >&2
  exit 1
}

umask 077
work="$(mktemp -d)"
auth_request="$work/auth-request.json"
auth_response="$work/auth-response.json"
auth_header="$work/auth-header"
secret_response="$work/secret-response.json"
output_tmp="$(mktemp "$output_dir/.${output_name}.XXXXXX")"
cleanup() {
  find "$work" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$work"
  if [ -n "$output_tmp" ] && [ -e "$output_tmp" ]; then
    shred -u "$output_tmp" 2>/dev/null || rm -f "$output_tmp"
  fi
}
trap cleanup EXIT

jq -n \
  --arg identityId "$INFISICAL_IDENTITY_ID" \
  --rawfile jwt "$INFISICAL_SA_TOKEN_PATH" \
  '{identityId: $identityId, jwt: ($jwt | rtrimstr("\n") | rtrimstr("\r"))}' \
  >"$auth_request"

auth_status="$(
  "$curl_bin" -sS -o "$auth_response" -w '%{http_code}' \
    -X POST "${infisical_api_url%/}/v1/auth/oidc-auth/login" \
    -H 'Content-Type: application/json' \
    --data-binary "@$auth_request"
)"
if [[ ! "$auth_status" =~ ^2[0-9][0-9]$ ]]; then
  echo "Failed to authenticate to Infisical (HTTP $auth_status)" >&2
  exit 1
fi
if ! jq -er '"Authorization: Bearer " + (.accessToken // empty)' \
  "$auth_response" >"$auth_header"; then
  echo "Failed to authenticate to Infisical: missing access token" >&2
  exit 1
fi

secret_status="$(
  "$curl_bin" -sS -o "$secret_response" -w '%{http_code}' \
    "${infisical_api_url%/}/v3/secrets/raw/${secret_name}?workspaceSlug=shared&environment=prod&secretPath=/ci" \
    -H "@$auth_header"
)"
if [[ ! "$secret_status" =~ ^2[0-9][0-9]$ ]]; then
  echo "Failed to fetch $secret_name from Infisical (HTTP $secret_status)" >&2
  exit 1
fi
if ! jq -erj '.secret.secretValue // empty' "$secret_response" >"$output_tmp" \
  || [ ! -s "$output_tmp" ]; then
  echo "Failed to fetch $secret_name from Infisical: missing secret value" >&2
  exit 1
fi

chmod 0600 "$output_tmp"
mv -f -- "$output_tmp" "$output_file"
output_tmp=""
printf 'Fetched %s into a private credential file\n' "$secret_name"
