#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly PLATFORM_BASE_URL="https://infisical.example.invalid"
readonly PLATFORM_PROJECT_ID="00000000-0000-0000-0000-000000000000"
readonly PLATFORM_ENVIRONMENT="dev"
readonly PLATFORM_SECRET_PATH_ENCODED="%2F"
readonly KEYRING_SERVICE="codewire-dev-smoke-auth"
readonly KEYRING_KIND="infisical-universal-auth"
readonly CONNECT_TIMEOUT_SECONDS="5"
readonly TOTAL_TIMEOUT_SECONDS="15"
readonly KEYRING_TIMEOUT_SECONDS="5"

AUTH_TMPDIR=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/with-dev-smoke-auth.sh [--] [command args...]

Loads the two dedicated dev smoke auth values with the scoped
codewire-dev-smoke-auth machine identity, validates them, removes all
Infisical material, and execs the requested command. With no command, runs:

  scripts/runtime/dev/smoke-dev-commodity.sh

The Universal Auth credential must already exist in the unlocked Secret
Service as one JSON value with clientId, clientSecret, and clientSecretId,
under these exact attributes:

  service=codewire-dev-smoke-auth
  kind=infisical-universal-auth

The wrapper is intentionally non-interactive. It never falls back to a human
Infisical login, browser, or email flow.
USAGE
}

log() {
  printf '[runtime-smoke-auth] %s\n' "$*" >&2
}

die() {
  printf '[runtime-smoke-auth] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local dir="${AUTH_TMPDIR:-}"
  [[ -n "$dir" ]] || return 0
  rm -rf -- "$dir" || return 1
  [[ ! -e "$dir" ]] || return 1
  AUTH_TMPDIR=""
}

unset_infisical_environment() {
  local name
  local -a names=( "${!INFISICAL_@}" )

  for name in "${names[@]}"; do
    unset "$name" 2>/dev/null || die "cannot remove inherited Infisical environment"
  done
}

new_private_file() {
  local path="$1"
  : >"$path"
  chmod 0600 "$path"
}

write_curl_config() {
  local path="$1"
  local method="$2"
  local url="$3"

  {
    printf 'silent\n'
    printf 'show-error\n'
    printf 'fail\n'
    printf 'globoff\n'
    printf 'retry = 0\n'
    printf 'connect-timeout = %s\n' "$CONNECT_TIMEOUT_SECONDS"
    printf 'max-time = %s\n' "$TOTAL_TIMEOUT_SECONDS"
    printf 'proto = "=https"\n'
    printf 'request = "%s"\n' "$method"
    printf 'url = "%s"\n' "$url"
  } >"$path"
  chmod 0600 "$path"
}

fetch_secret() {
  local name="$1"
  local output_file="$2"
  local response_file="$AUTH_TMPDIR/${name}.response.json"
  local curl_config="$AUTH_TMPDIR/${name}.curl"
  local url="${PLATFORM_BASE_URL}/api/v4/secrets/${name}?projectId=${PLATFORM_PROJECT_ID}&environment=${PLATFORM_ENVIRONMENT}&secretPath=${PLATFORM_SECRET_PATH_ENCODED}&type=shared&viewSecretValue=true&expandSecretReferences=false"

  new_private_file "$response_file"
  new_private_file "$curl_config"
  write_curl_config "$curl_config" "GET" "$url"
  jq -Rr '
    "header = " + ("Authorization: Bearer " + . | @json)
  ' "$AUTH_TMPDIR/access-token" >>"$curl_config"

  if ! curl --disable --config "$curl_config" --output "$response_file" 2>/dev/null; then
    die "failed to fetch the scoped $name value from Infisical; output suppressed"
  fi

  if ! jq -er --arg name "$name" '
    if type == "object"
      and (.secret | type == "object")
      and .secret.secretKey == $name
      and (.secret.secretValue | type == "string")
      and (.secret.secretValue | length > 0)
    then .secret.secretValue
    else error("unexpected secret response")
    end
  ' "$response_file" >"$output_file" 2>/dev/null; then
    die "Infisical returned an unexpected response for $name"
  fi
}

trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

for required_command in curl jq secret-tool timeout; do
  command -v "$required_command" >/dev/null 2>&1 || \
    die "missing required command: $required_command"
done

# Do not allow inherited credentials or stale smoke values to reach any child
# process. This wrapper has one credential source: the exact Secret Service
# item documented above.
unset_infisical_environment
unset CODEWIRE_DEV_SMOKE_API_KEY EXPECTED_CODEWIRE_SMOKE_USER_EMAIL CODEWIRE_API_KEY 2>/dev/null || \
  die "cannot remove inherited smoke auth environment"
ulimit -c 0 || die "cannot disable core dumps"

umask 077
AUTH_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/codewire-dev-smoke-auth.XXXXXX")"
chmod 0700 "$AUTH_TMPDIR"

KEYRING_SEARCH="$AUTH_TMPDIR/keyring-search"
CREDENTIAL_FILE="$AUTH_TMPDIR/universal-auth.json"
LOGIN_PAYLOAD="$AUTH_TMPDIR/login-payload.json"
LOGIN_RESPONSE="$AUTH_TMPDIR/login-response.json"
LOGIN_CONFIG="$AUTH_TMPDIR/login.curl"
API_KEY_FILE="$AUTH_TMPDIR/CODEWIRE_DEV_SMOKE_API_KEY"
EMAIL_FILE="$AUTH_TMPDIR/EXPECTED_CODEWIRE_SMOKE_USER_EMAIL"

for private_file in \
  "$KEYRING_SEARCH" \
  "$CREDENTIAL_FILE" \
  "$LOGIN_PAYLOAD" \
  "$LOGIN_RESPONSE" \
  "$LOGIN_CONFIG" \
  "$API_KEY_FILE" \
  "$EMAIL_FILE"; do
  new_private_file "$private_file"
done

# secret-tool lookup unlocks locked items and can prompt. Search without
# --unlock is the non-interactive Secret Service lookup: an absent or locked
# exact match therefore fails closed before any network request.
if ! timeout --signal=TERM --kill-after=1s "${KEYRING_TIMEOUT_SECONDS}s" \
    secret-tool search --all \
      service "$KEYRING_SERVICE" \
      kind "$KEYRING_KIND" \
      >"$KEYRING_SEARCH" 2>/dev/null; then
  die "Secret Service credential lookup failed or timed out"
fi

if ! awk '
  /^secret = / {
    count++
    if (count == 1) {
      sub(/^secret = /, "")
      print
    }
  }
  END { if (count != 1) exit 1 }
' "$KEYRING_SEARCH" >"$CREDENTIAL_FILE"; then
  die "Secret Service credential is absent, locked, or ambiguous"
fi

if ! jq -e '
  type == "object"
    and (.clientId | type == "string" and length > 0)
    and (.clientSecret | type == "string" and length > 0)
    and (.clientSecretId | type == "string" and length > 0)
' "$CREDENTIAL_FILE" >/dev/null 2>&1; then
  die "Secret Service credential has an unexpected shape"
fi

if ! jq -c '{clientId, clientSecret}' "$CREDENTIAL_FILE" >"$LOGIN_PAYLOAD" 2>/dev/null; then
  die "failed to prepare the Universal Auth exchange"
fi

write_curl_config \
  "$LOGIN_CONFIG" \
  "POST" \
  "${PLATFORM_BASE_URL}/api/v1/auth/universal-auth/login"
printf 'header = "Content-Type: application/json"\n' >>"$LOGIN_CONFIG"

if ! curl \
    --disable \
    --config "$LOGIN_CONFIG" \
    --data-binary "@$LOGIN_PAYLOAD" \
    --output "$LOGIN_RESPONSE" \
    2>/dev/null; then
  die "Infisical Universal Auth exchange failed or timed out; output suppressed"
fi

if ! jq -e '
  type == "object"
    and (.accessToken | type == "string" and length > 0)
    and ((.accessToken | test("[\\r\\n]")) | not)
    and .tokenType == "Bearer"
    and (.expiresIn | type == "number" and . > 0 and . <= 300)
    and (.accessTokenMaxTTL | type == "number" and . > 0 and . <= 300)
' "$LOGIN_RESPONSE" >/dev/null 2>&1; then
  die "Infisical Universal Auth returned an unexpected token response"
fi

new_private_file "$AUTH_TMPDIR/access-token"
if ! jq -er '.accessToken' "$LOGIN_RESPONSE" >"$AUTH_TMPDIR/access-token" 2>/dev/null; then
  die "failed to isolate the Universal Auth access token"
fi

# Infra limits this token to two uses. Keep this list literal and exhaustive:
# one authenticated request for each permitted secret, with no list, describe,
# retry, renewal, or revoke request.
fetch_secret "CODEWIRE_DEV_SMOKE_API_KEY" "$API_KEY_FILE"
fetch_secret "EXPECTED_CODEWIRE_SMOKE_USER_EMAIL" "$EMAIL_FILE"

if ! awk '
  NR == 1 && /^cw_[0-9a-f]{64}$/ { valid = 1; next }
  { valid = 0; exit }
  END { exit valid == 1 ? 0 : 1 }
' "$API_KEY_FILE"; then
  die "CODEWIRE_DEV_SMOKE_API_KEY from Infisical has an unexpected shape"
fi
if ! awk '
  NR == 1 && /^[^[:space:]@]+@[^[:space:]@]+$/ { valid = 1; next }
  { valid = 0; exit }
  END { exit valid == 1 ? 0 : 1 }
' "$EMAIL_FILE"; then
  die "EXPECTED_CODEWIRE_SMOKE_USER_EMAIL from Infisical has an unexpected shape"
fi

IFS= read -r CODEWIRE_DEV_SMOKE_API_KEY <"$API_KEY_FILE"
IFS= read -r EXPECTED_CODEWIRE_SMOKE_USER_EMAIL <"$EMAIL_FILE"

# An exec does not run the EXIT trap. Remove credentials, token, responses,
# curl configs, and secret copies before exposing only the two established
# smoke variables to the requested command.
cleanup || die "failed to remove temporary smoke auth material"
trap - EXIT HUP INT TERM
unset_infisical_environment
unset CODEWIRE_API_KEY
export CODEWIRE_DEV_SMOKE_API_KEY
export EXPECTED_CODEWIRE_SMOKE_USER_EMAIL

if [[ "${1:-}" == "--" ]]; then
  shift
fi
if [[ "$#" -eq 0 ]]; then
  set -- "$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
fi

log "loaded the two fixed dev smoke values with scoped machine auth"
exec "$@"
