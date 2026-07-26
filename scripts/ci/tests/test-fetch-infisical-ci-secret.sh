#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCH_SECRET="$ROOT/scripts/ci/setup/fetch-infisical-ci-secret.sh"

fail() {
  printf '[test-fetch-infisical-ci-secret] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-infisical-ci-secret.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output"

jwt='jwt-test-value'
access_token='access-test-value'
registry_token='registry-test-value'
printf '%s' "$jwt" >"$work/identity-token"

cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%q ' "$@" >>"${FAKE_CURL_CALLS:?}"
printf '\n' >>"$FAKE_CURL_CALLS"

output=''
data_file=''
header_file=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output="$2"
      shift 2
      ;;
    -w|-X)
      shift 2
      ;;
    -H)
      [[ "$2" == @* ]] && header_file="${2#@}"
      shift 2
      ;;
    --data-binary)
      data_file="${2#@}"
      shift 2
      ;;
    -sS)
      shift
      ;;
    http*)
      url="$1"
      shift
      ;;
    *)
      echo "unexpected fake curl argument: $1" >&2
      exit 1
      ;;
  esac
done

case "$url" in
  */v1/auth/oidc-auth/login)
    jq -e --arg jwt "${FAKE_JWT:?}" \
      '.identityId == "test-identity" and .jwt == $jwt' "$data_file" >/dev/null
    jq -n --arg value "${FAKE_ACCESS_TOKEN:?}" '{accessToken: $value}' >"$output"
    printf '200'
    ;;
  */v3/secrets/raw/*)
    grep -qxF "Authorization: Bearer ${FAKE_ACCESS_TOKEN:?}" "$header_file"
    if [ "${FAKE_SECRET_STATUS:-200}" != 200 ]; then
      printf '{}\n' >"$output"
      printf '%s' "$FAKE_SECRET_STATUS"
      exit 0
    fi
    jq -n --arg value "${FAKE_REGISTRY_TOKEN:?}" \
      '{secret: {secretValue: $value}}' >"$output"
    printf '200'
    ;;
  *)
    echo "unexpected fake curl URL: $url" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$work/bin/curl"

export CURL_BIN="$work/bin/curl"
export FAKE_CURL_CALLS="$work/curl-calls"
export FAKE_JWT="$jwt"
export FAKE_ACCESS_TOKEN="$access_token"
export FAKE_REGISTRY_TOKEN="$registry_token"
export INFISICAL_HOST='https://infisical-public.test'
export INFISICAL_API_URL='http://10.43.11.114:8080/api'
export INFISICAL_IDENTITY_ID='test-identity'
export INFISICAL_SA_TOKEN_PATH="$work/identity-token"

target="$work/output/gitea-token"
"$FETCH_SECRET" GITEA_REGISTRY_TOKEN "$target"
[[ "$(<"$target")" == "$registry_token" ]] || fail 'registry token changed'
[[ "$(stat -c '%a' "$target")" == 600 ]] || fail 'credential mode is not 0600'
if grep -qF "$jwt" "$FAKE_CURL_CALLS" \
  || grep -qF "$access_token" "$FAKE_CURL_CALLS" \
  || grep -qF "$registry_token" "$FAKE_CURL_CALLS"; then
  fail 'a secret value reached curl command arguments'
fi
grep -qF 'http://10.43.11.114:8080/api/v1/auth/oidc-auth/login' \
  "$FAKE_CURL_CALLS" || fail 'system-cluster Infisical endpoint was not selected'
if grep -qF 'https://infisical-public.test' "$FAKE_CURL_CALLS"; then
  fail 'public Infisical ingress was selected over the CI service'
fi

ghcr_target="$work/output/ghcr-token"
"$FETCH_SECRET" GHCR_PUBLISH_TOKEN "$ghcr_target" >/dev/null
[[ "$(<"$ghcr_target")" == "$registry_token" ]] || fail 'GHCR token changed'

fallback_target="$work/output/fallback-token"
INFISICAL_API_URL='' INFISICAL_HOST='https://infisical-fallback.test' \
  "$FETCH_SECRET" GITEA_REGISTRY_TOKEN "$fallback_target" >/dev/null
[[ "$(<"$fallback_target")" == "$registry_token" ]] ||
  fail 'HTTPS host fallback changed the token'
grep -qF 'https://infisical-fallback.test/api/v1/auth/oidc-auth/login' \
  "$FAKE_CURL_CALLS" || fail 'HTTPS host fallback was not used'

dns_target="$work/output/dns-token"
INFISICAL_API_URL='http://infisical-backend.infisical.svc:8080/api' \
  "$FETCH_SECRET" GITEA_REGISTRY_TOKEN "$dns_target" >/dev/null
[[ "$(<"$dns_target")" == "$registry_token" ]] ||
  fail 'reviewed service DNS endpoint changed the token'

calls_before_http_rejection="$(wc -l <"$FAKE_CURL_CALLS")"
if INFISICAL_API_URL='http://10.44.11.114:8080/api' \
  "$FETCH_SECRET" GITEA_REGISTRY_TOKEN "$work/output/http-rejected" \
  >"$work/http-rejected.out" 2>&1; then
  fail 'unreviewed cluster HTTP endpoint was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before_http_rejection" ]] ||
  fail 'unreviewed cluster HTTP endpoint reached curl'

printf 'preserve-me' >"$target"
if FAKE_SECRET_STATUS=503 "$FETCH_SECRET" GITEA_REGISTRY_TOKEN "$target" \
  >"$work/failure.out" 2>&1; then
  fail 'non-success secret response was accepted'
fi
[[ "$(<"$target")" == preserve-me ]] || fail 'failed fetch replaced prior output'

calls_before="$(wc -l <"$FAKE_CURL_CALLS")"
if "$FETCH_SECRET" UNREVIEWED_SECRET "$work/output/rejected" \
  >"$work/rejected.out" 2>&1; then
  fail 'unreviewed secret name was accepted'
fi
[[ "$(wc -l <"$FAKE_CURL_CALLS")" -eq "$calls_before" ]] ||
  fail 'unreviewed secret name reached Infisical'

if INFISICAL_SA_TOKEN_PATH="$work/missing" \
  "$FETCH_SECRET" GITEA_REGISTRY_TOKEN "$work/output/missing" \
  >"$work/missing.out" 2>&1; then
  fail 'missing identity token was accepted'
fi

echo 'Infisical CI secret handoff tests passed'
