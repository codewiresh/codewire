#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly ROOT
readonly FETCHER="$ROOT/scripts/ci/setup/fetch-forgejo-deploy-dev-token.sh"
readonly EXPECTED_AUDIENCE='u:36:cf95ede8-4fae-4121-b18a-05ca39e69bb9'
readonly TEST_REQUEST_TOKEN='test-only-oidc-request-token'
readonly TEST_JWT='synthetic.header.signature'

fail() {
  printf '[test-fetch-forgejo-deploy-dev-token] ERROR: %s\n' "$*" >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/fetch-forgejo-deploy-dev.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/output" "$work/runner"

cat >"$work/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN+x}" ]] || exit 91
printf '%s\n' "$@" >"$MOCK_CAPTURE_DIR/args"
output=''
url=''
previous=''
for argument in "$@"; do
  case "$previous" in
    --config) cp "$argument" "$MOCK_CAPTURE_DIR/oidc-config" ;;
    --output) output="$argument" ;;
  esac
  previous="$argument"
  url="$argument"
done
[[ -n "$output" ]]
jq -n --arg value "${MOCK_JWT:?}" '{value:$value}' >"$output"
MOCK
chmod +x "$work/bin/curl"

export ACTIONS_ID_TOKEN_REQUEST_URL='https://forgejo.example.invalid/api/actions/oidc?job=synthetic'
export ACTIONS_ID_TOKEN_REQUEST_TOKEN="$TEST_REQUEST_TOKEN"
export CURL_BIN="$work/bin/curl"
export MOCK_CAPTURE_DIR="$work"
export MOCK_JWT="$TEST_JWT"
export RUNNER_TEMP="$work/runner"

token_file="$work/output/token"
"$FETCHER" "$token_file" >"$work/success.out"
[[ "$(<"$token_file")" == "$TEST_JWT" ]] || fail 'returned JWT differs'
[[ "$(stat -c '%a' "$token_file")" == 600 ]] || fail 'token mode is not 0600'
grep -Fxq "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${EXPECTED_AUDIENCE}" \
  "$work/args" || fail 'OIDC request used the wrong audience'
grep -Fq "Authorization: Bearer $TEST_REQUEST_TOKEN" "$work/oidc-config" ||
  fail 'OIDC request lacks the private request-token header'
if grep -Fq "$TEST_REQUEST_TOKEN" "$work/args" "$work/success.out"; then
  fail 'OIDC request token reached arguments or output'
fi
[[ -z "$(find "$RUNNER_TEMP" -mindepth 1 -print -quit)" ]] ||
  fail 'temporary OIDC material survived cleanup'

printf keep >"$work/output/existing"
chmod 0600 "$work/output/existing"
if "$FETCHER" "$work/output/existing" >"$work/existing.out" 2>&1; then
  fail 'pre-existing output was accepted'
fi
[[ "$(<"$work/output/existing")" == keep ]] || fail 'pre-existing output changed'

rm -f "$work/args"
if ACTIONS_ID_TOKEN_REQUEST_TOKEN='unsafe token' \
    "$FETCHER" "$work/output/unsafe-request" >"$work/unsafe-request.out" 2>&1; then
  fail 'unsafe OIDC request token was accepted'
fi
[[ ! -e "$work/args" ]] || fail 'unsafe OIDC request token reached curl'
[[ ! -e "$work/output/unsafe-request" ]] ||
  fail 'unsafe OIDC request token created an output'

export MOCK_JWT='not-a-jwt'
if "$FETCHER" "$work/output/malformed" >"$work/malformed.out" 2>&1; then
  fail 'malformed JWT was accepted'
fi
[[ ! -e "$work/output/malformed" ]] || fail 'malformed JWT created an output'

printf '[test-fetch-forgejo-deploy-dev-token] private exact-audience JWT contract passed\n'
