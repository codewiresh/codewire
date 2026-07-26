#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER="$ROOT/scripts/runtime/dev/with-dev-smoke-auth.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-smoke-auth-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly CLIENT_ID="test-client-id-sensitive-sentinel"
readonly CLIENT_SECRET="test-client-secret-sensitive-sentinel"
readonly CLIENT_SECRET_ID="test-client-secret-id-sensitive-sentinel"
readonly ACCESS_TOKEN="test-access-token-sensitive-sentinel"
readonly API_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly EMAIL="smoke-user-sensitive@example.test"
readonly STALE_API_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly STALE_EMAIL="stale-smoke-sensitive@example.test"
readonly LOGIN_URL="https://infisical.example.invalid/api/v1/auth/universal-auth/login"
readonly PROJECT_ID="00000000-0000-0000-0000-000000000000"
readonly API_KEY_URL="https://infisical.example.invalid/api/v4/secrets/CODEWIRE_DEV_SMOKE_API_KEY?projectId=${PROJECT_ID}&environment=dev&secretPath=%2F&type=shared&viewSecretValue=true&expandSecretReferences=false"
readonly EMAIL_URL="https://infisical.example.invalid/api/v4/secrets/EXPECTED_CODEWIRE_SMOKE_USER_EMAIL?projectId=${PROJECT_ID}&environment=dev&secretPath=%2F&type=shared&viewSecretValue=true&expandSecretReferences=false"

cleanup() {
  if [[ "${KEEP_DEV_SMOKE_AUTH_TEST_TMP:-0}" == "1" ]]; then
    printf 'with-dev-smoke-auth tests: kept %s\n' "$TEST_TMP" >&2
  else
    rm -rf -- "$TEST_TMP"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

fail() {
  printf 'with-dev-smoke-auth tests: %s\n' "$*" >&2
  exit 1
}

assert_redacted() {
  local file="$1"
  local marker
  [[ -f "$file" ]] || return 0
  for marker in \
    "$CLIENT_ID" \
    "$CLIENT_SECRET" \
    "$CLIENT_SECRET_ID" \
    "$ACCESS_TOKEN" \
    "$API_KEY" \
    "$EMAIL" \
    "$STALE_API_KEY" \
    "$STALE_EMAIL"; do
    if grep -F "$marker" "$file" >/dev/null; then
      fail "sensitive test marker appeared in captured output"
    fi
  done
}

make_fake_tools() {
  local bin_dir="$1"
  mkdir -p "$bin_dir"

  cat >"$bin_dir/timeout" <<'FAKE_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail

[[ "${1:-}" == "--signal=TERM" ]] || exit 90
[[ "${2:-}" == "--kill-after=1s" ]] || exit 91
[[ "${3:-}" == "5s" ]] || exit 92
[[ "${4:-}" == "secret-tool" ]] || exit 93
printf 'bounded-keyring-lookup\n' >>"$MOCK_STATE_DIR/timeout.log"
if [[ "$MOCK_MODE" == "keyring_timeout" ]]; then
  exit 124
fi
exec /usr/bin/timeout "$@"
FAKE_TIMEOUT

  cat >"$bin_dir/secret-tool" <<'FAKE_SECRET_TOOL'
#!/usr/bin/env bash
set -euo pipefail

[[ -z "${INFISICAL_TOKEN+x}" ]] || exit 80
[[ -z "${INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET+x}" ]] || exit 81
[[ -z "${CODEWIRE_DEV_SMOKE_API_KEY+x}" ]] || exit 82
[[ -z "${EXPECTED_CODEWIRE_SMOKE_USER_EMAIL+x}" ]] || exit 83
[[ -z "${CODEWIRE_API_KEY+x}" ]] || exit 84
[[ "$#" == 6 ]] || exit 85
[[ "$1" == "search" && "$2" == "--all" ]] || exit 86
[[ "$3" == "service" && "$4" == "codewire-dev-smoke-auth" ]] || exit 87
[[ "$5" == "kind" && "$6" == "infisical-universal-auth" ]] || exit 88
[[ "$(stat -Lc '%a' /proc/$$/fd/1)" == "600" ]] || exit 90
printf 'search --all service=codewire-dev-smoke-auth kind=infisical-universal-auth\n' \
  >>"$MOCK_STATE_DIR/secret-tool.log"

case "$MOCK_MODE" in
  keyring_failure)
    exit 3
    ;;
  missing_keyring|locked_keyring)
    exit 0
    ;;
  invalid_keyring_json)
    printf '[test-item]\nsecret = not-json\n'
    ;;
  invalid_keyring_fields)
    printf '[test-item]\nsecret = {"clientId":"test-client-id-sensitive-sentinel"}\n'
    ;;
  ambiguous_keyring)
    printf '%s\n' \
      '[test-item-1]' \
      'secret = {"clientId":"test-client-id-sensitive-sentinel","clientSecret":"test-client-secret-sensitive-sentinel","clientSecretId":"test-client-secret-id-sensitive-sentinel"}' \
      '[test-item-2]' \
      'secret = {"clientId":"test-client-id-sensitive-sentinel","clientSecret":"test-client-secret-sensitive-sentinel","clientSecretId":"test-client-secret-id-sensitive-sentinel"}'
    ;;
  *)
    printf '%s\n' \
      '[test-item]' \
      'label = Codewire dev smoke Universal Auth' \
      'secret = {"clientId":"test-client-id-sensitive-sentinel","clientSecret":"test-client-secret-sensitive-sentinel","clientSecretId":"test-client-secret-id-sensitive-sentinel"}' \
      'attribute.service = codewire-dev-smoke-auth' \
      'attribute.kind = infisical-universal-auth'
    ;;
esac
FAKE_SECRET_TOOL

  cat >"$bin_dir/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail

mock_fail() {
  exit "$1"
}

assert_private_file() {
  local path="$1"
  [[ -f "$path" ]] || mock_fail 70
  [[ "$(stat -c '%a' "$path")" == "600" ]] || mock_fail 71
  [[ "$(stat -c '%a' "$(dirname "$path")")" == "700" ]] || mock_fail 72
}

for value in "$@"; do
  case "$value" in
    *sensitive-sentinel*|cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
      mock_fail 73
      ;;
  esac
done
[[ -z "${INFISICAL_TOKEN+x}" ]] || mock_fail 74
[[ -z "${INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET+x}" ]] || mock_fail 75
[[ -z "${CODEWIRE_DEV_SMOKE_API_KEY+x}" ]] || mock_fail 76
[[ -z "${EXPECTED_CODEWIRE_SMOKE_USER_EMAIL+x}" ]] || mock_fail 77
[[ -z "${CODEWIRE_API_KEY+x}" ]] || mock_fail 78

config=""
output=""
payload=""
[[ "${1:-}" == "--disable" ]] || mock_fail 79
while (($# > 0)); do
  case "$1" in
    --disable)
      shift
      ;;
    --config)
      config="$2"
      shift 2
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    --data-binary)
      payload="${2#@}"
      shift 2
      ;;
    *)
      mock_fail 79
      ;;
  esac
done

assert_private_file "$config"
assert_private_file "$output"
grep -Fx 'silent' "$config" >/dev/null || mock_fail 80
grep -Fx 'show-error' "$config" >/dev/null || mock_fail 81
grep -Fx 'fail' "$config" >/dev/null || mock_fail 82
grep -Fx 'globoff' "$config" >/dev/null || mock_fail 83
grep -Fx 'retry = 0' "$config" >/dev/null || mock_fail 84
grep -Fx 'connect-timeout = 5' "$config" >/dev/null || mock_fail 85
grep -Fx 'max-time = 15' "$config" >/dev/null || mock_fail 86
grep -Fx 'proto = "=https"' "$config" >/dev/null || mock_fail 87

method="$(sed -n 's/^request = "\([A-Z]*\)"$/\1/p' "$config")"
url="$(sed -n 's/^url = "\(.*\)"$/\1/p' "$config")"
[[ -n "$method" && -n "$url" ]] || mock_fail 88

count=0
if [[ -f "$MOCK_STATE_DIR/request-count" ]]; then
  count="$(<"$MOCK_STATE_DIR/request-count")"
fi
count=$((count + 1))
printf '%s' "$count" >"$MOCK_STATE_DIR/request-count"
printf '%s\t%s\t%s\n' "$count" "$method" "$url" >>"$MOCK_STATE_DIR/requests.log"

if [[ "$count" == 1 ]]; then
  [[ "$method" == "POST" ]] || mock_fail 88
  [[ "$url" == "https://infisical.example.invalid/api/v1/auth/universal-auth/login" ]] || mock_fail 89
  [[ -n "$payload" ]] || mock_fail 90
  assert_private_file "$payload"
  grep -Fx 'header = "Content-Type: application/json"' "$config" >/dev/null || mock_fail 91
  if grep -F 'Authorization:' "$config" >/dev/null; then
    mock_fail 92
  fi
  jq -e '
    type == "object"
      and keys == ["clientId", "clientSecret"]
      and .clientId == "test-client-id-sensitive-sentinel"
      and .clientSecret == "test-client-secret-sensitive-sentinel"
  ' "$payload" >/dev/null || mock_fail 93

  case "$MOCK_MODE" in
    login_failure) exit 22 ;;
    login_timeout) exit 28 ;;
    login_wrong_shape) printf '%s\n' '{"accessToken":42}' >"$output" ;;
    login_long_ttl)
      printf '%s\n' \
        '{"accessToken":"test-access-token-sensitive-sentinel","expiresIn":301,"accessTokenMaxTTL":301,"tokenType":"Bearer"}' \
        >"$output"
      ;;
    *)
      printf '%s\n' \
        '{"accessToken":"test-access-token-sensitive-sentinel","expiresIn":300,"accessTokenMaxTTL":300,"tokenType":"Bearer"}' \
        >"$output"
      ;;
  esac
  exit 0
fi

[[ -z "$payload" ]] || mock_fail 94
[[ "$method" == "GET" ]] || mock_fail 95
grep -Fx 'header = "Authorization: Bearer test-access-token-sensitive-sentinel"' \
  "$config" >/dev/null || mock_fail 96

case "$count" in
  2)
    [[ "$url" == "https://infisical.example.invalid/api/v4/secrets/CODEWIRE_DEV_SMOKE_API_KEY?projectId=00000000-0000-0000-0000-000000000000&environment=dev&secretPath=%2F&type=shared&viewSecretValue=true&expandSecretReferences=false" ]] || mock_fail 97
    case "$MOCK_MODE" in
      first_fetch_failure) exit 22 ;;
      fetch_timeout) exit 28 ;;
      first_wrong_shape) printf '%s\n' '{"secret":[]}' >"$output" ;;
      first_wrong_name)
        printf '%s\n' \
          '{"secret":{"secretKey":"OTHER_SECRET","secretValue":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}' \
          >"$output"
        ;;
      invalid_api_key)
        printf '%s\n' \
          '{"secret":{"secretKey":"CODEWIRE_DEV_SMOKE_API_KEY","secretValue":"not-an-api-key"}}' \
          >"$output"
        ;;
      *)
        printf '%s\n' \
          '{"secret":{"secretKey":"CODEWIRE_DEV_SMOKE_API_KEY","secretValue":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}' \
          >"$output"
        ;;
    esac
    ;;
  3)
    [[ "$url" == "https://infisical.example.invalid/api/v4/secrets/EXPECTED_CODEWIRE_SMOKE_USER_EMAIL?projectId=00000000-0000-0000-0000-000000000000&environment=dev&secretPath=%2F&type=shared&viewSecretValue=true&expandSecretReferences=false" ]] || mock_fail 98
    case "$MOCK_MODE" in
      second_fetch_failure) exit 22 ;;
      second_wrong_shape) printf '%s\n' '{"secret":{}}' >"$output" ;;
      second_wrong_name)
        printf '%s\n' \
          '{"secret":{"secretKey":"OTHER_SECRET","secretValue":"smoke-user-sensitive@example.test"}}' \
          >"$output"
        ;;
      invalid_email)
        printf '%s\n' \
          '{"secret":{"secretKey":"EXPECTED_CODEWIRE_SMOKE_USER_EMAIL","secretValue":"not-an-email"}}' \
          >"$output"
        ;;
      *)
        printf '%s\n' \
          '{"secret":{"secretKey":"EXPECTED_CODEWIRE_SMOKE_USER_EMAIL","secretValue":"smoke-user-sensitive@example.test"}}' \
          >"$output"
        ;;
    esac
    ;;
  *)
    mock_fail 99
    ;;
esac
FAKE_CURL

  cat >"$bin_dir/fallback" <<'FAKE_FALLBACK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fallback invoked\n' >>"$MOCK_STATE_DIR/fallback.log"
exit 100
FAKE_FALLBACK

  for name in infisical xdg-open sensible-browser open gio; do
    ln -s fallback "$bin_dir/$name"
  done

  chmod 0755 "$bin_dir/timeout" "$bin_dir/secret-tool" "$bin_dir/curl" "$bin_dir/fallback"
  for name in bash dirname rm chmod mktemp jq awk stat sed grep; do
    ln -s "$(command -v "$name")" "$bin_dir/$name"
  done
}

make_child() {
  local child="$1"
  cat >"$child" <<'CHILD'
#!/usr/bin/env bash
set -euo pipefail

[[ "$CODEWIRE_DEV_SMOKE_API_KEY" == "cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]]
[[ "$EXPECTED_CODEWIRE_SMOKE_USER_EMAIL" == "smoke-user-sensitive@example.test" ]]
[[ -z "${CODEWIRE_API_KEY+x}" ]]
names=( "${!INFISICAL_@}" )
[[ "${#names[@]}" == 0 ]]
shopt -s nullglob
leftovers=( "$TMPDIR"/codewire-dev-smoke-auth.* )
[[ "${#leftovers[@]}" == 0 ]]
printf 'child-safe\n'
printf 'ran\n' >"$MOCK_STATE_DIR/child.log"
CHILD
  chmod 0755 "$child"
}

request_count() {
  local state_dir="$1"
  if [[ -f "$state_dir/request-count" ]]; then
    printf '%s' "$(<"$state_dir/request-count")"
  else
    printf '0'
  fi
}

run_case() {
  local mode="$1"
  local expected_result="$2"
  local expected_requests="$3"
  local expected_error="${4:-}"
  local case_dir="$TEST_TMP/$mode"
  local bin_dir="$case_dir/bin"
  local state_dir="$case_dir/state"
  local auth_tmp="$case_dir/auth-tmp"
  local child="$case_dir/child"
  local rc

  mkdir -p "$state_dir" "$auth_tmp"
  chmod 0700 "$state_dir" "$auth_tmp"
  : >"$state_dir/requests.log"
  : >"$state_dir/secret-tool.log"
  : >"$state_dir/timeout.log"
  : >"$state_dir/fallback.log"
  make_fake_tools "$bin_dir"
  make_child "$child"

  set +e
  PATH="$bin_dir" \
    MOCK_MODE="$mode" \
    MOCK_STATE_DIR="$state_dir" \
    TMPDIR="$auth_tmp" \
    INFISICAL_TOKEN="$ACCESS_TOKEN" \
    INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET="$CLIENT_SECRET" \
    INFISICAL_DOMAIN="http://127.0.0.1:1" \
    INFISICAL_API_URL="http://127.0.0.1:1/api" \
    INFISICAL_PROJECT_ID="wrong-project" \
    INFISICAL_ENV="prod" \
    INFISICAL_PATH="/wrong" \
    CODEWIRE_DEV_SMOKE_API_KEY="$STALE_API_KEY" \
    EXPECTED_CODEWIRE_SMOKE_USER_EMAIL="$STALE_EMAIL" \
    CODEWIRE_API_KEY="$STALE_API_KEY" \
    "$WRAPPER" -- "$child" >"$case_dir/out" 2>"$case_dir/err"
  rc=$?
  set -e

  if [[ "$expected_result" == "success" ]]; then
    [[ "$rc" == 0 ]] || fail "$mode unexpectedly failed"
    grep -Fx 'child-safe' "$case_dir/out" >/dev/null || fail "$mode did not run the child"
    [[ -f "$state_dir/child.log" ]] || fail "$mode did not reach the child"
  else
    [[ "$rc" != 0 ]] || fail "$mode unexpectedly succeeded"
    [[ ! -e "$state_dir/child.log" ]] || fail "$mode reached the child after failure"
    grep -F "$expected_error" "$case_dir/err" >/dev/null || \
      fail "$mode did not emit its generic failure class"
  fi

  [[ "$(request_count "$state_dir")" == "$expected_requests" ]] || \
    fail "$mode made an unexpected number of HTTP requests"
  [[ -s "$state_dir/timeout.log" ]] || fail "$mode bypassed the bounded keyring lookup mock"
  if [[ "$mode" != "keyring_timeout" ]]; then
    [[ -s "$state_dir/secret-tool.log" ]] || fail "$mode bypassed the Secret Service mock"
  fi
  [[ ! -s "$state_dir/fallback.log" ]] || fail "$mode invoked a human-login fallback"
  if find "$auth_tmp" -mindepth 1 -print -quit | grep -q .; then
    fail "$mode left temporary auth material behind"
  fi

  assert_redacted "$case_dir/out"
  assert_redacted "$case_dir/err"
  assert_redacted "$state_dir/requests.log"
  assert_redacted "$state_dir/secret-tool.log"
  assert_redacted "$state_dir/timeout.log"
  assert_redacted "$state_dir/fallback.log"
}

test_static_contract() {
  grep -F 'readonly PLATFORM_BASE_URL="https://infisical.example.invalid"' "$WRAPPER" >/dev/null
  grep -F 'readonly PLATFORM_PROJECT_ID="00000000-0000-0000-0000-000000000000"' "$WRAPPER" >/dev/null
  grep -F 'readonly PLATFORM_ENVIRONMENT="dev"' "$WRAPPER" >/dev/null
  grep -F 'readonly PLATFORM_SECRET_PATH_ENCODED="%2F"' "$WRAPPER" >/dev/null
  grep -F "set -- \"\$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh\"" "$WRAPPER" >/dev/null
  if grep -E 'INFISICAL_(DOMAIN|PROJECT_ID|ENV|PATH)=.*:-' "$WRAPPER" >/dev/null; then
    fail "production Infisical scope remains environment-overridable"
  fi
}

test_mock_execution_surface() {
  local probe="$TEST_TMP/execution-probe"
  cat >"$probe" <<'PROBE'
#!/bin/sh
exit 0
PROBE
  chmod 0755 "$probe"
  [[ -x "$probe" ]] || fail "mock filesystem did not retain executable mode"
  "$probe" || fail "mock filesystem is noexec; refusing to risk PATH fallback"
}

test_static_contract
test_mock_execution_surface
run_case success success 3
run_case missing_keyring failure 0 'absent, locked, or ambiguous'
run_case locked_keyring failure 0 'absent, locked, or ambiguous'
run_case keyring_failure failure 0 'credential lookup failed or timed out'
run_case keyring_timeout failure 0 'credential lookup failed or timed out'
run_case invalid_keyring_json failure 0 'credential has an unexpected shape'
run_case invalid_keyring_fields failure 0 'credential has an unexpected shape'
run_case ambiguous_keyring failure 0 'absent, locked, or ambiguous'
run_case login_failure failure 1 'Universal Auth exchange failed or timed out'
run_case login_timeout failure 1 'Universal Auth exchange failed or timed out'
run_case login_wrong_shape failure 1 'unexpected token response'
run_case login_long_ttl failure 1 'unexpected token response'
run_case first_fetch_failure failure 2 'failed to fetch the scoped CODEWIRE_DEV_SMOKE_API_KEY'
run_case fetch_timeout failure 2 'failed to fetch the scoped CODEWIRE_DEV_SMOKE_API_KEY'
run_case first_wrong_shape failure 2 'unexpected response for CODEWIRE_DEV_SMOKE_API_KEY'
run_case first_wrong_name failure 2 'unexpected response for CODEWIRE_DEV_SMOKE_API_KEY'
run_case second_fetch_failure failure 3 'failed to fetch the scoped EXPECTED_CODEWIRE_SMOKE_USER_EMAIL'
run_case second_wrong_shape failure 3 'unexpected response for EXPECTED_CODEWIRE_SMOKE_USER_EMAIL'
run_case second_wrong_name failure 3 'unexpected response for EXPECTED_CODEWIRE_SMOKE_USER_EMAIL'
run_case invalid_api_key failure 3 'CODEWIRE_DEV_SMOKE_API_KEY from Infisical has an unexpected shape'
run_case invalid_email failure 3 'EXPECTED_CODEWIRE_SMOKE_USER_EMAIL from Infisical has an unexpected shape'

expected_requests="$TEST_TMP/expected-requests"
cat >"$expected_requests" <<EOF
1	POST	$LOGIN_URL
2	GET	$API_KEY_URL
3	GET	$EMAIL_URL
EOF
cmp -s "$expected_requests" "$TEST_TMP/success/state/requests.log" || \
  fail "success case request targets or ordering drifted"

printf 'with-dev-smoke-auth machine auth tests: OK\n'
