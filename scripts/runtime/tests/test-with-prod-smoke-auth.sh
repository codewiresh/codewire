#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER="$ROOT/scripts/runtime/prod/with-prod-smoke-auth.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-prod-smoke-auth-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly API_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly EMAIL="prod-smoke-sensitive@example.test"
readonly STALE_API_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly BAO_TOKEN_FIXTURE="synthetic-bao-token-4060"
readonly STALE_EMAIL="stale-smoke-sensitive@example.test"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT

fail() { printf 'with-prod-smoke-auth tests: %s\n' "$*" >&2; exit 1; }

assert_redacted() {
  local file="$1" marker
  [[ -f "$file" ]] || return 0
  for marker in "$API_KEY" "$EMAIL" "$STALE_API_KEY" "$STALE_EMAIL" "$BAO_TOKEN_FIXTURE"; do
    if grep -F "$marker" "$file" >/dev/null; then
      fail 'sensitive fixture reached output'
    fi
  done
}

make_fake_tools() {
  local bin="$1"
  mkdir -p "$bin"
  cat >"$bin/bao" <<'FAKE_BAO'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'kv get -format=json apps/codewire/prod/ci-smoke' ]] || exit 90
[[ "${BAO_ADDR:-}" == 'https://openbao.example.invalid' ]] || exit 91
[[ "${BAO_TOKEN:-}" == 'synthetic-bao-token-4060' ]] || exit 93
[[ "$HOME" == */bao-home && -d "$HOME" ]] || exit 94
[[ "$(stat -Lc '%a' /proc/$$/fd/1)" == '600' ]] || exit 92
printf 'read\n' >>"$MOCK_STATE/events"
case "$MOCK_MODE" in
  read_failure) printf 'connection refused\n' >&2; exit 2 ;;
  permission) printf 'permission denied (status code: 403)\n' >&2; exit 2 ;;
  absent) printf 'No value found at apps/data/codewire/prod/ci-smoke\n' >&2; exit 2 ;;
  wrong_shape) printf '%s\n' '{"data":{"metadata":{"version":1},"data":[]}}' ;;
  extra_field) printf '%s\n' '{"data":{"metadata":{"version":1},"data":{"apiKey":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userEmail":"prod-smoke-sensitive@example.test","other":"x"}}}' ;;
  invalid_key) printf '%s\n' '{"data":{"metadata":{"version":1},"data":{"apiKey":"bad","userEmail":"prod-smoke-sensitive@example.test"}}}' ;;
  invalid_email) printf '%s\n' '{"data":{"metadata":{"version":1},"data":{"apiKey":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userEmail":"bad"}}}' ;;
  *) printf '%s\n' '{"data":{"metadata":{"version":3},"data":{"apiKey":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userEmail":"prod-smoke-sensitive@example.test"}}}' ;;
esac
FAKE_BAO
  chmod 0755 "$bin/bao"
  cat >"$bin/../access" <<'FAKE_ACCESS'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'bao human' ]] || exit 95
if [[ "$MOCK_MODE" == access_closed ]]; then
  printf 'access: login-required: run scripts/access login (or login --device-code)\n' >&2
  exit 1
fi
printf 'token\n' >>"$MOCK_STATE/tokens"
printf '%s' 'synthetic-bao-token-4060' >&3
FAKE_ACCESS
  chmod 0755 "$bin/../access"
  cat >"$bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
header='' url=''
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --header) header="${2#@}"; shift ;;
    --url) url="$2"; shift ;;
  esac
  shift
done
[[ "$url" == 'https://openbao.example.invalid/v1/auth/token/revoke-self' ]] || exit 96
[[ "$(<"$header")" == 'X-Vault-Token: synthetic-bao-token-4060' ]] || exit 97
printf 'revoke\n' >>"$MOCK_STATE/revokes"
if [[ "$MOCK_MODE" == revoke_refused ]]; then printf '403'; else printf '204'; fi
FAKE_CURL
  chmod 0755 "$bin/curl"
  for name in bash chmod cmp dirname find grep id jq mkdir mktemp rmdir rm sed shred stat timeout wc; do
    ln -s "$(command -v "$name")" "$bin/$name"
  done
}

make_child() {
  local child="$1"
  cat >"$child" <<'CHILD'
#!/usr/bin/env bash
set -euo pipefail
[[ "$CODEWIRE_PROD_SMOKE_API_KEY" == 'cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
[[ "$EXPECTED_CODEWIRE_PROD_SMOKE_USER_EMAIL" == 'prod-smoke-sensitive@example.test' ]]
[[ -z "${CODEWIRE_API_KEY+x}" ]]
[[ -z "${CODEWIRE_DEV_SMOKE_API_KEY+x}" ]]
[[ -z "${EXPECTED_CODEWIRE_SMOKE_USER_EMAIL+x}" ]]
bao_names=( "${!BAO_@}" )
[[ "${#bao_names[@]}" == 0 ]]
shopt -s nullglob
leftovers=( "$TMPDIR"/codewire-prod-smoke-auth.* )
[[ "${#leftovers[@]}" == 0 ]]
printf 'child-safe\n'
printf 'ran\n' >"$MOCK_STATE/child"
CHILD
  chmod 0755 "$child"
}

run_case() {
  local mode="$1" expected="$2" expected_error="${3:-}" reads="${4:-1}"
  local dir="$TEST_TMP/$mode" rc
  local -a command=(-- "$TEST_TMP/$mode/child")
  [[ "$mode" != no_command ]] || command=(--)
  mkdir -p "$dir/bin" "$dir/state" "$dir/tmp"
  chmod 0700 "$dir/state" "$dir/tmp"
  : >"$dir/state/events"
  : >"$dir/state/tokens"
  : >"$dir/state/revokes"
  local access="$dir/access"
  [[ "$mode" != no_client ]] || access=''
  make_fake_tools "$dir/bin"
  make_child "$dir/child"

  set +e
  PATH="$dir/bin" MOCK_MODE="$mode" MOCK_STATE="$dir/state" TMPDIR="$dir/tmp" \
    BAO_ADDR='https://openbao.example.invalid' BAO_TOKEN='stale-owner-token' \
    CODEWIRE_ACCESS_CLIENT="$access" \
    CODEWIRE_PROD_SMOKE_API_KEY="$STALE_API_KEY" \
    EXPECTED_CODEWIRE_PROD_SMOKE_USER_EMAIL="$STALE_EMAIL" \
    CODEWIRE_DEV_SMOKE_API_KEY="$STALE_API_KEY" \
    EXPECTED_CODEWIRE_SMOKE_USER_EMAIL="$STALE_EMAIL" \
    CODEWIRE_API_KEY="$STALE_API_KEY" \
    "$WRAPPER" "${command[@]}" >"$dir/out" 2>"$dir/err"
  rc=$?
  set -e

  if [[ "$expected" == success ]]; then
    [[ "$rc" == 0 && -f "$dir/state/child" ]] || fail "$mode unexpectedly failed"
    grep -Fx 'child-safe' "$dir/out" >/dev/null || fail "$mode did not run child"
  else
    [[ "$rc" != 0 && ! -e "$dir/state/child" ]] || fail "$mode unexpectedly succeeded"
    grep -F "$expected_error" "$dir/err" >/dev/null || fail "$mode emitted wrong failure class"
  fi
  [[ "$(wc -l <"$dir/state/events")" == "$reads" ]] || fail "$mode made an unexpected read count"
  [[ "$(wc -l <"$dir/state/revokes")" == "$(wc -l <"$dir/state/tokens")" ]] ||
    fail "$mode left an issued OpenBao token unrevoked"
  find "$dir/tmp" -mindepth 1 -print -quit | grep -q . && fail "$mode left private files"
  assert_redacted "$dir/out"
  assert_redacted "$dir/err"
}

grep -F 'readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"' "$WRAPPER" >/dev/null
grep -F 'readonly OPENBAO_PATH="apps/codewire/prod/ci-smoke"' "$WRAPPER" >/dev/null
if grep -Eqi 'secret-tool|platform_project|codewire/dev/' "$WRAPPER"; then
  fail 'auth wrapper contains an unreviewed or Dev credential source'
fi

run_case success success
run_case no_command failure 'a command is required; Production smoke has no default' 0
run_case no_client failure 'set CODEWIRE_ACCESS_CLIENT' 0
run_case access_closed failure 'the access client session is closed' 0
run_case revoke_refused failure 'was not confirmed revoked'
run_case read_failure failure 'failed to fetch the canonical Prod smoke document'
run_case permission failure 'the access client token lacks the exact Prod smoke path'
run_case absent failure 'the Prod smoke identity is not provisioned yet'
run_case wrong_shape failure 'unexpected shape'
run_case extra_field failure 'unexpected shape'
run_case invalid_key failure 'unexpected shape'
run_case invalid_email failure 'unexpected shape'

printf 'with-prod-smoke-auth OpenBao tests: OK\n'
