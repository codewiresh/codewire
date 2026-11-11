#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER="$ROOT/scripts/runtime/dev/with-dev-smoke-auth.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-smoke-auth-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly API_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly EMAIL="smoke-user-sensitive@example.test"
readonly STALE_API_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly BAO_TOKEN_FIXTURE="synthetic-bao-token-4060"
readonly STALE_EMAIL="stale-smoke-sensitive@example.test"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT

fail() { printf 'with-dev-smoke-auth tests: %s\n' "$*" >&2; exit 1; }

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
[[ "$*" == "kv get -format=json $MOCK_OPENBAO_PATH" ]] || exit 90
[[ "${BAO_ADDR:-}" == 'https://openbao.example.invalid' ]] || exit 91
[[ "${BAO_TOKEN:-}" == 'synthetic-bao-token-4060' ]] || exit 93
[[ "$HOME" == */bao-home && -d "$HOME" ]] || exit 94
[[ "$(stat -Lc '%a' /proc/$$/fd/1)" == '600' ]] || exit 92
printf 'read\n' >>"$MOCK_STATE/events"
case "$MOCK_MODE" in
  read_failure) printf 'connection refused\n' >&2; exit 2 ;;
  permission) printf 'permission denied (status code: 403)\n' >&2; exit 2 ;;
  wrong_shape) printf '%s\n' '{"data":{"metadata":{"version":1},"data":[]}}' ;;
  extra_field) printf '%s\n' '{"data":{"metadata":{"version":1},"data":{"apiKey":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userEmail":"smoke-user-sensitive@example.test","other":"x"}}}' ;;
  invalid_key) printf '%s\n' '{"data":{"metadata":{"version":1},"data":{"apiKey":"bad","userEmail":"smoke-user-sensitive@example.test"}}}' ;;
  invalid_email) printf '%s\n' '{"data":{"metadata":{"version":1},"data":{"apiKey":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userEmail":"bad"}}}' ;;
  *) printf '%s\n' '{"data":{"metadata":{"version":3},"data":{"apiKey":"cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","userEmail":"smoke-user-sensitive@example.test"}}}' ;;
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
[[ "$CODEWIRE_DEV_SMOKE_API_KEY" == 'cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
[[ "$EXPECTED_CODEWIRE_SMOKE_USER_EMAIL" == 'smoke-user-sensitive@example.test' ]]
[[ -z "${CODEWIRE_API_KEY+x}" ]]
bao_names=( "${!BAO_@}" )
[[ "${#bao_names[@]}" == 0 ]]
# The child's local VM state root is private and absent, never the owner's
# inherited one (#4156).
[[ "$CODEWIRE_NATIVE_STATE_ROOT" == "$TMPDIR"/*/no-local-vm-state ]]
[[ ! -e "$CODEWIRE_NATIVE_STATE_ROOT" && ! -e "$(dirname "$CODEWIRE_NATIVE_STATE_ROOT")" ]]
shopt -s nullglob
leftovers=( "$TMPDIR"/codewire-dev-smoke-auth.* )
[[ "${#leftovers[@]}" == 0 ]]
printf 'child-safe\n'
printf 'ran\n' >"$MOCK_STATE/child"
CHILD
  chmod 0755 "$child"
}

# run_case MODE success|failure [ERROR [READS [WRAPPER ARGS...]]]; CASE_OPENBAO_PATH
# is the document the fake bao expects.
run_case() {
  local mode="$1" expected="$2" expected_error="${3:-}" reads="${4:-1}"
  shift "$(( $# < 4 ? $# : 4 ))"
  local dir="$TEST_TMP/$mode" rc
  mkdir -p "$dir/bin" "$dir/state" "$dir/tmp"
  chmod 0700 "$dir/state" "$dir/tmp"
  : >"$dir/state/events"
  : >"$dir/state/tokens"
  : >"$dir/state/revokes"
  local access="$dir/access" infra=''
  make_fake_tools "$dir/bin"
  # Without CODEWIRE_ACCESS_CLIENT: none at all, one on PATH, or one under
  # CODEWIRE_INFRA_DIR; an explicit relative path is refused, not skipped.
  case "$mode" in
    no_client) access='' ;;
    via_path) access=''; cp "$dir/access" "$dir/bin/access" ;;
    via_infra_dir) access='' infra="$dir/infra"; mkdir -p "$infra/scripts"; cp "$dir/access" "$infra/scripts/access" ;;
    relative_client) access='access' ;;
  esac
  make_child "$dir/child"

  set +e
  PATH="$dir/bin" MOCK_MODE="$mode" MOCK_STATE="$dir/state" TMPDIR="$dir/tmp" \
    MOCK_OPENBAO_PATH="${CASE_OPENBAO_PATH:-apps/codewire/dev/ci-smoke}" \
    BAO_ADDR='https://openbao.example.invalid' BAO_TOKEN='stale-owner-token' \
    CODEWIRE_ACCESS_CLIENT="$access" CODEWIRE_INFRA_DIR="$infra" \
    CODEWIRE_DEV_SMOKE_API_KEY="$STALE_API_KEY" \
    EXPECTED_CODEWIRE_SMOKE_USER_EMAIL="$STALE_EMAIL" \
    CODEWIRE_API_KEY="$STALE_API_KEY" \
    CODEWIRE_NATIVE_STATE_ROOT="$HOME/.codewire/native-v1" \
    "$WRAPPER" "$@" -- "$dir/child" >"$dir/out" 2>"$dir/err"
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
grep -F 'readonly SMOKE_OPENBAO_PATH="apps/codewire/dev/ci-smoke"' "$WRAPPER" >/dev/null
if grep -Eqi 'secret-tool|platform_project' "$WRAPPER"; then
  fail 'auth wrapper still contains an unreviewed credential source'
fi

run_case success success
run_case no_client failure 'set CODEWIRE_ACCESS_CLIENT' 0
run_case relative_client failure 'is not the absolute path of an executable access client' 0
run_case via_path success
run_case via_infra_dir success
run_case access_closed failure 'the access client session is closed' 0
run_case revoke_refused failure 'was not confirmed revoked'
run_case read_failure failure 'failed to fetch the canonical Dev smoke document'
run_case permission failure 'the access client token lacks the exact Dev path apps/codewire/dev/ci-smoke'
# --openbao-path reads another Dev identity's document, and only a Dev one.
CASE_OPENBAO_PATH=apps/codewire/dev/ci-billing-rehearsal run_case rehearsal_path success '' 1 \
  --openbao-path apps/codewire/dev/ci-billing-rehearsal
grep -F 'loaded the two Dev identity values from canonical OpenBao apps/codewire/dev/ci-billing-rehearsal' \
  "$TEST_TMP/rehearsal_path/err" >/dev/null || fail 'rehearsal_path did not name the document it read'
run_case prod_path failure 'OpenBao path must be apps/codewire/dev/<lowercase-slug>' 0 \
  --openbao-path apps/codewire/prod/ci-smoke
run_case traversal_path failure 'OpenBao path must be apps/codewire/dev/<lowercase-slug>' 0 \
  --openbao-path apps/codewire/dev/../prod/ci-smoke
run_case missing_path failure 'OpenBao path must be apps/codewire/dev/<lowercase-slug>' 0 \
  --openbao-path ''
run_case wrong_shape failure 'unexpected shape'
run_case extra_field failure 'unexpected shape'
run_case invalid_key failure 'unexpected shape'
run_case invalid_email failure 'unexpected shape'

printf 'with-dev-smoke-auth OpenBao tests: OK\n'
