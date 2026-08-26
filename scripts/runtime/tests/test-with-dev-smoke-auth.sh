#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WRAPPER="$ROOT/scripts/runtime/dev/with-dev-smoke-auth.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-smoke-auth-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly API_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly EMAIL="smoke-user-sensitive@example.test"
readonly STALE_API_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly STALE_EMAIL="stale-smoke-sensitive@example.test"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT

fail() { printf 'with-dev-smoke-auth tests: %s\n' "$*" >&2; exit 1; }

assert_redacted() {
  local file="$1" marker
  [[ -f "$file" ]] || return 0
  for marker in "$API_KEY" "$EMAIL" "$STALE_API_KEY" "$STALE_EMAIL"; do
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
[[ "$*" == 'kv get -format=json apps/codewire/dev/ci-smoke' ]] || exit 90
[[ "${BAO_ADDR:-}" == 'https://openbao.example.invalid' ]] || exit 91
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
  for name in bash chmod dirname find grep jq mktemp rmdir rm shred stat; do
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
shopt -s nullglob
leftovers=( "$TMPDIR"/codewire-dev-smoke-auth.* )
[[ "${#leftovers[@]}" == 0 ]]
printf 'child-safe\n'
printf 'ran\n' >"$MOCK_STATE/child"
CHILD
  chmod 0755 "$child"
}

run_case() {
  local mode="$1" expected="$2" expected_error="${3:-}"
  local dir="$TEST_TMP/$mode" rc
  mkdir -p "$dir/bin" "$dir/state" "$dir/tmp"
  chmod 0700 "$dir/state" "$dir/tmp"
  : >"$dir/state/events"
  make_fake_tools "$dir/bin"
  make_child "$dir/child"

  set +e
  PATH="$dir/bin" MOCK_MODE="$mode" MOCK_STATE="$dir/state" TMPDIR="$dir/tmp" \
    BAO_ADDR='https://openbao.example.invalid' BAO_TOKEN='stale-owner-token' \
    CODEWIRE_DEV_SMOKE_API_KEY="$STALE_API_KEY" \
    EXPECTED_CODEWIRE_SMOKE_USER_EMAIL="$STALE_EMAIL" \
    CODEWIRE_API_KEY="$STALE_API_KEY" \
    "$WRAPPER" -- "$dir/child" >"$dir/out" 2>"$dir/err"
  rc=$?
  set -e

  if [[ "$expected" == success ]]; then
    [[ "$rc" == 0 && -f "$dir/state/child" ]] || fail "$mode unexpectedly failed"
    grep -Fx 'child-safe' "$dir/out" >/dev/null || fail "$mode did not run child"
  else
    [[ "$rc" != 0 && ! -e "$dir/state/child" ]] || fail "$mode unexpectedly succeeded"
    grep -F "$expected_error" "$dir/err" >/dev/null || fail "$mode emitted wrong failure class"
  fi
  [[ "$(wc -l <"$dir/state/events")" == 1 ]] || fail "$mode made an unexpected read count"
  find "$dir/tmp" -mindepth 1 -print -quit | grep -q . && fail "$mode left private files"
  assert_redacted "$dir/out"
  assert_redacted "$dir/err"
}

grep -F 'readonly OPENBAO_ADDR="https://openbao.example.invalid"' "$WRAPPER" >/dev/null
grep -F 'readonly OPENBAO_PATH="apps/codewire/dev/ci-smoke"' "$WRAPPER" >/dev/null
if grep -Eqi 'infisical|secret-tool|platform_project' "$WRAPPER"; then
  fail 'auth wrapper still contains a legacy credential source'
fi

run_case success success
run_case read_failure failure 'failed to fetch the canonical Dev smoke document'
run_case permission failure 'OpenBao OIDC session is stale or lacks the exact Dev smoke path'
run_case wrong_shape failure 'unexpected shape'
run_case extra_field failure 'unexpected shape'
run_case invalid_key failure 'unexpected shape'
run_case invalid_email failure 'unexpected shape'

printf 'with-dev-smoke-auth OpenBao tests: OK\n'
