#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROVISIONER="$ROOT/scripts/runtime/dev/provision-dev-smoke-user.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-smoke-provision-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly OLD_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly CANDIDATE_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly CONCURRENT_KEY="cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
readonly EMAIL="codewire-dev-smoke@codewire-dev.sh"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'dev smoke provisioning tests: %s\n' "$*" >&2; exit 1; }

assert_redacted() {
  local file="$1" marker
  [[ -f "$file" ]] || return 0
  for marker in "$OLD_KEY" "$CANDIDATE_KEY" "$CONCURRENT_KEY"; do
    if grep -F "$marker" "$file" >/dev/null; then
      fail 'API-key fixture reached output'
    fi
  done
}

make_fake_tools() {
  local bin="$1"
  mkdir -p "$bin"

  cat >"$bin/kubectl" <<'FAKE_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail
[[ "${INFRA_KUBECONFIG_DIR:-}" == "$MOCK_STATE/kube" ]]
[[ "${KUBECONFIG:-}" == "$MOCK_STATE/kube/scoped.yaml" ]]
sql="$(sed -n '1,$p')"
printf '%s\n-- statement boundary --\n' "$sql" >>"$MOCK_STATE/psql.sql"
active="$(<"$MOCK_STATE/active-keys")"
if grep -F 'SELECT raw_key.value' <<<"$sql" >/dev/null; then
  printf 'db-stage\n' >>"$MOCK_STATE/events"
  printf '%s' "$((active + 1))" >"$MOCK_STATE/active-keys"
  printf '%s\n' 'cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
elif grep -F 'COALESCE(disabled_at, NOW())' <<<"$sql" >/dev/null; then
  printf 'db-rollback\n' >>"$MOCK_STATE/events"
  printf '%s' "$((active - 1))" >"$MOCK_STATE/active-keys"
  printf '0\n'
elif grep -F 'api_keys.key_hash <>' <<<"$sql" >/dev/null; then
  printf 'db-finalize\n' >>"$MOCK_STATE/events"
  printf '1' >"$MOCK_STATE/active-keys"
elif grep -F 'final database state assertion' <<<"$sql" >/dev/null; then
  printf 'db-verify\n' >>"$MOCK_STATE/events"
  if [[ "$MOCK_MODE" == finalize_verify_failure ]]; then
    printf '1|2|1\n'
  else
    printf '1|%s|1\n' "$(<"$MOCK_STATE/active-keys")"
  fi
else
  exit 92
fi
FAKE_KUBECTL

  cat >"$bin/bao" <<'FAKE_BAO'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  'kv get')
    [[ "$3" == '-format=json' && "$4" == 'apps/codewire/dev/ci-smoke' ]]
    printf 'bao-get\n' >>"$MOCK_STATE/events"
    if [[ "$MOCK_MODE" == read_failure ]]; then
      printf 'connection refused\n' >&2
      exit 2
    fi
    if [[ "$MOCK_MODE" == permission ]]; then
      printf 'permission denied (status code: 403)\n' >&2
      exit 2
    fi
    if [[ "$MOCK_MODE" == malformed ]]; then
      printf '%s\n' '{"data":{"metadata":{"version":1},"data":[]}}'
      exit 0
    fi
    get_count=0
    [[ ! -f "$MOCK_STATE/get-count" ]] || get_count="$(<"$MOCK_STATE/get-count")"
    get_count=$((get_count + 1))
    printf '%s' "$get_count" >"$MOCK_STATE/get-count"
    if [[ "$MOCK_MODE" == concurrent_publish && "$get_count" == 3 ]]; then
      jq '.data.metadata.version += 1 | .data.data.apiKey = "cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"' \
        "$MOCK_STATE/openbao.json" >"$MOCK_STATE/openbao.next"
      mv "$MOCK_STATE/openbao.next" "$MOCK_STATE/openbao.json"
    fi
    cat "$MOCK_STATE/openbao.json"
    ;;
  'kv put')
    printf 'bao-put\n' >>"$MOCK_STATE/events"
    count=0
    [[ ! -f "$MOCK_STATE/put-count" ]] || count="$(<"$MOCK_STATE/put-count")"
    count=$((count + 1))
    printf '%s' "$count" >"$MOCK_STATE/put-count"
    [[ "$3" == -cas=* && "$4" == 'apps/codewire/dev/ci-smoke' && "$5" == @* ]]
    if [[ "$MOCK_MODE" == cas_failure && "$count" == 1 ]]; then
      printf 'check-and-set parameter did not match current version\n' >&2
      exit 2
    fi
    expected="${3#-cas=}"
    actual="$(jq -er '.data.metadata.version' "$MOCK_STATE/openbao.json")"
    [[ "$expected" == "$actual" ]] || exit 93
    payload="${5#@}"
    [[ -f "$payload" && "$(stat -c '%a' "$payload")" == 600 ]]
    next=$((actual + 1))
    jq -n --argjson version "$next" --slurpfile data "$payload" \
      '{data:{metadata:{version:$version},data:$data[0]}}' >"$MOCK_STATE/openbao.next"
    mv "$MOCK_STATE/openbao.next" "$MOCK_STATE/openbao.json"
    printf 'written\n'
    ;;
  *) exit 94 ;;
esac
FAKE_BAO

  cat >"$bin/cw" <<'FAKE_CW'
#!/usr/bin/env bash
set -euo pipefail
printf 'probe\n' >>"$MOCK_STATE/events"
[[ "${CODEWIRE_API_KEY:-}" == 'cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
[[ -n "${CW_CONFIG_DIR:-}" && -d "$CW_CONFIG_DIR" ]]
[[ "$*" == '--server https://codewire-dev.sh org list --output json' ]]
if [[ "$MOCK_MODE" == probe_failure ]]; then
  printf 'session expired or invalid\n' >&2
  exit 1
fi
printf '%s\n' '[{"slug":"codewire-dev-smoke","role":"owner"}]'
FAKE_CW

  chmod 0755 "$bin/kubectl" "$bin/bao" "$bin/cw"
  for name in awk bash cat chmod dirname find grep jq mkdir mktemp mv \
    rg rmdir rm sed sha256sum shred stat; do
    ln -s "$(command -v "$name")" "$bin/$name"
  done
}

run_case() {
  local mode="$1" expected="$2" expected_events="$3" expected_error="${4:-}"
  local dir="$TEST_TMP/$mode" rc
  mkdir -p "$dir/bin" "$dir/state/kube" "$dir/tmp"
  chmod 0700 "$dir/state" "$dir/state/kube" "$dir/tmp"
  : >"$dir/state/kube/scoped.yaml"
  : >"$dir/state/events"
  : >"$dir/state/psql.sql"
  if [[ "$mode" == interrupted ]]; then
    printf '2' >"$dir/state/active-keys"
  else
    printf '1' >"$dir/state/active-keys"
  fi
  jq -n --arg apiKey "$OLD_KEY" --arg userEmail "$EMAIL" \
    '{data:{metadata:{version:7},data:{apiKey:$apiKey,userEmail:$userEmail}}}' \
    >"$dir/state/openbao.json"
  make_fake_tools "$dir/bin"

  set +e
  PATH="$dir/bin" MOCK_MODE="$mode" MOCK_STATE="$dir/state" TMPDIR="$dir/tmp" \
    INFRA_KUBECONFIG_DIR="$dir/state/kube" \
    KUBECONFIG="$dir/state/kube/scoped.yaml" \
    BAO_ADDR='https://openbao.example.invalid' CW_BIN="$dir/bin/cw" \
    "$PROVISIONER" >"$dir/out" 2>"$dir/err"
  rc=$?
  set -e

  if [[ "$expected" == success ]]; then
    [[ "$rc" == 0 ]] || fail "$mode unexpectedly failed"
    grep -F 'PASS canonical_store=openbao api_probe=true active_database_keys=1' \
      "$dir/err" >/dev/null || fail "$mode omitted success receipt"
    jq -e --arg key "$CANDIDATE_KEY" '.data.data.apiKey == $key' \
      "$dir/state/openbao.json" >/dev/null || fail "$mode did not retain candidate"
  else
    [[ "$rc" != 0 ]] || fail "$mode unexpectedly succeeded"
    grep -F "$expected_error" "$dir/err" >/dev/null || fail "$mode emitted wrong failure class"
  fi
  printf '%s\n' "$expected_events" >"$dir/expected-events"
  cmp -s "$dir/expected-events" "$dir/state/events" || {
    sed -n '1,80p' "$dir/state/events" >&2
    fail "$mode crossed an unexpected transaction boundary"
  }
  find "$dir/tmp" -mindepth 1 -print -quit | grep -q . && fail "$mode left private files"
  assert_redacted "$dir/out"
  assert_redacted "$dir/err"
  assert_redacted "$dir/state/events"
  if [[ "$expected" == success ]]; then
    [[ "$(<"$dir/state/active-keys")" == 1 ]] ||
      fail "$mode did not converge interrupted database state"
  fi
}

success_events=$'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify\nbao-get'
run_case success success "$success_events"
run_case interrupted success "$success_events"
run_case cas_failure failure $'bao-get\ndb-stage\nbao-put\ndb-rollback' \
  'CAS publication failed; candidate database key was disabled'
run_case probe_failure failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\nbao-put\nbao-get\ndb-rollback' \
  'candidate API authentication failed; prior document was restored and candidate disabled'
run_case concurrent_publish failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get' \
  'canonical OpenBao document changed concurrently; active keys were retained'
run_case finalize_verify_failure failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify' \
  'post-commit database verification did not observe the exact one-key/one-owner state'
run_case read_failure failure 'bao-get' 'unable to read the canonical Dev smoke document'
run_case permission failure 'bao-get' 'OpenBao OIDC session is stale or lacks the exact Dev smoke path'
run_case malformed failure 'bao-get' 'unexpected shape'

jq -e --arg key "$OLD_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/probe_failure/state/openbao.json" >/dev/null ||
  fail 'probe failure did not restore the old document'
jq -e --arg key "$CONCURRENT_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/concurrent_publish/state/openbao.json" >/dev/null ||
  fail 'concurrent publication was overwritten'
[[ "$(<"$TEST_TMP/concurrent_publish/state/active-keys")" == 2 ]] ||
  fail 'concurrent publication caused an active key to be disabled'
jq -e --arg key "$CANDIDATE_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/finalize_verify_failure/state/openbao.json" >/dev/null ||
  fail 'post-commit verification failure changed the API-proven canonical document'
[[ "$(<"$TEST_TMP/finalize_verify_failure/state/active-keys")" == 1 ]] ||
  fail 'post-commit verification failure rolled back committed key revocation'
probe_line="$(grep -n '^probe$' "$TEST_TMP/success/state/events" | cut -d: -f1)"
finalize_line="$(grep -n '^db-finalize$' "$TEST_TMP/success/state/events" | cut -d: -f1)"
[[ "$probe_line" -lt "$finalize_line" ]] ||
  fail 'test did not prove the API probe precedes key disablement'
grep -F 'api_keys.key_hash <>' "$TEST_TMP/success/state/psql.sql" >/dev/null ||
  fail 'finalization does not disable noncandidate keys'
grep -F 'api_keys.created_at < candidate_key.created_at' \
  "$TEST_TMP/success/state/psql.sql" >/dev/null ||
  fail 'finalization can disable keys created by a concurrent rotation'
grep -F 'final database state assertion' "$TEST_TMP/success/state/psql.sql" >/dev/null ||
  fail 'final database state is not verified in a separate statement'
printf 'dev smoke OpenBao rotation tests: OK\n'
