#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROVISIONER="$ROOT/scripts/runtime/prod/provision-prod-smoke-user.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-prod-smoke-provision-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly OLD_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly CANDIDATE_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly CONCURRENT_KEY="cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
readonly EMAIL="codewire-prod-smoke@codewire.sh"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'prod smoke provisioning tests: %s\n' "$*" >&2; exit 1; }
# The scripts take the cluster names from their environment; these are not real.
export CODEWIRE_DEV_CLUSTER=example-dev CODEWIRE_PROD_CLUSTER=example-prod

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
if [[ "$*" == 'config current-context' ]]; then
  if [[ "$MOCK_MODE" == wrong_cluster ]]; then printf 'example-dev\n'; else printf 'example-prod\n'; fi
  exit 0
fi
if [[ "$1 $2 $3 $4" == '-n prod get pods' ]]; then
  [[ "$*" == '-n prod get pods -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o json' ]] || exit 95
  printf 'primary-lookup\n' >>"$MOCK_STATE/events"
  if [[ "$MOCK_MODE" == two_primaries ]]; then
    printf '%s\n' '{"items":[{"metadata":{"name":"codewire-db-1"},"status":{"phase":"Running"}},{"metadata":{"name":"codewire-db-2"},"status":{"phase":"Running"}}]}'
  else
    printf '%s\n' '{"items":[{"metadata":{"name":"codewire-db-2"},"status":{"phase":"Running"}}]}'
  fi
  exit 0
fi
[[ "$1 $2 $3 $4 $5 $6 $7" == '-n prod exec -i codewire-db-2 -c postgres' ]] || exit 96
sql="$(sed -n '1,$p')"
printf '%s\n-- statement boundary --\n' "$sql" >>"$MOCK_STATE/psql.sql"
active="$(<"$MOCK_STATE/active-keys")"
if grep -F 'FROM billing_catalog_plans' <<<"$sql" >/dev/null; then
  printf 'db-plan\n' >>"$MOCK_STATE/events"
  if [[ "$MOCK_MODE" == missing_plan ]]; then printf '0\n'; else printf '1\n'; fi
elif grep -F 'raw_key.value' <<<"$sql" >/dev/null; then
  printf 'db-stage\n' >>"$MOCK_STATE/events"
  if [[ "$MOCK_MODE" == foreign_slug ]]; then
    printf 'ERROR:  division by zero\n' >&2
    exit 3
  fi
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
    [[ "$3" == '-format=json' && "$4" == 'apps/codewire/prod/ci-smoke' ]]
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
    if [[ ! -f "$MOCK_STATE/openbao.json" ]]; then
      printf 'No value found at apps/data/codewire/prod/ci-smoke\n' >&2
      exit 2
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
    [[ "$3" == -cas=* && "$4" == 'apps/codewire/prod/ci-smoke' && "$5" == @* ]]
    if [[ "$MOCK_MODE" == cas_failure && "$count" == 1 ]]; then
      printf 'check-and-set parameter did not match current version\n' >&2
      exit 2
    fi
    expected="${3#-cas=}"
    actual=0
    [[ ! -f "$MOCK_STATE/openbao.json" ]] || actual="$(jq -er '.data.metadata.version' "$MOCK_STATE/openbao.json")"
    [[ "$expected" == "$actual" ]] || exit 93
    payload="${5#@}"
    [[ -f "$payload" && "$(stat -c '%a' "$payload")" == 600 ]]
    next=$((actual + 1))
    jq -n --argjson version "$next" --slurpfile data "$payload" \
      '{data:{metadata:{version:$version},data:$data[0]}}' >"$MOCK_STATE/openbao.next"
    mv "$MOCK_STATE/openbao.next" "$MOCK_STATE/openbao.json"
    printf 'written\n'
    ;;
  'kv metadata')
    [[ "$3" == delete && "$4" == 'apps/codewire/prod/ci-smoke' ]]
    printf 'bao-delete\n' >>"$MOCK_STATE/events"
    rm -f "$MOCK_STATE/openbao.json"
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
[[ "$*" == '--server https://codewire.sh org list --output json' ]]
if [[ "$MOCK_MODE" == probe_failure || "$MOCK_MODE" == first_probe_failure ]]; then
  printf 'session expired or invalid\n' >&2
  exit 1
fi
printf '%s\n' '[{"slug":"codewire-prod-smoke","role":"owner"}]'
FAKE_CW

  chmod 0755 "$bin/kubectl" "$bin/bao" "$bin/cw"
  for name in awk bash cat chmod dirname find grep jq mkdir mktemp mv \
    rg rmdir rm sed sha256sum shred stat; do
    ln -s "$(command -v "$name")" "$bin/$name"
  done
}

run_case() {
  local mode="$1" expected="$2" expected_events="$3" expected_error="${4:-}"
  local dir="$TEST_TMP/$mode" rc confirm=example-prod
  [[ "$mode" != unconfirmed ]] || confirm=example-dev
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
  if [[ "$mode" != first_run && "$mode" != first_probe_failure ]]; then
    jq -n --arg apiKey "$OLD_KEY" --arg userEmail "$EMAIL" \
      '{data:{metadata:{version:7},data:{apiKey:$apiKey,userEmail:$userEmail}}}' \
      >"$dir/state/openbao.json"
  fi
  make_fake_tools "$dir/bin"

  set +e
  PATH="$dir/bin" MOCK_MODE="$mode" MOCK_STATE="$dir/state" TMPDIR="$dir/tmp" \
    INFRA_KUBECONFIG_DIR="$dir/state/kube" \
    KUBECONFIG="$dir/state/kube/scoped.yaml" \
    BAO_ADDR='https://openbao.example.invalid' CW_BIN="$dir/bin/cw" \
    "$PROVISIONER" --confirm-production "$confirm" >"$dir/out" 2>"$dir/err"
  rc=$?
  set -e

  if [[ "$expected" == success ]]; then
    [[ "$rc" == 0 ]] || { sed -n '1,20p' "$dir/err" >&2; fail "$mode unexpectedly failed"; }
    grep -F 'PASS canonical_store=openbao api_probe=true active_database_keys=1' \
      "$dir/err" >/dev/null || fail "$mode omitted success receipt"
    jq -e --arg key "$CANDIDATE_KEY" '.data.data.apiKey == $key' \
      "$dir/state/openbao.json" >/dev/null || fail "$mode did not retain candidate"
  else
    [[ "$rc" != 0 ]] || fail "$mode unexpectedly succeeded"
    grep -F "$expected_error" "$dir/err" >/dev/null || { sed -n '1,20p' "$dir/err" >&2; fail "$mode emitted wrong failure class"; }
  fi
  printf '%s\n' "$expected_events" >"$dir/expected-events"
  [[ -n "$expected_events" ]] || : >"$dir/expected-events"
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

pre=$'primary-lookup\nbao-get\ndb-plan'
success_events="$pre"$'\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify\nbao-get'
run_case success success "$success_events"
run_case interrupted success "$success_events"
run_case first_run success "$success_events"
run_case unconfirmed failure '' 'Production provisioning requires --confirm-production example-prod'
run_case wrong_cluster failure '' 'scoped kube-access does not target example-prod'
run_case two_primaries failure 'primary-lookup' 'Production database does not have exactly one running primary'
run_case missing_plan failure "$pre" 'the smoke plan is not an active admin-only sandbox plan'
run_case foreign_slug failure "$pre"$'\ndb-stage' \
  'candidate creation failed and was rolled back'
run_case cas_failure failure "$pre"$'\ndb-stage\nbao-put\ndb-rollback' \
  'CAS publication failed; candidate database key was disabled'
run_case probe_failure failure \
  "$pre"$'\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\nbao-put\nbao-get\ndb-rollback' \
  'candidate API authentication failed; prior document was restored and candidate disabled'
run_case first_probe_failure failure \
  "$pre"$'\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\nbao-delete\nbao-get\ndb-rollback' \
  'candidate API authentication failed; prior document was restored and candidate disabled'
run_case concurrent_publish failure \
  "$pre"$'\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get' \
  'canonical OpenBao document changed concurrently; active keys were retained'
run_case finalize_verify_failure failure \
  "$pre"$'\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify' \
  'post-commit database verification did not observe the exact one-key/one-owner state'
run_case read_failure failure $'primary-lookup\nbao-get' 'unable to read the canonical Prod smoke document'
run_case permission failure $'primary-lookup\nbao-get' 'OpenBao OIDC session is stale or lacks the exact Prod smoke path'
run_case malformed failure $'primary-lookup\nbao-get' 'unexpected shape'

jq -e --arg key "$OLD_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/probe_failure/state/openbao.json" >/dev/null ||
  fail 'probe failure did not restore the old document'
[[ ! -e "$TEST_TMP/first_probe_failure/state/openbao.json" ]] ||
  fail 'a failed first run left a readable canonical document'
jq -e --arg key "$CONCURRENT_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/concurrent_publish/state/openbao.json" >/dev/null ||
  fail 'concurrent publication was overwritten'
[[ "$(<"$TEST_TMP/concurrent_publish/state/active-keys")" == 2 ]] ||
  fail 'concurrent publication caused an active key to be disabled'
[[ "$(<"$TEST_TMP/foreign_slug/state/active-keys")" == 1 ]] ||
  fail 'a refused organization slug created a key'
jq -e --arg key "$OLD_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/foreign_slug/state/openbao.json" >/dev/null ||
  fail 'a refused organization slug changed the canonical document'
jq -e --arg key "$CANDIDATE_KEY" '.data.data.apiKey == $key' \
  "$TEST_TMP/finalize_verify_failure/state/openbao.json" >/dev/null ||
  fail 'post-commit verification failure changed the API-proven canonical document'
[[ "$(<"$TEST_TMP/finalize_verify_failure/state/active-keys")" == 1 ]] ||
  fail 'post-commit verification failure rolled back committed key revocation'
probe_line="$(grep -n '^probe$' "$TEST_TMP/success/state/events" | cut -d: -f1)"
finalize_line="$(grep -n '^db-finalize$' "$TEST_TMP/success/state/events" | cut -d: -f1)"
[[ "$probe_line" -lt "$finalize_line" ]] ||
  fail 'test did not prove the API probe precedes key disablement'
sql="$TEST_TMP/success/state/psql.sql"
grep -F 'api_keys.key_hash <>' "$sql" >/dev/null ||
  fail 'finalization does not disable noncandidate keys'
grep -F 'api_keys.created_at < candidate_key.created_at' "$sql" >/dev/null ||
  fail 'finalization can disable keys created by a concurrent rotation'
grep -F 'final database state assertion' "$sql" >/dev/null ||
  fail 'final database state is not verified in a separate statement'
grep -F 'is_admin = false, enabled = true' "$sql" >/dev/null ||
  fail 'a repaired smoke user could keep admin rights or stay disabled'
grep -F 'WHERE organizations.created_by = EXCLUDED.created_by' "$sql" >/dev/null ||
  fail 'the smoke organization upsert can take over another user'"'"'s organization'
if grep -E -i 'CREATE EXTENSION|INSERT INTO billing_catalog_plans|confidential_sandbox' "$sql" >/dev/null; then
  fail 'Production provisioning writes an extension or billing catalog row'
fi
# Without the Production cluster's name nothing runs: an empty name never
# matches an empty confirmation.
for confirm in example-prod ''; do
  if output="$(env -u CODEWIRE_PROD_CLUSTER "$PROVISIONER" --confirm-production "$confirm" 2>&1)"; then
    fail 'provisioning ran without CODEWIRE_PROD_CLUSTER'
  fi
  [[ "$output" == *'CODEWIRE_PROD_CLUSTER is required'* ]] || fail "a missing Production cluster name is not named: $output"
done
printf 'prod smoke OpenBao provisioning tests: OK\n'
