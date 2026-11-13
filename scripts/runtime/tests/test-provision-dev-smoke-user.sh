#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR  # the tests exercise the script default

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROVISIONER="$ROOT/scripts/runtime/dev/provision-dev-smoke-user.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-smoke-provision-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly OLD_KEY="cw_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
readonly CANDIDATE_KEY="cw_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
readonly CONCURRENT_KEY="cw_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
readonly EMAIL="codewire-dev-smoke@codewire-dev.sh"
readonly SMOKE_PATH="apps/codewire/dev/ci-smoke"
readonly REHEARSAL_PATH="apps/codewire/dev/ci-billing-rehearsal"
readonly REHEARSAL_EMAIL="codewire-dev-billing-rehearsal@codewire-dev.sh"
readonly REHEARSAL_SLUG="codewire-dev-billing-rehearsal"
REHEARSAL_ARGS=(
  --email "$REHEARSAL_EMAIL"
  --name 'Codewire Dev billing rehearsal'
  --org-name 'Codewire Dev billing rehearsal'
  --org-slug "$REHEARSAL_SLUG"
  --key-name dev-billing-rehearsal
  --openbao-path "$REHEARSAL_PATH"
  --rate-card regular
)

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
  local bin="$1" name
  mkdir -p "$bin"

  cat >"$bin/kubectl" <<'FAKE_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail
[[ "${INFRA_KUBECONFIG_DIR:-}" == "$MOCK_STATE/kube" ]]
[[ "${KUBECONFIG:-}" == "$MOCK_STATE/kube/scoped.yaml" ]]
if [[ "$*" == '-n dev get pods -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o name' ]]; then
  printf 'lookup\n' >>"$MOCK_STATE/primary-lookups"
  [[ -z "$MOCK_PRIMARIES" ]] || printf '%s\n' "$MOCK_PRIMARIES"
  exit 0
fi
[[ "$1 $2 $3 $4" == "-n dev exec -i" ]] || exit 91
sql="$(sed -n '1,$p')"
printf '%s\n-- statement boundary --\n' "$sql" >>"$MOCK_STATE/psql.sql"
printf '%s\n' "$*" >>"$MOCK_STATE/psql.args"
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
  if [[ "$MOCK_MODE" == *finalize_verify_failure ]]; then
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
    [[ "$3" == '-format=json' && "$4" == "$MOCK_OPENBAO_PATH" ]]
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
      printf 'No value found at %s\n' "${4/\/codewire\//\/data\/codewire\/}" >&2
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
    [[ "$3" == -cas=* && "$4" == "$MOCK_OPENBAO_PATH" && "$5" == @* ]]
    printf '%s\n' "$3" >>"$MOCK_STATE/put-cas"
    if [[ "$MOCK_MODE" == *cas_failure && "$count" == 1 ]]; then
      printf 'check-and-set parameter did not match current version\n' >&2
      exit 2
    fi
    expected="${3#-cas=}"
    # -cas=0 writes only when the path has no document yet.
    actual=0
    [[ ! -f "$MOCK_STATE/openbao.json" ]] ||
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
if [[ "$MOCK_MODE" == *probe_failure ]]; then
  printf 'session expired or invalid\n' >&2
  exit 1
fi
jq -cn --arg slug "$MOCK_ORG_SLUG" '[{slug:$slug,role:"owner"}]'
FAKE_CW

  chmod 0755 "$bin/kubectl" "$bin/bao" "$bin/cw"
  for name in awk bash cat chmod dirname find grep jq mkdir mktemp mv \
    rg rmdir rm sed sha256sum shred stat wc; do
    ln -s "$(command -v "$name")" "$bin/$name"
  done
}

# CASE_DOCUMENT=absent starts with no OpenBao document and no active key;
# CASE_OPENBAO_PATH and CASE_ORG_SLUG tell the fakes which identity to expect.
prepare_case() {
  local dir="$1"
  mkdir -p "$dir/bin" "$dir/state/kube" "$dir/tmp"
  chmod 0700 "$dir/state" "$dir/state/kube" "$dir/tmp"
  : >"$dir/state/kube/scoped.yaml"
  : >"$dir/state/events"
  : >"$dir/state/psql.sql"
  : >"$dir/state/psql.args"
  : >"$dir/state/primary-lookups"
  if [[ "${CASE_DOCUMENT:-present}" == absent ]]; then
    printf '0' >"$dir/state/active-keys"
  else
    if [[ "$(basename "$dir")" == interrupted ]]; then
      printf '2' >"$dir/state/active-keys"
    else
      printf '1' >"$dir/state/active-keys"
    fi
    jq -n --arg apiKey "$OLD_KEY" --arg userEmail "$EMAIL" \
      '{data:{metadata:{version:7},data:{apiKey:$apiKey,userEmail:$userEmail}}}' \
      >"$dir/state/openbao.json"
  fi
  make_fake_tools "$dir/bin"
}

# Runs the provisioner in a prepared case directory and checks its outcome.
invoke_case() {
  local dir="$1" mode="$2" expected="$3" expected_events="$4" expected_error="$5"
  shift 5
  local name rc
  name="$(basename "$dir")"
  : >"$dir/state/events"
  set +e
  PATH="$dir/bin" MOCK_MODE="$mode" MOCK_STATE="$dir/state" TMPDIR="$dir/tmp" \
    MOCK_OPENBAO_PATH="${CASE_OPENBAO_PATH:-$SMOKE_PATH}" \
    MOCK_ORG_SLUG="${CASE_ORG_SLUG:-codewire-dev-smoke}" \
    MOCK_PRIMARIES="${CASE_PRIMARIES-pod/codewire-db-3}" \
    INFRA_KUBECONFIG_DIR="$dir/state/kube" \
    KUBECONFIG="$dir/state/kube/scoped.yaml" \
    BAO_ADDR='https://openbao.example.invalid' CW_BIN="$dir/bin/cw" \
    "$PROVISIONER" "$@" >"$dir/out" 2>"$dir/err"
  rc=$?
  set -e
  if [[ "$expected" == success ]]; then
    [[ "$rc" == 0 ]] || fail "$name unexpectedly failed"
    grep -F 'PASS canonical_store=openbao api_probe=true active_database_keys=1' \
      "$dir/err" >/dev/null || fail "$name omitted success receipt"
    jq -e --arg key "$CANDIDATE_KEY" '.data.data.apiKey == $key' \
      "$dir/state/openbao.json" >/dev/null || fail "$name did not retain candidate"
  else
    [[ "$rc" != 0 ]] || fail "$name unexpectedly succeeded"
    grep -F -e "$expected_error" "$dir/err" >/dev/null || fail "$name emitted wrong failure class"
  fi
  if [[ -n "$expected_events" ]]; then
    printf '%s\n' "$expected_events" >"$dir/expected-events"
  else
    : >"$dir/expected-events"
  fi
  cmp -s "$dir/expected-events" "$dir/state/events" || {
    sed -n '1,80p' "$dir/state/events" >&2
    fail "$name crossed an unexpected transaction boundary"
  }
  find "$dir/tmp" -mindepth 1 -print -quit | grep -q . && fail "$name left private files"
  assert_redacted "$dir/out"
  assert_redacted "$dir/err"
  assert_redacted "$dir/state/events"
  if [[ "$expected" == success ]]; then
    [[ "$(<"$dir/state/active-keys")" == 1 ]] ||
      fail "$name did not converge interrupted database state"
  fi
}

# run_case NAME MODE success|failure EVENTS [ERROR [SCRIPT ARGS...]]
run_case() {
  local name="$1" mode="$2"
  shift 2
  [[ "$#" -ge 3 ]] || set -- "$@" ''
  prepare_case "$TEST_TMP/$name"
  invoke_case "$TEST_TMP/$name" "$mode" "$@"
}

# A refusal before any OpenBao or database call.
run_refusal() {
  local name="$1" expected_error="$2"
  shift 2
  run_case "$name" success failure '' "$expected_error" "$@"
}

success_events=$'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify\nbao-get'
run_case success success success "$success_events"
run_case interrupted interrupted success "$success_events"
run_case postgres_pod_override success success "$success_events" '' \
  --postgres-pod codewire-db-2
CASE_PRIMARIES='' run_case no_primary success failure '' \
  'expected exactly one codewire-db primary'
CASE_PRIMARIES=$'pod/codewire-db-2\npod/codewire-db-3' run_case two_primaries success failure '' \
  'expected exactly one codewire-db primary'
run_case cas_failure cas_failure failure $'bao-get\ndb-stage\nbao-put\ndb-rollback' \
  'CAS publication failed; candidate database key was disabled'
run_case probe_failure probe_failure failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\nbao-put\nbao-get\ndb-rollback' \
  'candidate API authentication failed; prior document was restored and candidate disabled'
run_case concurrent_publish concurrent_publish failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get' \
  'canonical OpenBao document changed concurrently; active keys were retained'
run_case finalize_verify_failure finalize_verify_failure failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify' \
  'post-commit database verification did not observe the exact one-key/one-owner state'
run_case read_failure read_failure failure 'bao-get' 'unable to read the canonical Dev document'
run_case permission permission failure 'bao-get' \
  "OpenBao OIDC session is stale or lacks the exact Dev path $SMOKE_PATH"
run_case malformed malformed failure 'bao-get' 'unexpected shape'
CASE_DOCUMENT=absent run_case missing_document success failure 'bao-get' \
  "canonical Dev document $SMOKE_PATH does not exist; pass --create-document only for a new identity"

# The billing-rehearsal identity: regular rate card, its own document.
CASE_DOCUMENT=absent CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_create success success "$success_events" '' \
  "${REHEARSAL_ARGS[@]}" --create-document
CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_rotate success success "$success_events" '' "${REHEARSAL_ARGS[@]}"
CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_create_existing success failure 'bao-get' \
  "OpenBao $REHEARSAL_PATH already exists; rerun without --create-document" \
  "${REHEARSAL_ARGS[@]}" --create-document
CASE_DOCUMENT=absent CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_missing success failure 'bao-get' \
  "canonical Dev document $REHEARSAL_PATH does not exist" "${REHEARSAL_ARGS[@]}"
CASE_DOCUMENT=absent CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_create_cas_failure create_cas_failure failure \
  $'bao-get\ndb-stage\nbao-put\ndb-rollback' \
  'CAS publication failed; candidate database key was disabled' \
  "${REHEARSAL_ARGS[@]}" --create-document
created_disabled="OpenBao $REHEARSAL_PATH was created by this run and now holds a disabled key; rerun without --create-document to rotate it"
CASE_DOCUMENT=absent CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_create_probe_failure create_probe_failure failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\ndb-rollback' "$created_disabled" \
  "${REHEARSAL_ARGS[@]}" --create-document
CASE_DOCUMENT=absent CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
  run_case rehearsal_create_finalize_failure create_finalize_verify_failure failure \
  $'bao-get\ndb-stage\nbao-put\nbao-get\nprobe\nbao-get\ndb-finalize\ndb-verify\ndb-rollback' \
  "$created_disabled" "${REHEARSAL_ARGS[@]}" --create-document

# Refusals that touch neither OpenBao nor the database.
run_refusal plan_key_regular '--plan-key applies only to --rate-card unlimited' \
  "${REHEARSAL_ARGS[@]}" --plan-key unlimited
run_refusal rate_card_unknown '--rate-card must be unlimited or regular' --rate-card discounted
run_refusal smoke_regular 'the Dev smoke identity stays unlimited' --rate-card regular \
  --openbao-path "$REHEARSAL_PATH"
run_refusal rehearsal_unlimited 'the billing-rehearsal identity is never unlimited' \
  "${REHEARSAL_ARGS[@]}" --rate-card unlimited
run_refusal acceptance_account 'the browser acceptance account is never provisioned' \
  "${REHEARSAL_ARGS[@]}" --email e2e@codewire.sh
bad_path_index=0
for bad_path in apps/codewire/prod/ci-smoke apps/codewire/dev/ apps/codewire/dev/Ci-smoke \
  apps/codewire/dev/ci_smoke apps/codewire/dev/ci-smoke/extra apps/codewire/dev/-ci \
  apps/codewire/dev/../prod/ci-smoke ' apps/codewire/dev/ci-smoke'; do
  bad_path_index=$((bad_path_index + 1))
  run_refusal "bad_openbao_path_$bad_path_index" \
    'OpenBao path must be apps/codewire/dev/<lowercase-slug>' --openbao-path "$bad_path"
done

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
# The default staging statement is the smoke identity's: the confidential-plan
# upsert and an unlimited, billing-exempt organization.
success_sql="$TEST_TMP/success/state/psql.sql"
for expected in 'INSERT INTO billing_catalog_plans' "'active'::text AS billing_status" \
  'true AS billing_exempt' "'unlimited'::text AS rate_card" "SELECT 'confidential_sandbox', :'plan_key'::text"; do
  grep -F "$expected" "$success_sql" >/dev/null ||
    fail "default staging statement lost: $expected"
done
grep -F -- '--set plan_key=unlimited' "$TEST_TMP/success/state/psql.args" >/dev/null ||
  fail 'default staging statement lost its plan key'

# The regular staging statement: no confidential-plan upsert, no plan key, and
# an ordinary organization (plan none, status none, not exempt, regular).
for name in rehearsal_create rehearsal_rotate; do
  rehearsal_sql="$TEST_TMP/$name/state/psql.sql"
  for unexpected in billing_catalog_plans confidential_plan plan_key "'unlimited'" \
    'true AS billing_exempt' "'active'"; do
    if grep -F "$unexpected" "$rehearsal_sql" >/dev/null; then
      fail "$name staging statement contains $unexpected"
    fi
  done
  for expected in "'none'::text AS billing_plan" "'none'::text AS billing_status" \
    'false AS billing_exempt' "'regular'::text AS rate_card" 'FROM input, smoke_user, org_billing'; do
    grep -F "$expected" "$rehearsal_sql" >/dev/null || fail "$name staging statement lacks $expected"
  done
  if grep -F 'plan_key' "$TEST_TMP/$name/state/psql.args" >/dev/null; then
    fail "$name sent a plan key"
  fi
  grep -F -- "--set org_slug=$REHEARSAL_SLUG" "$TEST_TMP/$name/state/psql.args" >/dev/null ||
    fail "$name did not stage the rehearsal organization"
  jq -e --arg email "$REHEARSAL_EMAIL" '.data.data.userEmail == $email' \
    "$TEST_TMP/$name/state/openbao.json" >/dev/null || fail "$name published the wrong user"
done

# Create mode publishes with -cas=0 and leaves a first version; a rotation
# compares against the version it read.
[[ "$(<"$TEST_TMP/rehearsal_create/state/put-cas")" == '-cas=0' ]] ||
  fail 'create mode did not publish with -cas=0'
jq -e '.data.metadata.version == 1' "$TEST_TMP/rehearsal_create/state/openbao.json" >/dev/null ||
  fail 'create mode did not create the first document version'
[[ "$(<"$TEST_TMP/rehearsal_rotate/state/put-cas")" == '-cas=7' ]] ||
  fail 'rotation did not publish against the version it read'
# The database pod is the CloudNativePG primary, looked up once per run, unless
# --postgres-pod names one; anything but exactly one primary stops the run
# before OpenBao or the database is touched.
[[ "$(wc -l <"$TEST_TMP/success/state/primary-lookups")" == 1 ]] ||
  fail 'the primary was not looked up exactly once'
[[ "$(grep -c '' "$TEST_TMP/success/state/psql.args")" -gt 0 &&
  "$(grep -vc -- '^-n dev exec -i codewire-db-3 ' "$TEST_TMP/success/state/psql.args")" == 0 ]] ||
  fail 'queries did not all run on the looked-up primary'
[[ ! -s "$TEST_TMP/postgres_pod_override/state/primary-lookups" ]] ||
  fail '--postgres-pod still looked up the primary'
[[ "$(grep -vc -- '^-n dev exec -i codewire-db-2 ' "$TEST_TMP/postgres_pod_override/state/psql.args")" == 0 ]] ||
  fail '--postgres-pod did not choose the database pod'
for name in no_primary two_primaries; do
  [[ ! -s "$TEST_TMP/$name/state/psql.sql" ]] || fail "$name reached the database"
done

for name in rehearsal_create_existing rehearsal_missing missing_document; do
  [[ ! -s "$TEST_TMP/$name/state/psql.sql" ]] || fail "$name reached the database"
done
[[ ! -f "$TEST_TMP/rehearsal_create_cas_failure/state/openbao.json" ]] ||
  fail 'a failed create-mode publication left a document'
[[ "$(<"$TEST_TMP/rehearsal_create_cas_failure/state/active-keys")" == 0 ]] ||
  fail 'a failed create-mode publication left the candidate active'

# A create-mode failure after publication leaves the documented state: the
# document holds the candidate, now disabled, and no key is active. Rerunning
# without --create-document then rotates normally.
for name in rehearsal_create_probe_failure rehearsal_create_finalize_failure; do
  dir="$TEST_TMP/$name"
  jq -e --arg key "$CANDIDATE_KEY" '.data.data.apiKey == $key and .data.metadata.version == 1' \
    "$dir/state/openbao.json" >/dev/null || fail "$name did not leave the created document"
  [[ "$(<"$dir/state/active-keys")" == 0 ]] || fail "$name left the candidate key active"
  grep -F 'prior document was restored' "$dir/err" >/dev/null &&
    fail "$name claimed a restore that create mode cannot do"
  rm -f -- "$dir/state/get-count"
  CASE_OPENBAO_PATH="$REHEARSAL_PATH" CASE_ORG_SLUG="$REHEARSAL_SLUG" \
    invoke_case "$dir" success success "$success_events" '' "${REHEARSAL_ARGS[@]}"
  jq -e '.data.metadata.version == 2' "$dir/state/openbao.json" >/dev/null ||
    fail "$name rerun did not rotate the created document"
  [[ "$(sed -n '$p' "$dir/state/put-cas")" == '-cas=1' ]] ||
    fail "$name rerun did not publish against the created version"
done
printf 'dev smoke OpenBao rotation tests: OK\n'
