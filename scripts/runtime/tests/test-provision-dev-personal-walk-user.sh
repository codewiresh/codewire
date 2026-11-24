#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR CODEWIRE_SERVER_URL  # the tests exercise the script defaults

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROVISIONER="$ROOT/scripts/runtime/dev/provision-dev-personal-walk-user.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-personal-walk-provision-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
readonly OLD_PASSWORD="old-synthetic-personal-walk-password-0000000"
readonly ACCESS_HASH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# shellcheck disable=SC2016 # A literal PHC string, not an expansion.
readonly HASH='$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g'

# The provisioner refuses a runtime directory that is not on tmpfs, so each
# case's stands in under /dev/shm. Its TMPDIR stays on disk, and must stay empty.
[[ "$(stat -f -c %T /dev/shm 2>/dev/null)" == tmpfs ]] ||
  { printf 'dev personal-walk provisioning tests: /dev/shm is not tmpfs\n' >&2; exit 1; }
SHM_TMP="$(mktemp -d /dev/shm/codewire-personal-walk-provision-tests.XXXXXX)"
chmod 0700 "$SHM_TMP"

cleanup() { rm -rf -- "$TEST_TMP" "$SHM_TMP"; }
trap cleanup EXIT
fail() { printf 'dev personal-walk provisioning tests: %s\n' "$*" >&2; exit 1; }

make_fake_tools() {
  local bin="$1"
  mkdir -p "$bin"

  # Three database calls, told apart by what they send: the account write, the
  # listing of sessions and CLI sign-ins, and their revocation by id.
  cat >"$bin/kubectl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == '-n dev get pods -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o name' ]]; then
  printf 'pod/codewire-db-2\n'; exit 0
fi
[[ "$1 $2 $3 $4 $5" == "-n dev exec -i codewire-db-2" ]] || exit 91
printf '%s\n' "$*" >>"$MOCK_STATE/psql.args"
sql="$(cat)"
printf '%s\n' "$sql" >>"$MOCK_STATE/psql.sql"
if [[ "$sql" == *'INSERT INTO users'* ]]; then
  printf 'db-account\n' >>"$MOCK_STATE/events"
  [[ "$MOCK_MODE" != db_failure ]] || exit 1
  printf 'removed|1|2|1|1|0\n'
  if [[ "$MOCK_MODE" == bad_state ]]; then printf 'state|1|1|1|1|1|2|1|0|1|1\n'
  elif [[ "$MOCK_MODE" == over_credit ]]; then printf 'state|1|1|1|1|1|1|1|0|1|0\n'
  else printf 'state|1|1|1|1|1|1|1|0|1|1\n'; fi
elif [[ "$sql" == *"'session ' ||"* ]]; then
  printf 'db-list\n' >>"$MOCK_STATE/events"
  if [[ "$MOCK_MODE" == bad_grant_id ]]; then printf 'session bad;id\n'; exit 0; fi
  printf 'session s-1\nsession s-2\nrefresh r-1\naccess %s\n' "$ACCESS_HASH"
elif [[ "$sql" == *'DELETE FROM sessions'* ]]; then
  printf 'db-revoke\n' >>"$MOCK_STATE/events"
  printf 'revoked|2|1|1\n'
  if [[ "$MOCK_MODE" == revoke_incomplete ]]; then printf 'remaining|1\n'
  else printf 'remaining|0\n'; fi
else
  exit 92
fi
FAKE

  cat >"$bin/bao" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$BAO_ADDR" == https://openbao.example.invalid ]] || exit 92
printf '%s\n' "$*" >>"$MOCK_STATE/argv"
case "$1 $2" in
  'kv get')
    printf 'bao-get\n' >>"$MOCK_STATE/events"
    if [[ -f "$MOCK_STATE/published.json" ]]; then
      jq -n --slurpfile data "$MOCK_STATE/published.json" '{data: {metadata: {version: 4}, data: $data[0]}}'
      exit 0
    fi
    case "$MOCK_MODE" in
      rotate|probe_failure|cas_failure|create_existing|old_accepted|revoke_incomplete|bad_grant_id)
        jq -n --arg password "$OLD_PASSWORD" --arg email "$EMAIL" \
          '{data: {metadata: {version: 3}, data: {password: $password, userEmail: $email}}}' ;;
      malformed) printf '{"data":{"metadata":{"version":3},"data":{"apiKey":"cw_x"}}}\n' ;;
      wrong_email)
        jq -n --arg password "$OLD_PASSWORD" \
          '{data: {metadata: {version: 3}, data: {password: $password, userEmail: "person@example.test"}}}' ;;
      permission) printf 'Error: permission denied\n' >&2; exit 2 ;;
      *) printf 'No value found at %s\n' "$4" >&2; exit 2 ;;
    esac ;;
  'kv put')
    printf 'bao-put %s\n' "$3" >>"$MOCK_STATE/events"
    [[ "$MOCK_MODE" != cas_failure ]] || exit 2
    cp "${5#@}" "$MOCK_STATE/published.json" ;;
  *) exit 93 ;;
esac
FAKE

  cat >"$bin/curl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_STATE/argv"
url="${*: -1}" jar="" body="" origin=""
while (($# > 0)); do
  case "$1" in
    -c) jar="$2"; shift 2 ;;
    --data) body="$2"; shift 2 ;;
    -H) [[ "$2" != Origin:* ]] || origin="${2#Origin: }"; shift 2 ;;
    *) shift ;;
  esac
done
case "$url" in
  */api/auth/sign-in)
    if jq -e --arg old "$OLD_PASSWORD" '.password == $old' "${body#@}" >/dev/null; then
      printf 'curl sign-in-old\n' >>"$MOCK_STATE/events"
      if [[ "$MOCK_MODE" == old_accepted ]]; then
        printf '#HttpOnly_codewire-dev.sh\tFALSE\t/\tTRUE\t0\tcodewire.session_token\told\n' >"$jar"
        printf '200'
      else
        printf '401'
      fi
      exit 0
    fi
    printf 'curl sign-in\n' >>"$MOCK_STATE/events"
    jq -e --slurpfile doc "$MOCK_STATE/published.json" \
      '.password == $doc[0].password and .email == $doc[0].userEmail' "${body#@}" >/dev/null || exit 94
    if [[ "$MOCK_MODE" == probe_failure ]]; then printf '401'; exit 0; fi
    printf '#HttpOnly_codewire-dev.sh\tFALSE\t/\tTRUE\t0\tcodewire.session_token\tprobe\n' >"$jar"
    printf '200' ;;
  */api/auth/sign-out)
    [[ "$origin" == https://codewire-dev.sh ]] || exit 96
    printf 'curl sign-out\n' >>"$MOCK_STATE/events" ;;
  *) exit 95 ;;
esac
FAKE

  cat >"$bin/argon2" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >>"\$MOCK_STATE/argv"
[[ "\$*" == *' -id -t 3 -m 16 -p 2 -l 32 -e' ]] || exit 96
password="\$(cat)"
[[ \${#password} == 43 ]] || exit 97
printf '%s\n' '$HASH'
FAKE
  chmod 0755 "$bin"/*
}

# run_case NAME MODE EXPECT [ARGS...]: run the provisioner in MODE and check
# that it passes or fails as EXPECT says. Leaves the case folder in $CASE.
# SERVER_URL, when set, is passed as CODEWIRE_SERVER_URL.
run_case() {
  local name="$1" mode="$2" expect="$3"; shift 3
  CASE="$TEST_TMP/$name"
  mkdir -p "$CASE/state" "$CASE/kube" "$CASE/tmp"
  local runtime="${CASE_RUNTIME:-$SHM_TMP/$name}"
  [[ -n "${CASE_RUNTIME:-}" ]] || mkdir -m 0700 "$runtime"
  : >"$CASE/state/events"
  : >"$CASE/state/argv"
  make_fake_tools "$CASE/bin"
  local status=0
  local -a server=()
  [[ -z "${SERVER_URL:-}" ]] || server=(CODEWIRE_SERVER_URL="$SERVER_URL")
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE" TMPDIR="$CASE/tmp" XDG_RUNTIME_DIR="$runtime" \
    MOCK_STATE="$CASE/state" \
    MOCK_MODE="$mode" INFRA_KUBECONFIG_DIR="${KUBE_DIR-$CASE/kube}" KUBECONFIG="$CASE/kube/scoped.yaml" \
    EMAIL="$EMAIL" OLD_PASSWORD="$OLD_PASSWORD" ACCESS_HASH="$ACCESS_HASH" "${server[@]}" \
    bash "$PROVISIONER" "$@" >"$CASE/out" 2>&1 || status=$?
  if [[ "$expect" == pass ]]; then
    [[ "$status" == 0 ]] || { cat "$CASE/out" >&2; fail "$name: expected success, exit $status"; }
  else
    [[ "$status" != 0 ]] || { cat "$CASE/out" >&2; fail "$name: expected failure"; }
  fi
  local password
  for password in "$OLD_PASSWORD" \
    "$( [[ -f "$CASE/state/published.json" ]] && jq -r .password "$CASE/state/published.json")"; do
    [[ -n "$password" ]] || continue
    ! grep -qF -- "$password" "$CASE/out" || fail "$name: a password reached output"
    ! grep -qF -- "$password" "$CASE/state/argv" || fail "$name: a password reached argv"
    ! grep -qF -- "$password" "$CASE/state/psql.sql" 2>/dev/null || fail "$name: a password reached the database"
    ! grep -qF -- "$password" "$CASE/state/psql.args" 2>/dev/null || fail "$name: a password reached kubectl's argv"
  done
  [[ -z "$(find "$CASE/tmp" -mindepth 1 -print -quit)" ]] || fail "$name: wrote to the disk TMPDIR"
  [[ -z "$(find "$runtime" -mindepth 1 -print -quit)" ]] || fail "$name: left temporary files"
}

expect_events() {
  local want="$1"
  [[ "$(cat "$CASE/state/events")" == "$want" ]] ||
    fail "$(basename "$CASE"): events were [$(tr '\n' ',' <"$CASE/state/events")], want [$(tr '\n' ',' <<<"$want")]"
}
expect_output() {
  grep -qF -- "$1" "$CASE/out" || { cat "$CASE/out" >&2; fail "$(basename "$CASE"): output lacks: $1"; }
}
readonly PROVEN=$'bao-get\ndb-account\nbao-put -cas=3\nbao-get\ncurl sign-in\ncurl sign-out'

run_case create absent pass --create-document
expect_events $'bao-get\ndb-account\nbao-put -cas=0\nbao-get\ncurl sign-in\ncurl sign-out\ndb-list\ndb-revoke'
expect_output 'PASS canonical_store=openbao path=apps/codewire/dev/ci-personal-walk sign_in_probe=true old_password_refused=not_applicable'
expect_output 'removed sign_in_links=1 other_memberships=2 other_members=1 pending_invitations=1 api_keys=0'
expect_output 'revoked sessions=2 cli_refresh_tokens=1 cli_access_tokens=1'
jq -e --arg email "$EMAIL" 'keys == ["password", "userEmail"] and .userEmail == $email and
  (.password | test("^[A-Za-z0-9_-]{43}$"))' "$CASE/state/published.json" >/dev/null ||
  fail 'create: the published document has the wrong shape'
grep -qF "\\set hash '$HASH'" "$CASE/state/psql.sql" || fail 'create: the hash did not reach the database'
for value in "email=$EMAIL" 'org_slug=codewire-dev-personal-walk'; do
  grep -qF -- "$value" "$CASE/state/psql.args" || fail "create: psql was not given $value"
done
for statement in "'regular', false" 'is_admin = false' 'two_factor_enabled = false' \
  'WHERE organizations.created_by = EXCLUDED.created_by' 'DELETE FROM api_keys' \
  "DELETE FROM org_invitations WHERE org_id = :'walk_org_id' AND status = 'pending'" \
  "DELETE FROM org_members WHERE org_id = :'walk_org_id' AND user_id <> :'walk_user_id'" \
  "VALUES (:'walk_org_id', 2, 2, 4000, 16384)" "'grant', 5000000000 - balance" \
  'WHERE balance < 5000000000;' 'AND balance_nano_eur = 5000000000' \
  'auto_top_up_enabled = false' 'AND NOT auto_top_up_enabled'; do
  grep -qF -- "$statement" "$CASE/state/psql.sql" || fail "create: the SQL lacks: $statement"
done
# Revocation is by the exact ids listed, never by account alone.
for id_set in "\\set session_ids '{s-1,s-2}'" "\\set refresh_ids '{r-1}'" \
  "\\set access_ids '{$ACCESS_HASH}'"; do
  grep -qF -- "$id_set" "$CASE/state/psql.sql" || fail "create: the revocation lacks: $id_set"
done
! grep -qF "$ACCESS_HASH" "$CASE/state/psql.args" || fail 'create: a token hash reached kubectl argv'

run_case rotate rotate pass
expect_events "$PROVEN"$'\ndb-list\ndb-revoke\ncurl sign-in-old'
expect_output 'old_password_refused=true'
[[ "$(jq -r .password "$CASE/state/published.json")" != "$OLD_PASSWORD" ]] ||
  fail 'rotate: the password did not change'

run_case old_accepted old_accepted fail
expect_events "$PROVEN"$'\ndb-list\ndb-revoke\ncurl sign-in-old\ncurl sign-out'
expect_output 'Dev still accepts the old password'

run_case probe_failure probe_failure fail
expect_events $'bao-get\ndb-account\nbao-put -cas=3\nbao-get\ncurl sign-in'
expect_output 'no session or CLI sign-in was revoked'

run_case revoke_incomplete revoke_incomplete fail
expect_events "$PROVEN"$'\ndb-list\ndb-revoke'
expect_output 'still present'

run_case bad_grant_id bad_grant_id fail
expect_events "$PROVEN"$'\ndb-list'
expect_output 'unexpected shape'

run_case bad_state bad_state fail --create-document
expect_events $'bao-get\ndb-account'
expect_output 'expected account state'

# A balance the top-up couldn't bring to exactly EUR 5 (one above the bound)
# stops the run before anything is published.
run_case over_credit over_credit fail --create-document
expect_events $'bao-get\ndb-account'
expect_output 'expected account state'

run_case create_existing create_existing fail --create-document
expect_events 'bao-get'
expect_output 'already exists; rerun without --create-document'

run_case rotate_absent absent fail
expect_events 'bao-get'
expect_output 'does not exist; pass --create-document'

run_case permission permission fail
expect_events 'bao-get'
expect_output 'OIDC session is stale'

run_case malformed malformed fail
expect_events 'bao-get'
expect_output 'unexpected shape'

run_case wrong_email wrong_email fail
expect_events 'bao-get'
expect_output 'unexpected shape'

run_case db_failure db_failure fail --create-document
expect_events $'bao-get\ndb-account'
expect_output 'nothing was published'

run_case cas_failure cas_failure fail
expect_events $'bao-get\ndb-account\nbao-put -cas=3'
expect_output 'the OpenBao CAS write failed'

SERVER_URL=https://codewire.sh run_case production_server absent fail --create-document
expect_events ''
expect_output 'exists only on Dev; refusing server https://codewire.sh'

KUBE_DIR="" run_case no_kube_access absent fail --create-document
expect_events ''
expect_output 'scoped Infra kube-access wrapper'

# The runtime directory must be the caller's own 0700 tmpfs directory; a
# disk one is refused before anything is read or written.
mkdir -m 0700 "$TEST_TMP/disk-runtime"
CASE_RUNTIME="$TEST_TMP/disk-runtime" run_case disk_runtime absent fail --create-document
expect_events ''
expect_output 'XDG_RUNTIME_DIR is not on tmpfs'
mkdir -m 0755 "$SHM_TMP/open-runtime"
CASE_RUNTIME="$SHM_TMP/open-runtime" run_case open_runtime absent fail --create-document
expect_events ''
expect_output 'your own 0700 runtime directory'

printf 'dev personal-walk provisioning tests: PASS\n'
