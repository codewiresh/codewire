#!/usr/bin/env bash
set -euo pipefail
unset CODEWIRE_OPENBAO_ADDR CODEWIRE_SERVER_URL  # the tests exercise the script defaults

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROVISIONER="$ROOT/scripts/runtime/dev/provision-dev-invitee-user.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-invitee-provision-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly EMAIL="success+codewire-dev-invitee@simulator.amazonses.com"
# shellcheck disable=SC2016 # A literal PHC string, not an expansion.
readonly HASH='$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g'

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'dev invitee provisioning tests: %s\n' "$*" >&2; exit 1; }

make_fake_tools() {
  local bin="$1"
  mkdir -p "$bin"

  cat >"$bin/kubectl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == '-n dev get pods -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o name' ]]; then
  printf 'pod/codewire-db-2\n'; exit 0
fi
[[ "$1 $2 $3 $4 $5" == "-n dev exec -i codewire-db-2" ]] || exit 91
cat >>"$MOCK_STATE/psql.sql"
printf '%s\n' "$*" >>"$MOCK_STATE/psql.args"
printf 'db\n' >>"$MOCK_STATE/events"
[[ "$MOCK_MODE" != db_failure ]] || exit 1
printf '1 2 0\n'
FAKE

  cat >"$bin/bao" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[[ "$BAO_ADDR" == https://openbao.example.invalid ]] || exit 92
case "$1 $2" in
  'kv get')
    printf 'bao-get\n' >>"$MOCK_STATE/events"
    if [[ -f "$MOCK_STATE/published.json" ]]; then
      jq -n --slurpfile data "$MOCK_STATE/published.json" '{data: {metadata: {version: 4}, data: $data[0]}}'
      exit 0
    fi
    case "$MOCK_MODE" in
      rotate|probe_failure|cas_failure|create_existing)
        printf '{"data":{"metadata":{"version":3},"data":{"password":"old","userEmail":"x@y.z"}}}\n' ;;
      malformed) printf '{"data":{"metadata":{"version":3},"data":{"apiKey":"cw_x"}}}\n' ;;
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
url="${*: -1}" jar="" body=""
while (($# > 0)); do
  case "$1" in -c) jar="$2"; shift 2 ;; --data) body="$2"; shift 2 ;; *) shift ;; esac
done
printf 'curl %s\n' "${url##*/api/auth/}" >>"$MOCK_STATE/events"
case "$url" in
  */api/auth/sign-in)
    jq -e --slurpfile doc "$MOCK_STATE/published.json" \
      '.password == $doc[0].password and .email == $doc[0].userEmail' "${body#@}" >/dev/null || exit 94
    if [[ "$MOCK_MODE" == probe_failure ]]; then printf '401'; exit 0; fi
    printf '#HttpOnly_codewire-dev.sh\tFALSE\t/\tTRUE\t0\tcodewire.session_token\tprobe\n' >"$jar"
    printf '200' ;;
  */api/auth/sign-out) : ;;
  *) exit 95 ;;
esac
FAKE

  cat >"$bin/argon2" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
[[ "\$*" == *' -id -t 3 -m 16 -p 2 -l 32 -e' ]] || exit 96
password="\$(cat)"
[[ \${#password} == 43 ]] || exit 97
printf '%s\n' '$HASH'
FAKE
  chmod 0755 "$bin"/*
}

# run_case NAME MODE EXPECT [ARGS...]: run the provisioner in MODE and check
# that it passes or fails as EXPECT says. Leaves the case folder in $CASE.
run_case() {
  local name="$1" mode="$2" expect="$3"; shift 3
  CASE="$TEST_TMP/$name"
  mkdir -p "$CASE/state" "$CASE/kube" "$CASE/tmp"
  : >"$CASE/state/events"
  make_fake_tools "$CASE/bin"
  local status=0
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE" TMPDIR="$CASE/tmp" MOCK_STATE="$CASE/state" \
    MOCK_MODE="$mode" INFRA_KUBECONFIG_DIR="${KUBE_DIR-$CASE/kube}" KUBECONFIG="$CASE/kube/scoped.yaml" \
    bash "$PROVISIONER" "$@" >"$CASE/out" 2>&1 || status=$?
  if [[ "$expect" == pass ]]; then
    [[ "$status" == 0 ]] || { cat "$CASE/out" >&2; fail "$name: expected success, exit $status"; }
  else
    [[ "$status" != 0 ]] || { cat "$CASE/out" >&2; fail "$name: expected failure"; }
  fi
  if [[ -f "$CASE/state/published.json" ]]; then
    local password
    password="$(jq -r .password "$CASE/state/published.json")"
    ! grep -qF -- "$password" "$CASE/out" || fail "$name: the password reached output"
    ! grep -qF -- "$password" "$CASE/state/psql.sql" 2>/dev/null || fail "$name: the password reached the database"
  fi
  [[ -z "$(find "$CASE/tmp" -mindepth 1 -print -quit)" ]] || fail "$name: left temporary files"
}

expect_events() {
  local want="$1"
  [[ "$(cat "$CASE/state/events")" == "$want" ]] ||
    fail "$(basename "$CASE"): events were [$(tr '\n' ',' <"$CASE/state/events")], want [$(tr '\n' ',' <<<"$want")]"
}
expect_output() {
  grep -qF -- "$1" "$CASE/out" || { cat "$CASE/out" >&2; fail "$(basename "$CASE"): output lacks: $1"; }
}

run_case create absent pass --create-document
expect_events $'bao-get\ndb\nbao-put -cas=0\nbao-get\ncurl sign-in\ncurl sign-out'
expect_output 'PASS canonical_store=openbao path=apps/codewire/dev/ci-invitee sign_in_probe=true'
expect_output 'removed memberships=2 api_keys=0'
jq -e --arg email "$EMAIL" 'keys == ["password", "userEmail"] and .userEmail == $email and
  (.password | test("^[A-Za-z0-9_-]{43}$"))' "$CASE/state/published.json" >/dev/null ||
  fail 'create: the published document has the wrong shape'
grep -qF "\\set hash '$HASH'" "$CASE/state/psql.sql" || fail 'create: the hash did not reach the database'
grep -qF "email=$EMAIL" "$CASE/state/psql.args" || fail 'create: the email was not passed to psql'
for statement in 'DELETE FROM org_members' 'DELETE FROM api_keys' 'DELETE FROM sessions' \
  "provider_id = 'credential'" 'email_verified = true, enabled = true'; do
  grep -qF "$statement" "$CASE/state/psql.sql" || fail "create: the SQL lacks: $statement"
done

run_case rotate rotate pass
expect_events $'bao-get\ndb\nbao-put -cas=3\nbao-get\ncurl sign-in\ncurl sign-out'

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

run_case db_failure db_failure fail --create-document
expect_events $'bao-get\ndb'
expect_output 'nothing was published'

run_case cas_failure cas_failure fail
expect_events $'bao-get\ndb\nbao-put -cas=3'
expect_output 'the OpenBao CAS write failed'

run_case probe_failure probe_failure fail
expect_events $'bao-get\ndb\nbao-put -cas=3\nbao-get\ncurl sign-in'
expect_output 'answered HTTP 401'

KUBE_DIR="" run_case no_kube_access absent fail --create-document
expect_events ''
expect_output 'scoped Infra kube-access wrapper'

printf 'dev invitee provisioning tests: PASS\n'
