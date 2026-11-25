#!/usr/bin/env bash
# grant-dev-walk-org-credit.sh against a fake kubectl: one transaction that
# locks only the invitee's walk organization, turns top-up off, sets a quota of
# one default-shape Sandbox and tops the credit up to exactly EUR 2, never the
# unlimited card; it fails unless the state it reads back holds, and refuses to
# run outside scoped kube-access, outside Dev, without exactly one database
# primary, or for a slug that doesn't name a walk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/runtime/dev/grant-dev-walk-org-credit.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-walk-org-credit-tests.XXXXXX")"
cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'dev walk org credit tests: %s\n' "$*" >&2; exit 1; }

readonly ORG_ID="94e5c3245f5546fba77baa6eca13ca6c"

mkdir -p "$TEST_TMP/bin" "$TEST_TMP/kube"
cat >"$TEST_TMP/bin/kubectl" <<'FAKE_KUBECTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_STATE/calls"
if [[ " $* " == *" get pods "* ]]; then
  case "$MOCK_MODE" in
    no_primary) ;;
    two_primaries) printf 'pod/codewire-db-1\npod/codewire-db-3\n' ;;
    *) printf 'pod/codewire-db-3\n' ;;
  esac
  exit 0
fi
[[ " $* " == *" exec -i codewire-db-3 -c postgres -- psql "* ]] || exit 91
cat >>"$MOCK_STATE/psql.sql"
# The state line: id, flags, quota, balance, members.
case "$MOCK_MODE" in
  missing) ;;
  psql_error) exit 3 ;;
  top_up_on) printf 'state|%s|0|1|2000000000|2\n' "$MOCK_ORG_ID" ;;
  wide_quota) printf 'state|%s|1|0|2000000000|2\n' "$MOCK_ORG_ID" ;;
  over_credit) printf 'state|%s|1|1|3000000000|2\n' "$MOCK_ORG_ID" ;;
  bad_id) printf 'state|not-an-id|1|1|2000000000|2\n' ;;
  *) printf 'state|%s|1|1|2000000000|2\n' "$MOCK_ORG_ID" ;;
esac
FAKE_KUBECTL
chmod +x "$TEST_TMP/bin/kubectl"

run_case() {
  local name="$1" mode="$2"; shift 2
  local state="$TEST_TMP/$name"
  mkdir -p "$state"
  set +e
  PATH="$TEST_TMP/bin:$PATH" MOCK_STATE="$state" MOCK_MODE="$mode" MOCK_ORG_ID="$ORG_ID" \
    INFRA_KUBECONFIG_DIR="$TEST_TMP/kube" KUBECONFIG="$TEST_TMP/kube/scoped.yaml" \
    "$SCRIPT" "$@" >"$state/stdout" 2>"$state/stderr"
  echo "$?" >"$state/status"
  set -e
}
status_of() { cat "$TEST_TMP/$1/status"; }
stderr_has() { grep -F -- "$2" "$TEST_TMP/$1/stderr" >/dev/null || fail "$1: stderr lacks: $2"; }
expect_refused() { # NAME MESSAGE: failed, said why, and never reached psql
  [[ "$(status_of "$1")" != 0 ]] || fail "$1: should fail"
  stderr_has "$1" "$2"
  [[ ! -e "$TEST_TMP/$1/psql.sql" ]] || fail "$1: reached psql"
}

# The bound, in one transaction that locks only the invitee's walk organization
# and narrows it, then reads it back.
run_case granted granted --org-slug w3586-del-1
[[ "$(status_of granted)" == 0 ]] || fail "granted: exit $(status_of granted): $(cat "$TEST_TMP/granted/stderr")"
stderr_has granted "PASS org=w3586-del-1 id=$ORG_ID rate_card=regular auto_top_up=off quota=1x2000m8192MB credit_eur=2 members=2"
sql="$(cat "$TEST_TMP/granted/psql.sql")"
for needle in "BEGIN;" "COMMIT;" "FOR UPDATE OF o" "\\if :found" \
  "lower(owner.email) = lower(:'owner_email')" "m.role = 'owner'" \
  "o.rate_card = 'regular' AND o.deletion_state = 'active' AND o.suspended_at IS NULL" \
  "NOT (lower(u.email) = lower(:'member_email') AND m.role = 'member')" \
  "SET auto_top_up_enabled = false" "VALUES (:'org_id', 1, 1, :cpu, :memory)" \
  "SELECT :'org_id', 'grant', :credit - balance" "WHERE balance < :credit"; do
  grep -F -- "$needle" <<<"$sql" >/dev/null || fail "granted: SQL lacks: $needle"
done
for forbidden in unlimited billing_exempt "DELETE FROM" "SET rate_card"; do
  ! grep -F -- "$forbidden" <<<"$sql" >/dev/null || fail "granted: SQL names $forbidden"
done
calls="$(cat "$TEST_TMP/granted/calls")"
for needle in "org_slug=w3586-del-1" "owner_email=success+codewire-dev-invitee@simulator.amazonses.com" \
  "member_email=success+codewire-dev-personal-walk@simulator.amazonses.com" \
  "credit=2000000000" "cpu=2000" "memory=8192"; do
  grep -F -- "$needle" <<<"$calls" >/dev/null || fail "granted: psql was not given $needle"
done

# No such walk organization: nothing changed, and it says what it looked for.
run_case missing missing --org-slug w3586-del-9
[[ "$(status_of missing)" != 0 ]] || fail 'missing: should fail'
stderr_has missing 'no walk organization w3586-del-9 that the invitee created and owns'
run_case psql_error psql_error --org-slug w3586-del-1
[[ "$(status_of psql_error)" != 0 ]] || fail 'psql_error: should fail'
stderr_has psql_error 'the database write failed; nothing was changed'

# A state that doesn't hold fails the run, so the walk never starts on it.
run_case top_up_on top_up_on --org-slug w3586-del-1
[[ "$(status_of top_up_on)" != 0 ]] || fail 'top_up_on: should fail'
stderr_has top_up_on 'is not regular, active and without top-up'
run_case wide_quota wide_quota --org-slug w3586-del-1
[[ "$(status_of wide_quota)" != 0 ]] || fail 'wide_quota: should fail'
stderr_has wide_quota 'quota is not one Sandbox of the default shape'
run_case over_credit over_credit --org-slug w3586-del-1
[[ "$(status_of over_credit)" != 0 ]] || fail 'over_credit: should fail'
stderr_has over_credit 'credit is 3000000000 nano-euro, not EUR 2; do not walk with it'
run_case bad_id bad_id --org-slug w3586-del-1
[[ "$(status_of bad_id)" != 0 ]] || fail 'bad_id: should fail'
stderr_has bad_id 'unexpected state line'

# The slug names a walk; checked before anything runs.
for slug in codewire-dev-smoke w35-del w3586 W3586-del-1 'w3586-del 1' \
  w3586-abcdefghijklmnopqrstuvwxyz0123456789; do
  run_case "slug_${slug// /_}" granted --org-slug "$slug"
  expect_refused "slug_${slug// /_}" 'the organization slug must name its walk'
done
run_case no_slug granted
expect_refused no_slug 'the organization slug must name its walk'

# Exactly one primary, or nothing runs.
for mode in no_primary two_primaries; do
  run_case "$mode" "$mode" --org-slug w3586-del-1
  expect_refused "$mode" 'expected exactly one codewire-db primary'
done

# Dev only, and only inside scoped kube-access.
run_case prod_namespace granted --org-slug w3586-del-1 --namespace prod
expect_refused prod_namespace 'this script changes the Dev database only'
mkdir -p "$TEST_TMP/unscoped"
set +e
PATH="$TEST_TMP/bin:$PATH" MOCK_STATE="$TEST_TMP/unscoped" MOCK_MODE=granted \
  INFRA_KUBECONFIG_DIR="" KUBECONFIG="" "$SCRIPT" --org-slug w3586-del-1 \
  >/dev/null 2>"$TEST_TMP/unscoped/stderr"
unscoped=$?
set -e
[[ "$unscoped" != 0 ]] || fail 'unscoped: should fail'
grep -F 'run through the scoped Infra kube-access wrapper' "$TEST_TMP/unscoped/stderr" >/dev/null ||
  fail 'unscoped: wrong refusal'
[[ ! -e "$TEST_TMP/unscoped/calls" ]] || fail 'unscoped: reached kubectl'

printf 'dev walk org credit tests: ok\n'
