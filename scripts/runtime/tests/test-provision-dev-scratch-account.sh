#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROVISIONER="$ROOT/scripts/runtime/dev/provision-dev-scratch-account.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-scratch-account-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly USER_ID="0123456789abcdef0123456789abcdef"
# shellcheck disable=SC2016 # A literal PHC string, not an expansion.
readonly HASH='$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g'

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'dev scratch account tests: %s\n' "$*" >&2; exit 1; }

make_fake_tools() {
  local bin="$1"
  mkdir -p "$bin"

  cat >"$bin/kubectl" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
if [[ "\$*" == '-n dev get pods -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o name' ]]; then
  printf 'pod/codewire-db-2\n'; exit 0
fi
[[ "\$1 \$2 \$3 \$4 \$5" == "-n dev exec -i codewire-db-2" ]] || exit 91
cat >>"\$MOCK_STATE/psql.sql"
printf '%s\n' "\$*" >>"\$MOCK_STATE/psql.args"
case "\$MOCK_MODE" in
  db_failure) exit 1 ;;
  exists) : ;;
  *) printf '%s\n' '$USER_ID' ;;
esac
FAKE

  cat >"$bin/argon2" <<FAKE
#!/usr/bin/env bash
set -euo pipefail
[[ "\$*" == *' -id -t 3 -m 16 -p 2 -l 32 -e' ]] || exit 96
password="\$(cat)"
[[ \${#password} == 43 ]] || exit 97
printf '%s\n' "\$password" >"\$MOCK_STATE/password"
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
  make_fake_tools "$CASE/bin"
  local status=0
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE" TMPDIR="$CASE/tmp" MOCK_STATE="$CASE/state" \
    MOCK_MODE="$mode" INFRA_KUBECONFIG_DIR="${KUBE_DIR-$CASE/kube}" KUBECONFIG="$CASE/kube/scoped.yaml" \
    bash "$PROVISIONER" "$@" >"$CASE/out" 2>"$CASE/err" || status=$?
  if [[ "$expect" == pass ]]; then
    [[ "$status" == 0 ]] || { cat "$CASE/err" >&2; fail "$name: expected success, exit $status"; }
  else
    [[ "$status" != 0 ]] || { cat "$CASE/err" >&2; fail "$name: expected failure"; }
  fi
  if [[ -f "$CASE/state/password" ]]; then
    local password
    password="$(cat "$CASE/state/password")"
    ! grep -qF -- "$password" "$CASE/out" "$CASE/err" || fail "$name: the password reached output"
    ! grep -qF -- "$password" "$CASE/state/psql.sql" 2>/dev/null || fail "$name: the password reached the database"
  fi
  [[ -z "$(find "$CASE/tmp" -mindepth 1 -print -quit)" ]] || fail "$name: left temporary files"
}

expect_err() {
  grep -qF -- "$1" "$CASE/err" || { cat "$CASE/err" >&2; fail "$(basename "$CASE"): output lacks: $1"; }
}
expect_arg() {
  grep -qF -- "$1" "$CASE/state/psql.args" || fail "$(basename "$CASE"): psql was not passed: $1"
}

run_case unverified ok pass --unverified --label purge-4541
[[ "$(cat "$CASE/out")" == "$USER_ID" ]] || fail 'unverified: stdout is not exactly the account id'
expect_err "PASS user_id=$USER_ID email=success+cw-scratch-purge-4541@simulator.amazonses.com email_verified=false"
expect_arg 'email=success+cw-scratch-purge-4541@simulator.amazonses.com'
expect_arg 'verified=false'
expect_arg 'name=Scratch purge-4541'
grep -qF "\\set hash '$HASH'" "$CASE/state/psql.sql" || fail 'unverified: the hash did not reach the database'
for statement in 'ON CONFLICT (email) DO NOTHING' "'credential'" ":'verified'::boolean"; do
  grep -qF "$statement" "$CASE/state/psql.sql" || fail "unverified: the SQL lacks: $statement"
done
for statement in 'UPDATE' 'DELETE' 'org_members' 'api_keys'; do
  ! grep -qF "$statement" "$CASE/state/psql.sql" || fail "unverified: the SQL must not touch: $statement"
done

run_case verified ok pass --verified --label admin-delete-4541
expect_arg 'verified=true'
expect_err 'email_verified=true'

run_case exists exists fail --verified --label admin-delete-4541
expect_err 'already exists; nothing was written'

run_case db_failure db_failure fail --unverified --label purge-4541
expect_err 'the database write failed'

run_case no_mode ok fail --label purge-4541
expect_err 'pass --unverified or --verified'
[[ ! -f "$CASE/state/psql.sql" ]] || fail 'no_mode: wrote to the database'

run_case both_modes ok fail --unverified --verified --label purge-4541
expect_err 'pass one of --unverified and --verified'

run_case bad_label ok fail --unverified --label 'Purge 4541'
expect_err '--label must be 1-32 of a-z, 0-9 and -'
[[ ! -f "$CASE/state/psql.sql" ]] || fail 'bad_label: wrote to the database'

KUBE_DIR="" run_case no_kube_access ok fail --unverified --label purge-4541
expect_err 'scoped Infra kube-access wrapper'
[[ ! -f "$CASE/state/psql.sql" ]] || fail 'no_kube_access: wrote to the database'

printf 'dev scratch account tests: PASS\n'
