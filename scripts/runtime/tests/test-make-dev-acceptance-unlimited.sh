#!/usr/bin/env bash
# make-dev-acceptance-unlimited.sh against a fake kubectl: it changes and
# audits only the named organization owned by the expected account, reads the
# result back, is a no-op when already unlimited, and refuses to run outside
# scoped kube-access, outside Dev, or without exactly one database primary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/runtime/dev/make-dev-acceptance-unlimited.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-acceptance-unlimited-tests.XXXXXX")"
cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'dev acceptance unlimited tests: %s\n' "$*" >&2; exit 1; }

readonly ORG_ID="cf4bc133bbc34f65a88b6f7d23bfc6cc"

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
sql="$(cat)"
printf '%s\n-- statement boundary --\n' "$sql" >>"$MOCK_STATE/psql.sql"
if grep -F 'dev.acceptance.rate_card' <<<"$sql" >/dev/null; then
  case "$MOCK_MODE" in
    missing) ;;
    already) printf '%s|unlimited|0\n' "$MOCK_ORG_ID" ;;
    *) printf '%s|regular|1\n' "$MOCK_ORG_ID" ;;
  esac
elif grep -F 'SELECT rate_card' <<<"$sql" >/dev/null; then
  # PostgreSQL renders a boolean cast to text as true or false.
  if [[ "$MOCK_MODE" == readback_regular ]]; then printf 'regular|false\n'; else printf 'unlimited|true\n'; fi
else
  exit 92
fi
FAKE_KUBECTL
chmod +x "$TEST_TMP/bin/kubectl"

run_case() {
  local mode="$1"; shift
  local state="$TEST_TMP/$mode"
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

# The organization changes once, through one transaction that names the slug,
# the owner and the audit action, and reads back as unlimited.
run_case changed
[[ "$(status_of changed)" == 0 ]] || fail "changed: exit $(status_of changed): $(cat "$TEST_TMP/changed/stderr")"
stderr_has changed "organization $ORG_ID: regular -> unlimited, billing-exempt (audited)"
sql="$(cat "$TEST_TMP/changed/psql.sql")"
for needle in "BEGIN;" "COMMIT;" "FOR UPDATE OF o" "lower(u.email) = lower(:'owner_email')" \
  "m.role = 'owner'" "SET rate_card = 'unlimited', billing_exempt = true" \
  "'dev.acceptance.rate_card'" "o.rate_card <> 'unlimited' OR NOT o.billing_exempt"; do
  grep -F -- "$needle" <<<"$sql" >/dev/null || fail "changed: SQL lacks: $needle"
done
grep -F -- "billing_exempt::text" <<<"$sql" >/dev/null ||
  fail 'changed: the read-back must cast the boolean to text explicitly'
grep -F -- "org_slug=codewire-dev-acceptance" "$TEST_TMP/changed/calls" >/dev/null ||
  fail 'changed: the default slug was not passed'
grep -F -- "owner_email=hello@codewire.sh" "$TEST_TMP/changed/calls" >/dev/null ||
  fail 'changed: the default owner was not passed'

# Repeating it changes and records nothing.
run_case already
[[ "$(status_of already)" == 0 ]] || fail 'already: should succeed'
stderr_has already 'was already unlimited; nothing changed'

# No organization by that slug and owner: an error, nothing read back.
run_case missing --org-slug other-org --owner-email someone@example.test
[[ "$(status_of missing)" != 0 ]] || fail 'missing: should fail'
stderr_has missing 'no organization other-org is owned by someone@example.test; nothing changed'
[[ "$(grep -c 'statement boundary' "$TEST_TMP/missing/psql.sql")" == 1 ]] ||
  fail 'missing: read back after nothing changed'

# A read-back that is not unlimited fails.
run_case readback_regular
[[ "$(status_of readback_regular)" != 0 ]] || fail 'readback_regular: should fail'
stderr_has readback_regular 'reads back as regular|false, not unlimited'

# Exactly one primary, or nothing runs.
for mode in no_primary two_primaries; do
  run_case "$mode"
  [[ "$(status_of "$mode")" != 0 ]] || fail "$mode: should fail"
  stderr_has "$mode" 'expected exactly one codewire-db primary'
  [[ ! -e "$TEST_TMP/$mode/psql.sql" ]] || fail "$mode: reached psql"
done

# Dev only, and only inside scoped kube-access.
run_case prod_namespace --namespace prod
[[ "$(status_of prod_namespace)" != 0 ]] || fail 'prod_namespace: should fail'
stderr_has prod_namespace 'this script changes the Dev database only'
mkdir -p "$TEST_TMP/unscoped"
set +e
PATH="$TEST_TMP/bin:$PATH" MOCK_STATE="$TEST_TMP/unscoped" MOCK_MODE=changed \
  INFRA_KUBECONFIG_DIR="" KUBECONFIG="" "$SCRIPT" >/dev/null 2>"$TEST_TMP/unscoped/stderr"
unscoped=$?
set -e
[[ "$unscoped" != 0 ]] || fail 'unscoped: should fail'
grep -F 'run through the scoped Infra kube-access wrapper' "$TEST_TMP/unscoped/stderr" >/dev/null ||
  fail 'unscoped: wrong refusal'
[[ ! -e "$TEST_TMP/unscoped/calls" ]] || fail 'unscoped: reached kubectl'

# Shapes are checked before anything runs.
run_case bad_slug --org-slug 'Bad Slug'
[[ "$(status_of bad_slug)" != 0 ]] || fail 'bad_slug: should fail'
stderr_has bad_slug 'organization slug has an invalid shape'

printf 'dev acceptance unlimited tests: ok\n'
