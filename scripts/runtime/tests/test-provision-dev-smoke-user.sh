#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-smoke-provision-tests.XXXXXX")"
trap 'rm -rf "$TEST_TMP"' EXIT

mkdir -p "$TEST_TMP/bin" "$TEST_TMP/home"
: >"$TEST_TMP/kubeconfig"

cat >"$TEST_TMP/bin/kubectl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_STATE/kubectl.args"
sql="$(sed -n '1,$p')"
printf '%s\n-- statement boundary --\n' "$sql" >>"$MOCK_STATE/psql.sql"
if grep -F 'SELECT raw_key.value' <<<"$sql" >/dev/null; then
  printf 'cw_%064d\n' 0
else
  printf 'codewire-dev-smoke@codewire-dev.sh|codewire-dev-smoke|unlimited|active|t|1|1|1|00000000\n'
fi
SH

cat >"$TEST_TMP/bin/infisical" <<'SH'
#!/usr/bin/env bash
exit 0
SH

chmod +x "$TEST_TMP/bin/kubectl" "$TEST_TMP/bin/infisical"

MOCK_STATE="$TEST_TMP" \
PATH="$TEST_TMP/bin:$PATH" \
HOME="$TEST_TMP/home" \
KUBECONFIG="$TEST_TMP/kubeconfig" \
  "$ROOT/scripts/runtime/dev/provision-dev-smoke-user.sh" \
    --skip-infisical >"$TEST_TMP/stdout" 2>"$TEST_TMP/stderr"

grep -F "INSERT INTO billing_catalog_plans" "$TEST_TMP/psql.sql" >/dev/null
grep -F "'confidential_sandbox'" "$TEST_TMP/psql.sql" >/dev/null
grep -F "max_concurrent_ws = EXCLUDED.max_concurrent_ws" "$TEST_TMP/psql.sql" >/dev/null
grep -F "billing_plan = EXCLUDED.billing_plan" "$TEST_TMP/psql.sql" >/dev/null
grep -F "billing_status = EXCLUDED.billing_status" "$TEST_TMP/psql.sql" >/dev/null
grep -F "billing_exempt = EXCLUDED.billing_exempt" "$TEST_TMP/psql.sql" >/dev/null

[[ "$(grep -c -- '--set plan_key=unlimited' "$TEST_TMP/kubectl.args")" == "2" ]]
grep -F "provisioning complete" "$TEST_TMP/stderr" >/dev/null
if grep -F "cw_" "$TEST_TMP/stdout" "$TEST_TMP/stderr" >/dev/null; then
  echo "provisioning output exposed the API key" >&2
  exit 1
fi

echo "dev smoke provisioning tests passed"
