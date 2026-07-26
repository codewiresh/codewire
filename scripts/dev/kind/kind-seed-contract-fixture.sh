#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"
NAMESPACE="${NAMESPACE:-default}"
SEED_FILE="$ROOT_DIR/tests/fixtures/billing/seed.sql"

psql_exec() {
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" exec -i deploy/postgres -- \
    psql -U codewire -d codewire "$@"
}

exists="$(psql_exec -tAc "SELECT EXISTS (SELECT 1 FROM organizations WHERE id = 'org_contract_1')" | tr -d '[:space:]')"
if [ "$exists" != "t" ]; then
  echo "[kind-seed-contract-fixture] loading billing contract fixture"
  psql_exec -v ON_ERROR_STOP=1 < "$SEED_FILE"
else
  echo "[kind-seed-contract-fixture] billing contract fixture already present"
fi

psql_exec -v ON_ERROR_STOP=1 <<'SQL'
UPDATE sessions
SET expires_at = NOW() + INTERVAL '4 hours'
WHERE token_hash IN (
    encode(digest('contract-admin-session-token', 'sha256'), 'hex'),
    encode(digest('contract-user-session-token', 'sha256'), 'hex')
);

UPDATE environments
SET state = 'running',
    desired_state = 'started',
    error_reason = NULL,
    shutdown_at = NULL,
    destroyed_at = NULL
WHERE id IN ('env_contract_1', 'env_contract_journal');

UPDATE environments
SET state = 'destroyed',
    desired_state = 'started',
    error_reason = NULL,
    shutdown_at = NULL,
    destroyed_at = COALESCE(destroyed_at, NOW())
WHERE id = 'env_contract_2';
SQL
echo "[kind-seed-contract-fixture] refreshed contract session and environment fixture state"
