#!/usr/bin/env bash
set -euo pipefail

AUTH_ONLY=false
case "$#:${1:-}" in
  0:) ;;
  1:--auth-only) AUTH_ONLY=true ;;
  1:--help|1:-h)
    echo 'usage: kind-seed-contract-fixture.sh [--auth-only]'
    exit 0
    ;;
  *)
    echo 'usage: kind-seed-contract-fixture.sh [--auth-only]' >&2
    exit 2
    ;;
esac

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
  if [ "$AUTH_ONLY" = true ]; then
    echo '[kind-seed-contract-fixture] auth-only requires the existing synthetic fixture' >&2
    exit 1
  fi
  echo "[kind-seed-contract-fixture] loading billing contract fixture"
  psql_exec -v ON_ERROR_STOP=1 < "$SEED_FILE"
else
  echo "[kind-seed-contract-fixture] billing contract fixture already present"
fi

psql_exec -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DO $fixture$
DECLARE
    affected bigint;
    stale_expiry timestamp;
BEGIN
    -- Refresh only the checked-in synthetic identities. Disabled users and
    -- clients require fresh product login; never restore their capabilities.
    PERFORM 1 FROM users
    WHERE id IN ('usr_contract_admin', 'usr_contract_user') AND enabled
    FOR SHARE;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 2 THEN
        RAISE EXCEPTION 'expected two enabled synthetic contract users';
    END IF;
    PERFORM 1 FROM oidc_clients
    WHERE id = 'oidc_kind_connect' AND NOT disabled
    FOR SHARE;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION 'expected the active synthetic OIDC client';
    END IF;
    SELECT expires_at INTO stale_expiry FROM sessions
    WHERE id = 'ses_contract_stale' AND user_id = 'usr_contract_user'
      AND token_hash = encode(digest('contract-stale-session-token', 'sha256'), 'hex')
      AND expires_at < NOW()
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'expected the unchanged expired negative-auth fixture';
    END IF;

    UPDATE sessions SET expires_at = NOW() + INTERVAL '4 hours'
    WHERE (id, user_id, token_hash) IN (
        ('ses_contract_admin', 'usr_contract_admin',
         encode(digest('contract-admin-session-token', 'sha256'), 'hex')),
        ('ses_contract_user', 'usr_contract_user',
         encode(digest('contract-user-session-token', 'sha256'), 'hex'))
    );
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 2 THEN
        RAISE EXCEPTION 'expected exactly two synthetic session refreshes';
    END IF;
    UPDATE oidc_access_tokens SET expires_at = NOW() + INTERVAL '4 hours'
    WHERE token_hash = encode(digest('at_kind_connect_oidc_codewire_api', 'sha256'), 'hex')
      AND client_id = 'oidc_kind_connect' AND user_id = 'usr_contract_user'
      AND scopes = ARRAY['openid', 'codewire.api']::text[];
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION 'expected exactly one synthetic OIDC refresh';
    END IF;
    IF (SELECT expires_at FROM sessions WHERE id = 'ses_contract_stale')
        IS DISTINCT FROM stale_expiry THEN
        RAISE EXCEPTION 'expired negative-auth fixture changed';
    END IF;
END
$fixture$;
COMMIT;
SQL

if [ "$AUTH_ONLY" = true ]; then
  echo '[kind-seed-contract-fixture] refreshed synthetic auth only; environment state preserved'
  exit 0
fi

psql_exec -v ON_ERROR_STOP=1 <<'SQL'
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
