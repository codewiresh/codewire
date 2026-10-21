#!/usr/bin/env bash
set -euo pipefail

readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"

TARGET=""
ALLOW_PROD_MUTATION=0
TMPDIR_PROVISION=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/apikey/provision-apikey-smoke-user.sh --target dev|prod|prod-evidence-secondary [--allow-prod-mutation]

Creates or repairs the fixed ApiKeyService lifecycle-smoke identity, rotates
its bootstrap API key, and stores only the raw replacement key in its
canonical OpenBao document.

Production targets require both the exact target and --allow-prod-mutation.
The cluster comes from CODEWIRE_DEV_CLUSTER or CODEWIRE_PROD_CLUSTER (set in
~/.config/codewire/env); it selects the Infra kubeconfig-CLUSTER.yaml and its
admin@CLUSTER context.

Safety:
  - target identity, namespace, and secret destinations are fixed
  - no raw key is written to stdout, argv, or logs
  - never run with shell tracing enabled or pipe output through tee
USAGE
}

log() {
  printf '[apikey-smoke-provision] %s\n' "$*" >&2
}

die() {
  printf '[apikey-smoke-provision] ERROR: %s\n' "$*" >&2
  exit 1
}

secure_remove() {
  [[ "$#" -gt 0 ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$@" 2>/dev/null && return 0
  fi
  rm -f -- "$@" 2>/dev/null
}

cleanup() {
  local status=0
  if [[ -n "$TMPDIR_PROVISION" && -d "$TMPDIR_PROVISION" ]]; then
    while IFS= read -r -d '' file; do secure_remove "$file" || status=1; done \
      < <(find "$TMPDIR_PROVISION" -type f -print0)
    rmdir "$TMPDIR_PROVISION" 2>/dev/null || status=1
    [[ ! -e "$TMPDIR_PROVISION" ]] || status=1
  fi
  TMPDIR_PROVISION=""
  return "$status"
}
trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while (($# > 0)); do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || die "--target requires dev, prod, or prod-evidence-secondary"
      TARGET="$2"
      shift 2
      ;;
    --allow-prod-mutation)
      ALLOW_PROD_MUTATION=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

case "$TARGET" in
  dev)
    CLUSTER="${CODEWIRE_DEV_CLUSTER:?set CODEWIRE_DEV_CLUSTER to the Dev cluster name}"
    KUBE_NAMESPACE="dev"
    FIXTURE_USER_ID="f23d1c4a5ed665e62094d9d106c0d13b"
    FIXTURE_USER_EMAIL="connect-apikey-smoke-dev@codewire-dev.sh"
    FIXTURE_USER_NAME="Codewire ApiKey Dev Smoke"
    FIXTURE_ORG_ID="9bef2654d4ac6824ead235fdb9bb8598"
    FIXTURE_ORG_SLUG="connect-apikey-smoke-dev"
    FIXTURE_ORG_NAME="Codewire ApiKey Dev Smoke"
    FIXTURE_MEMBER_ID="apikey-smoke-dev-owner"
    FIXTURE_KEY_NAME="connect-apikey-smoke-dev-bootstrap"
    OPENBAO_PATH="apps/codewire/dev/apikey-smoke"
    ;;
  prod)
    [[ "$ALLOW_PROD_MUTATION" == "1" ]] || \
      die "production provisioning requires --allow-prod-mutation"
    CLUSTER="${CODEWIRE_PROD_CLUSTER:?set CODEWIRE_PROD_CLUSTER to the Production cluster name}"
    KUBE_NAMESPACE="prod"
    FIXTURE_USER_ID="627a3c7cad1f50a7b44c00de1e054df9"
    FIXTURE_USER_EMAIL="connect-apikey-smoke-prod@codewire.sh"
    FIXTURE_USER_NAME="Codewire ApiKey Prod Smoke"
    FIXTURE_ORG_ID="3289cbf3e0ca05c5ef2ac7cb696d5318"
    FIXTURE_ORG_SLUG="connect-apikey-smoke-prod"
    FIXTURE_ORG_NAME="Codewire ApiKey Prod Smoke"
    FIXTURE_MEMBER_ID="apikey-smoke-prod-owner"
    FIXTURE_KEY_NAME="connect-apikey-smoke-prod-bootstrap"
    OPENBAO_PATH="apps/codewire/prod/apikey-smoke"
    ;;
  prod-evidence-secondary)
    [[ "$ALLOW_PROD_MUTATION" == "1" ]] || \
      die "production provisioning requires --allow-prod-mutation"
    CLUSTER="${CODEWIRE_PROD_CLUSTER:?set CODEWIRE_PROD_CLUSTER to the Production cluster name}"
    KUBE_NAMESPACE="prod"
    FIXTURE_USER_ID="258099727105fa93538769d4e3498b24"
    FIXTURE_USER_EMAIL="connect-apikey-evidence-prod-secondary@codewire.sh"
    FIXTURE_USER_NAME="Codewire ApiKey Prod Evidence Secondary"
    FIXTURE_ORG_ID="63742e203ad7e3c65f25af8e221ccf21"
    FIXTURE_ORG_SLUG="connect-apikey-evidence-prod-secondary"
    FIXTURE_ORG_NAME="Codewire ApiKey Prod Evidence Secondary"
    FIXTURE_MEMBER_ID="apikey-evidence-prod-secondary-owner"
    FIXTURE_KEY_NAME="connect-apikey-evidence-prod-secondary-bootstrap"
    OPENBAO_PATH="apps/codewire/prod/apikey-evidence-secondary"
    ;;
  *)
    die "--target must be dev, prod, or prod-evidence-secondary"
    ;;
esac
[[ "$CLUSTER" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || die "cluster name is invalid for target=$TARGET"
KUBECONFIG_FIXED="$HOME/src/infra/kubeconfig-$CLUSTER.yaml"
KUBE_CONTEXT="admin@$CLUSTER"

for command in awk bao find jq kubectl mktemp rm rmdir sha256sum; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ -f "$KUBECONFIG_FIXED" ]] || die "fixed kubeconfig is missing for target=$TARGET"
[[ "${BAO_ADDR:-$OPENBAO_ADDR}" == "$OPENBAO_ADDR" ]] ||
  die 'BAO_ADDR must be the canonical OpenBao Tailnet endpoint'
ulimit -c 0 || die 'cannot disable core dumps'

# OpenBao credentials belong only to the one OpenBao command below. Prevent a
# human session token or client certificate from reaching kubectl, psql, or a
# database container through the process environment.
declare -a OPENBAO_ENV_UNSETS=()
for name in "${!BAO_@}"; do
  OPENBAO_ENV_UNSETS+=( -u "$name" )
done

run_without_openbao() {
  env "${OPENBAO_ENV_UNSETS[@]}" "$@"
}

export KUBECONFIG="$KUBECONFIG_FIXED"
POSTGRES_POD="$(
  run_without_openbao kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" \
    get cluster.postgresql.cnpg.io codewire-db \
    -o jsonpath='{.status.currentPrimary}'
)"
[[ "$POSTGRES_POD" =~ ^codewire-db-[0-9]+$ ]] || \
  die "database operator did not report a valid current primary"

TMPDIR_PROVISION="$(mktemp -d "${TMPDIR:-/tmp}/codewire-apikey-smoke-provision.XXXXXX")"
chmod 0700 "$TMPDIR_PROVISION"
KEY_FILE="$TMPDIR_PROVISION/bootstrap-key"
OPENBAO_FILE="$TMPDIR_PROVISION/openbao.json"
OPENBAO_STDOUT="$TMPDIR_PROVISION/openbao.stdout"
OPENBAO_STDERR="$TMPDIR_PROVISION/openbao.stderr"
META_FILE="$TMPDIR_PROVISION/metadata"

run_psql() {
  run_without_openbao kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" \
    exec -i "$POSTGRES_POD" -c postgres -- \
    psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d codewire "$@"
}

log "checking fixed target=$TARGET fixture isolation"
resource_count="$(
  run_psql --set "org_id=$FIXTURE_ORG_ID" <<'SQL'
SELECT
  (SELECT COUNT(*) FROM admin_invoice_credits WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM environments WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM environment_presets WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM repo_configs WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM secret_projects WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM org_subscriptions WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM org_invitations WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM billing_events WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM environment_quotas WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM environment_subscriptions WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM environment_usage_billing WHERE org_id = :'org_id') +
  (SELECT COUNT(*) FROM stripe_invoices WHERE org_id = :'org_id');
SQL
)"
[[ "$resource_count" == "0" ]] || \
  die "fixed target=$TARGET organization is not an empty lifecycle fixture"

log "repairing fixed target=$TARGET identity and rotating bootstrap key"
run_psql \
  --set "user_id=$FIXTURE_USER_ID" \
  --set "user_email=$FIXTURE_USER_EMAIL" \
  --set "user_name=$FIXTURE_USER_NAME" \
  --set "org_id=$FIXTURE_ORG_ID" \
  --set "org_slug=$FIXTURE_ORG_SLUG" \
  --set "org_name=$FIXTURE_ORG_NAME" \
  --set "member_id=$FIXTURE_MEMBER_ID" \
  --set "key_name=$FIXTURE_KEY_NAME" \
  >"$KEY_FILE" <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
BEGIN;

INSERT INTO users (
  id, email, email_verified, name, is_admin, two_factor_enabled,
  failed_login_attempts, locked_until, created_at, updated_at
)
VALUES (
  :'user_id', :'user_email', true, :'user_name', false, false,
  0, NULL, NOW(), NOW()
)
ON CONFLICT (id) DO UPDATE
SET email = EXCLUDED.email,
    email_verified = true,
    name = EXCLUDED.name,
    is_admin = false,
    failed_login_attempts = 0,
    locked_until = NULL,
    updated_at = NOW();

INSERT INTO organizations (
  id, name, slug, created_by, billing_plan, billing_status,
  stripe_customer_id, trial_ends_at, created_at, updated_at
)
VALUES (
  :'org_id', :'org_name', :'org_slug', :'user_id', 'none', 'none',
  NULL, NULL, NOW(), NOW()
)
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    slug = EXCLUDED.slug,
    created_by = EXCLUDED.created_by,
    billing_plan = 'none',
    billing_status = 'none',
    stripe_customer_id = NULL,
    trial_ends_at = NULL,
    updated_at = NOW();

DELETE FROM org_member_assignments
WHERE org_member_id IN (
  SELECT id FROM org_members WHERE user_id = :'user_id' OR org_id = :'org_id'
);
DELETE FROM org_members WHERE user_id = :'user_id' OR org_id = :'org_id';

INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
VALUES (:'member_id', :'org_id', :'user_id', 'owner', NOW(), NOW());

WITH raw_key AS (
  SELECT 'cw_' || encode(public.gen_random_bytes(32), 'hex') AS value
), inserted AS (
  INSERT INTO api_keys (
    user_id, org_id, name, key_hash, key_prefix, scopes, created_at
  )
  SELECT
    :'user_id', :'org_id', :'key_name',
    encode(public.digest(raw_key.value, 'sha256'), 'hex'),
    substring(raw_key.value FROM 4 FOR 8), ARRAY[]::text[], NOW()
  FROM raw_key
  RETURNING id
)
SELECT raw_key.value FROM raw_key, inserted;
COMMIT;
SQL

chmod 0600 "$KEY_FILE"
if ! awk 'BEGIN { ok=0 } /^cw_[0-9a-f]{64}$/ { ok++ } END { exit ok == 1 ? 0 : 1 }' "$KEY_FILE"; then
  die "provisioning did not produce exactly one well-formed bootstrap key"
fi

run_psql \
  --set "user_id=$FIXTURE_USER_ID" \
  --set "user_email=$FIXTURE_USER_EMAIL" \
  --set "org_id=$FIXTURE_ORG_ID" \
  --set "org_slug=$FIXTURE_ORG_SLUG" \
  >"$META_FILE" <<'SQL'
SELECT
  u.id,
  u.email,
  u.is_admin,
  o.id,
  o.slug,
  (SELECT COUNT(*) FROM org_members WHERE user_id = u.id),
  (SELECT COUNT(*) FROM org_members WHERE org_id = o.id),
  (SELECT COUNT(*) FROM org_members WHERE user_id = u.id AND org_id = o.id AND role = 'owner'),
  (SELECT COUNT(*) FROM org_member_assignments a
     JOIN org_members m ON m.id = a.org_member_id WHERE m.user_id = u.id),
  (SELECT COUNT(*) FROM api_keys WHERE org_id = o.id AND disabled_at IS NULL),
  (SELECT key_prefix FROM api_keys
    WHERE user_id = u.id AND org_id = o.id AND disabled_at IS NULL
    ORDER BY created_at DESC LIMIT 1)
FROM users u
JOIN organizations o ON o.id = :'org_id'
WHERE u.id = :'user_id' AND u.email = :'user_email' AND o.slug = :'org_slug';
SQL

IFS='|' read -r actual_user_id actual_email is_admin actual_org_id actual_slug \
  membership_count org_member_count owner_count assignment_count org_active_key_count key_prefix <"$META_FILE"
[[ "$actual_user_id" == "$FIXTURE_USER_ID" ]] || die "fixed user ID verification failed"
[[ "$actual_email" == "$FIXTURE_USER_EMAIL" ]] || die "fixed user email verification failed"
[[ "$is_admin" == "f" ]] || die "fixture user must not be a site admin"
[[ "$actual_org_id" == "$FIXTURE_ORG_ID" ]] || die "fixed organization ID verification failed"
[[ "$actual_slug" == "$FIXTURE_ORG_SLUG" ]] || die "fixed organization slug verification failed"
[[ "$membership_count" == "1" ]] || die "fixture user must belong to exactly one organization"
[[ "$org_member_count" == "1" ]] || die "fixture organization must have exactly one member"
[[ "$owner_count" == "1" ]] || die "fixture user must own its fixed organization"
[[ "$assignment_count" == "0" ]] || die "fixture user must have no member assignments"
[[ "$org_active_key_count" =~ ^[1-9][0-9]*$ ]] || die "fixture organization must have an active API key"
[[ "$key_prefix" =~ ^[0-9a-f]{8}$ ]] || die "active bootstrap key prefix is malformed"

umask 077
jq -n --rawfile apiKey "$KEY_FILE" '{apiKey: ($apiKey | rtrimstr("\n"))}' >"$OPENBAO_FILE"
:>"$OPENBAO_STDOUT"
:>"$OPENBAO_STDERR"
chmod 0600 "$OPENBAO_FILE" "$OPENBAO_STDOUT" "$OPENBAO_STDERR"
if ! BAO_ADDR="$OPENBAO_ADDR" bao kv put "$OPENBAO_PATH" "@$OPENBAO_FILE" \
  >"$OPENBAO_STDOUT" 2>"$OPENBAO_STDERR"; then
  die "failed to store target=$TARGET bootstrap key in OpenBao; output suppressed; prior keys remain active"
fi

candidate_hash="$(tr -d '\n' <"$KEY_FILE" | sha256sum | awk '{print $1}')"
[[ "$candidate_hash" =~ ^[0-9a-f]{64}$ ]] || die 'candidate key fingerprint is malformed'
run_psql --set "user_id=$FIXTURE_USER_ID" --set "org_id=$FIXTURE_ORG_ID" \
  --set "candidate_hash=$candidate_hash" <<'SQL' >/dev/null
UPDATE api_keys
SET disabled_at = NOW()
WHERE (user_id = :'user_id' OR org_id = :'org_id')
  AND key_hash <> :'candidate_hash'
  AND disabled_at IS NULL;
SQL

active_key_count="$(run_psql --set "user_id=$FIXTURE_USER_ID" --set "org_id=$FIXTURE_ORG_ID" \
  --set "candidate_hash=$candidate_hash" <<'SQL'
SELECT COUNT(*) FROM api_keys
WHERE user_id = :'user_id' AND org_id = :'org_id'
  AND key_hash = :'candidate_hash' AND disabled_at IS NULL;
SQL
)"
[[ "$active_key_count" == '1' ]] || die 'candidate key was not the sole accepted replacement'

log "fixture user: $FIXTURE_USER_EMAIL"
log "fixture org: $FIXTURE_ORG_SLUG"
log "active bootstrap prefix: $key_prefix"
log "target=$TARGET provisioning complete"
