#!/usr/bin/env bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-dev}"
POSTGRES_POD="${POSTGRES_POD:-codewire-db-1}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-codewire}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
SMOKE_EMAIL="${SMOKE_EMAIL:-codewire-dev-smoke@codewire-dev.sh}"
SMOKE_NAME="${SMOKE_NAME:-Codewire Dev Smoke}"
SMOKE_ORG_NAME="${SMOKE_ORG_NAME:-Codewire Dev Smoke}"
SMOKE_ORG_SLUG="${SMOKE_ORG_SLUG:-codewire-dev-smoke}"
SMOKE_KEY_NAME="${SMOKE_KEY_NAME:-runtime-dev-commodity-smoke}"
INFISICAL_ENV="${INFISICAL_ENV:-dev}"
INFISICAL_PATH="${INFISICAL_PATH:-/}"
INFISICAL_DOMAIN="${INFISICAL_DOMAIN:-https://infisical.example.invalid}"
INFISICAL_PROJECT_ID="${INFISICAL_PROJECT_ID:-}"
SKIP_INFISICAL="${SKIP_INFISICAL:-0}"

TMPDIR_SMOKE=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/provision-dev-smoke-user.sh [options]

Creates or repairs the dedicated dev smoke identity used by
smoke-dev-commodity.sh, rotates its API key, and stores the key in
Infisical without printing it.

Options:
  --email EMAIL             Smoke user email
  --name NAME               Smoke user display name
  --org-name NAME           Smoke organization name
  --org-slug SLUG           Smoke organization slug
  --key-name NAME           Smoke API key name
  --context NAME            Kubernetes context (default: codewire-dev)
  --namespace NAME          Kubernetes namespace (default: dev)
  --postgres-pod NAME       Postgres pod (default: codewire-db-1)
  --infisical-env NAME      Infisical environment (default: dev)
  --infisical-path PATH     Infisical path (default: /)
  --infisical-domain URL    Infisical instance (default: https://infisical.example.invalid)
  --infisical-project-id ID Optional Infisical project ID
  --skip-infisical          Provision DB only; do not write Infisical
  -h, --help                Show this help

Safety:
  - never run this with shell tracing enabled
  - never pipe this through tee
  - do not inspect the private temp files unless you intend to handle secrets
USAGE
}

log() {
  printf '[runtime-smoke-provision] %s\n' "$*" >&2
}

die() {
  printf '[runtime-smoke-provision] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

cleanup() {
  if [[ -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" ]]; then
    rm -rf "$TMPDIR_SMOKE"
  fi
}
trap cleanup EXIT

while (($# > 0)); do
  case "$1" in
    --email)
      [[ $# -ge 2 ]] || die "--email requires a value"
      SMOKE_EMAIL="$2"
      shift 2
      ;;
    --name)
      [[ $# -ge 2 ]] || die "--name requires a value"
      SMOKE_NAME="$2"
      shift 2
      ;;
    --org-name)
      [[ $# -ge 2 ]] || die "--org-name requires a value"
      SMOKE_ORG_NAME="$2"
      shift 2
      ;;
    --org-slug)
      [[ $# -ge 2 ]] || die "--org-slug requires a value"
      SMOKE_ORG_SLUG="$2"
      shift 2
      ;;
    --key-name)
      [[ $# -ge 2 ]] || die "--key-name requires a value"
      SMOKE_KEY_NAME="$2"
      shift 2
      ;;
    --context)
      [[ $# -ge 2 ]] || die "--context requires a value"
      KUBE_CONTEXT="$2"
      shift 2
      ;;
    --namespace)
      [[ $# -ge 2 ]] || die "--namespace requires a value"
      KUBE_NAMESPACE="$2"
      shift 2
      ;;
    --postgres-pod)
      [[ $# -ge 2 ]] || die "--postgres-pod requires a value"
      POSTGRES_POD="$2"
      shift 2
      ;;
    --infisical-env)
      [[ $# -ge 2 ]] || die "--infisical-env requires a value"
      INFISICAL_ENV="$2"
      shift 2
      ;;
    --infisical-path)
      [[ $# -ge 2 ]] || die "--infisical-path requires a value"
      INFISICAL_PATH="$2"
      shift 2
      ;;
    --infisical-domain)
      [[ $# -ge 2 ]] || die "--infisical-domain requires a value"
      INFISICAL_DOMAIN="$2"
      shift 2
      ;;
    --infisical-project-id)
      [[ $# -ge 2 ]] || die "--infisical-project-id requires a value"
      INFISICAL_PROJECT_ID="$2"
      shift 2
      ;;
    --skip-infisical)
      SKIP_INFISICAL=1
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

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

require_cmd kubectl
require_cmd infisical
require_cmd awk

if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

TMPDIR_SMOKE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-smoke-provision.XXXXXX")"
chmod 0700 "$TMPDIR_SMOKE"
KEY_FILE="$TMPDIR_SMOKE/api-key"
ENV_FILE="$TMPDIR_SMOKE/infisical.env"
META_FILE="$TMPDIR_SMOKE/metadata"

run_psql() {
  kubectl --context "$KUBE_CONTEXT" -n "$KUBE_NAMESPACE" \
    exec -i "$POSTGRES_POD" -c "$POSTGRES_CONTAINER" -- \
    psql -X -qAt -v ON_ERROR_STOP=1 \
      -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"
}

log "provisioning smoke identity in $KUBE_CONTEXT/$KUBE_NAMESPACE"

run_psql \
  --set "smoke_email=$SMOKE_EMAIL" \
  --set "smoke_name=$SMOKE_NAME" \
  --set "org_name=$SMOKE_ORG_NAME" \
  --set "org_slug=$SMOKE_ORG_SLUG" \
  --set "key_name=$SMOKE_KEY_NAME" \
  >"$KEY_FILE" <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
BEGIN;
WITH input AS (
  SELECT
    :'smoke_email'::text AS smoke_email,
    :'smoke_name'::text AS smoke_name,
    :'org_name'::text AS org_name,
    :'org_slug'::text AS org_slug,
    :'key_name'::text AS key_name
),
smoke_user AS (
  INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), smoke_email, true, smoke_name, NOW(), NOW()
  FROM input
  ON CONFLICT (email) DO UPDATE
    SET email_verified = true,
        name = EXCLUDED.name,
        updated_at = NOW()
  RETURNING id
),
smoke_org AS (
  INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), org_name, org_slug, smoke_user.id, NOW(), NOW()
  FROM input, smoke_user
  ON CONFLICT (slug) DO UPDATE
    SET name = EXCLUDED.name,
        updated_at = NOW()
  RETURNING id
),
prune_memberships AS (
  DELETE FROM org_members m
  USING smoke_user, smoke_org
  WHERE m.user_id = smoke_user.id
    AND m.org_id <> smoke_org.id
  RETURNING m.id
),
update_membership AS (
  UPDATE org_members m
  SET role = 'owner',
      updated_at = NOW()
  FROM smoke_user, smoke_org
  WHERE m.user_id = smoke_user.id
    AND m.org_id = smoke_org.id
  RETURNING m.id
),
insert_membership AS (
  INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), smoke_org.id, smoke_user.id, 'owner', NOW(), NOW()
  FROM smoke_user, smoke_org
  WHERE NOT EXISTS (SELECT 1 FROM update_membership)
  RETURNING id
),
disable_old_keys AS (
  UPDATE api_keys ak
  SET disabled_at = NOW()
  FROM smoke_user
  WHERE ak.user_id = smoke_user.id
    AND ak.disabled_at IS NULL
  RETURNING ak.id
),
raw_key AS (
  SELECT 'cw_' || encode(public.gen_random_bytes(32), 'hex') AS value
),
insert_key AS (
  INSERT INTO api_keys (user_id, org_id, name, key_hash, key_prefix, scopes, created_at)
  SELECT
    smoke_user.id,
    smoke_org.id,
    input.key_name,
    encode(public.digest(raw_key.value, 'sha256'), 'hex'),
    substring(raw_key.value FROM 4 FOR 8),
    ARRAY[]::text[],
    NOW()
  FROM input, smoke_user, smoke_org, raw_key, (SELECT COUNT(*) FROM disable_old_keys) AS old_keys
  RETURNING id
)
SELECT raw_key.value FROM raw_key, insert_key;
COMMIT;
SQL

if ! awk 'BEGIN { ok=0 } /^cw_[0-9a-f]{64}$/ { ok=1 } END { exit ok ? 0 : 1 }' "$KEY_FILE"; then
  die "provisioning did not produce a well-formed API key"
fi

run_psql \
  --set "smoke_email=$SMOKE_EMAIL" \
  --set "org_slug=$SMOKE_ORG_SLUG" \
  --set "key_name=$SMOKE_KEY_NAME" \
  >"$META_FILE" <<'SQL'
WITH smoke_user AS (
  SELECT id, email FROM users WHERE email = :'smoke_email'
),
smoke_org AS (
  SELECT id, slug FROM organizations WHERE slug = :'org_slug'
)
SELECT
  smoke_user.email,
  smoke_org.slug,
  (SELECT COUNT(*) FROM org_members WHERE user_id = smoke_user.id),
  (SELECT COUNT(*) FROM org_members WHERE user_id = smoke_user.id AND org_id = smoke_org.id AND role = 'owner'),
  (SELECT COUNT(*) FROM api_keys WHERE user_id = smoke_user.id AND disabled_at IS NULL),
  (SELECT key_prefix FROM api_keys WHERE user_id = smoke_user.id AND disabled_at IS NULL ORDER BY created_at DESC LIMIT 1)
FROM smoke_user, smoke_org;
SQL

IFS='|' read -r actual_email actual_slug membership_count owner_count active_key_count key_prefix <"$META_FILE"
[[ "$actual_email" == "$SMOKE_EMAIL" ]] || die "metadata verification failed for smoke email"
[[ "$actual_slug" == "$SMOKE_ORG_SLUG" ]] || die "metadata verification failed for smoke org slug"
[[ "$membership_count" == "1" ]] || die "smoke user must belong to exactly one organization"
[[ "$owner_count" == "1" ]] || die "smoke user must own the smoke organization"
[[ "$active_key_count" == "1" ]] || die "smoke user must have exactly one active API key"
[[ -n "$key_prefix" ]] || die "active smoke API key prefix was empty"

if [[ "$SKIP_INFISICAL" != "1" ]]; then
  umask 077
  {
    printf 'CODEWIRE_DEV_SMOKE_API_KEY=%s\n' "$(awk 'NR == 1 { print; exit }' "$KEY_FILE")"
    printf 'EXPECTED_CODEWIRE_SMOKE_USER_EMAIL=%s\n' "$SMOKE_EMAIL"
  } >"$ENV_FILE"

  infisical_cmd=(
    infisical secrets set
    --env "$INFISICAL_ENV"
    --path "$INFISICAL_PATH"
    --domain "$INFISICAL_DOMAIN"
    --file "$ENV_FILE"
    --log-level error
    --silent
  )
  if [[ -n "$INFISICAL_PROJECT_ID" ]]; then
    infisical_cmd+=(--projectId "$INFISICAL_PROJECT_ID")
  fi

  if ! "${infisical_cmd[@]}" >/dev/null 2>"$TMPDIR_SMOKE/infisical-set.err"; then
    die "failed to write smoke secrets to Infisical; output suppressed to avoid leaking secrets"
  fi
  log "stored smoke secrets using requested Infisical domain=$INFISICAL_DOMAIN env=$INFISICAL_ENV path=$INFISICAL_PATH"
else
  log "skipped Infisical write"
fi

log "smoke user: $SMOKE_EMAIL"
log "smoke org: $SMOKE_ORG_SLUG"
log "active API key prefix: $key_prefix"
log "provisioning complete"
