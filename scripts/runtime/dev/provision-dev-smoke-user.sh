#!/usr/bin/env bash
# Rotate the Dev commodity-smoke identity without ever creating a zero-key or
# secret-store/database split. Run only through Infra's scoped kube-access
# wrapper and a current human OpenBao OIDC session.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly OPENBAO_PATH="apps/codewire/dev/ci-smoke"
readonly CODEWIRE_SERVER_URL="https://codewire-dev.sh"

KUBE_CONTEXT="${KUBE_CONTEXT:-}"
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
SMOKE_PLAN_KEY="${SMOKE_PLAN_KEY:-unlimited}"
CW_BIN="${CW_BIN:-$ROOT/target/debug/cw}"

TMPDIR_SMOKE=""
CANDIDATE_HASH=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/provision-dev-smoke-user.sh [options]

Creates or repairs the dedicated Dev smoke user and organization, rotates its
API key, CAS-publishes the replacement to the canonical OpenBao document,
proves the replacement through an isolated Codewire client, and only then
disables older database keys.

Options:
  --email EMAIL             Smoke user email
  --name NAME               Smoke user display name
  --org-name NAME           Smoke organization name
  --org-slug SLUG           Smoke organization slug
  --key-name NAME           Smoke API key name
  --plan-key KEY            Billing plan used by the smoke org
  --context NAME            Optional Kubernetes context inside scoped kube-access
  --namespace NAME          Kubernetes namespace (default: dev)
  --postgres-pod NAME       PostgreSQL pod (default: codewire-db-1)
  -h, --help                Show this help

Safety:
  - run through Infra scripts/kube-access --mode agent dev-cluster
  - establish the normal OpenBao human OIDC session before invoking it
  - never run with shell tracing or pipe output through tee
  - a failed publication or probe keeps the previously active key usable
USAGE
}

log() { printf '[runtime-smoke-provision] %s\n' "$*" >&2; }
die() { printf '[runtime-smoke-provision] ERROR: %s\n' "$*" >&2; exit 1; }

secure_remove() {
  [[ "$#" -gt 0 ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$@" 2>/dev/null && return 0
  fi
  rm -f -- "$@" 2>/dev/null
}

cleanup() {
  local status=0
  if [[ -n "$TMPDIR_SMOKE" && -d "$TMPDIR_SMOKE" ]]; then
    while IFS= read -r -d '' file; do secure_remove "$file" || status=1; done \
      < <(find "$TMPDIR_SMOKE" -type f -print0)
    while IFS= read -r -d '' dir; do rmdir "$dir" 2>/dev/null || status=1; done \
      < <(find "$TMPDIR_SMOKE" -depth -type d -print0)
    [[ ! -e "$TMPDIR_SMOKE" ]] || status=1
  fi
  TMPDIR_SMOKE=""
  return "$status"
}
trap 'cleanup || true' EXIT
trap 'exit 130' HUP INT TERM

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

while (($# > 0)); do
  case "$1" in
    --email) [[ $# -ge 2 ]] || die '--email requires a value'; SMOKE_EMAIL="$2"; shift 2 ;;
    --name) [[ $# -ge 2 ]] || die '--name requires a value'; SMOKE_NAME="$2"; shift 2 ;;
    --org-name) [[ $# -ge 2 ]] || die '--org-name requires a value'; SMOKE_ORG_NAME="$2"; shift 2 ;;
    --org-slug) [[ $# -ge 2 ]] || die '--org-slug requires a value'; SMOKE_ORG_SLUG="$2"; shift 2 ;;
    --key-name) [[ $# -ge 2 ]] || die '--key-name requires a value'; SMOKE_KEY_NAME="$2"; shift 2 ;;
    --plan-key) [[ $# -ge 2 ]] || die '--plan-key requires a value'; SMOKE_PLAN_KEY="$2"; shift 2 ;;
    --context) [[ $# -ge 2 ]] || die '--context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace) [[ $# -ge 2 ]] || die '--namespace requires a value'; KUBE_NAMESPACE="$2"; shift 2 ;;
    --postgres-pod) [[ $# -ge 2 ]] || die '--postgres-pod requires a value'; POSTGRES_POD="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
[[ "$SMOKE_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] ||
  die 'smoke email has an invalid shape'
[[ "$SMOKE_ORG_SLUG" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] ||
  die 'smoke organization slug has an invalid shape'
[[ "$SMOKE_KEY_NAME" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] ||
  die 'smoke key name has an invalid shape'
[[ "$SMOKE_PLAN_KEY" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] ||
  die 'smoke plan key has an invalid shape'
for command in awk bao find jq kubectl mktemp rg rm rmdir sha256sum stat; do
  require_cmd "$command"
done
[[ -x "$CW_BIN" ]] || die "Codewire CLI is unavailable: $CW_BIN"
[[ -n "${INFRA_KUBECONFIG_DIR:-}" && -n "${KUBECONFIG:-}" ]] ||
  die 'run through the scoped Infra kube-access wrapper'
[[ "$KUBECONFIG" == "$INFRA_KUBECONFIG_DIR"/* ]] ||
  die 'KUBECONFIG is outside the scoped Infra kube-access directory'
[[ "${BAO_ADDR:-$OPENBAO_ADDR}" == "$OPENBAO_ADDR" ]] ||
  die 'BAO_ADDR must be the canonical OpenBao Tailnet endpoint'
export BAO_ADDR="$OPENBAO_ADDR"

umask 077
TMPDIR_SMOKE="$(mktemp -d "${TMPDIR:-/tmp}/codewire-smoke-rotation.XXXXXX")"
chmod 0700 "$TMPDIR_SMOKE"
KEY_FILE="$TMPDIR_SMOKE/candidate-api-key"
CANDIDATE_PAYLOAD="$TMPDIR_SMOKE/candidate-openbao.json"
OLD_DOCUMENT="$TMPDIR_SMOKE/old-openbao.json"
OLD_PAYLOAD="$TMPDIR_SMOKE/old-openbao-payload.json"
CURRENT_DOCUMENT="$TMPDIR_SMOKE/current-openbao.json"
BAO_STDOUT="$TMPDIR_SMOKE/bao.stdout"
BAO_STDERR="$TMPDIR_SMOKE/bao.stderr"
PROBE_CONFIG="$TMPDIR_SMOKE/cw-config"
PROBE_STDOUT="$TMPDIR_SMOKE/probe.json"
PROBE_STDERR="$TMPDIR_SMOKE/probe.stderr"
DB_RESULT="$TMPDIR_SMOKE/db-result"
mkdir -m 0700 "$PROBE_CONFIG"
for file in "$KEY_FILE" "$CANDIDATE_PAYLOAD" "$OLD_DOCUMENT" "$OLD_PAYLOAD" \
  "$CURRENT_DOCUMENT" "$BAO_STDOUT" "$BAO_STDERR" "$PROBE_STDOUT" \
  "$PROBE_STDERR" "$DB_RESULT"; do
  : >"$file"
  chmod 0600 "$file"
done

KUBECTL=(kubectl)
[[ -z "$KUBE_CONTEXT" ]] || KUBECTL+=(--context "$KUBE_CONTEXT")
run_psql() {
  "${KUBECTL[@]}" -n "$KUBE_NAMESPACE" exec -i "$POSTGRES_POD" \
    -c "$POSTGRES_CONTAINER" -- psql -X -qAt -v ON_ERROR_STOP=1 \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"
}

read_openbao_document() {
  local output="$1"
  : >"$BAO_STDERR"
  if ! bao kv get -format=json "$OPENBAO_PATH" >"$output" 2>"$BAO_STDERR"; then
    if rg -qi 'permission denied|status code: 403|code 403' "$BAO_STDERR"; then
      die 'OpenBao OIDC session is stale or lacks the exact Dev smoke path'
    fi
    die 'unable to read the canonical Dev smoke document; protected output suppressed'
  fi
  jq -e '
    (.data.metadata.version | type == "number" and . > 0) and
    (.data.data | type == "object" and keys == ["apiKey", "userEmail"]) and
    (.data.data.apiKey | type == "string" and test("^cw_[0-9a-f]{64}$")) and
    (.data.data.userEmail | type == "string" and
      test("^[^[:space:]@]+@[^[:space:]@]+\\.[^[:space:]@]+$"))
  ' "$output" >/dev/null || die 'canonical Dev smoke document has an unexpected shape'
}

rollback_candidate() {
  [[ "$CANDIDATE_HASH" =~ ^[0-9a-f]{64}$ ]] || return 0
  {
    printf "\\set candidate_hash '%s'\n" "$CANDIDATE_HASH"
    printf "\\set smoke_email '%s'\n" "$SMOKE_EMAIL"
    cat <<'SQL'
UPDATE api_keys
SET disabled_at = COALESCE(disabled_at, NOW())
WHERE user_id = (SELECT id FROM users WHERE email = :'smoke_email')
  AND key_hash = :'candidate_hash';
SELECT COUNT(*) FROM api_keys
WHERE user_id = (SELECT id FROM users WHERE email = :'smoke_email')
  AND key_hash = :'candidate_hash' AND disabled_at IS NULL;
SQL
  } | run_psql >"$DB_RESULT"
  [[ "$(<"$DB_RESULT")" == "0" ]] || die 'candidate database key rollback was inconclusive'
}

restore_old_document() {
  local current_version
  read_openbao_document "$CURRENT_DOCUMENT"
  jq -e --slurpfile candidate "$CANDIDATE_PAYLOAD" \
    '.data.data == $candidate[0]' "$CURRENT_DOCUMENT" >/dev/null ||
    die 'canonical document changed concurrently; candidate remains active for safe reconciliation'
  current_version="$(jq -er '.data.metadata.version' "$CURRENT_DOCUMENT")"
  if ! bao kv put -cas="$current_version" "$OPENBAO_PATH" "@$OLD_PAYLOAD" \
    >"$BAO_STDOUT" 2>"$BAO_STDERR"; then
    die 'unable to restore the prior canonical document; candidate remains active'
  fi
  read_openbao_document "$CURRENT_DOCUMENT"
  jq -e --slurpfile old "$OLD_PAYLOAD" '.data.data == $old[0]' \
    "$CURRENT_DOCUMENT" >/dev/null || die 'prior canonical document restore was inconclusive'
}

log 'checking the canonical OpenBao document before database mutation'
read_openbao_document "$OLD_DOCUMENT"
jq -e '.data.data' "$OLD_DOCUMENT" >"$OLD_PAYLOAD"
old_version="$(jq -er '.data.metadata.version' "$OLD_DOCUMENT")"

log 'creating one candidate key while retaining every currently active key'
run_psql \
  --set "smoke_email=$SMOKE_EMAIL" \
  --set "smoke_name=$SMOKE_NAME" \
  --set "org_name=$SMOKE_ORG_NAME" \
  --set "org_slug=$SMOKE_ORG_SLUG" \
  --set "key_name=$SMOKE_KEY_NAME" \
  --set "plan_key=$SMOKE_PLAN_KEY" \
  >"$KEY_FILE" <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
BEGIN;
WITH input AS (
  SELECT :'smoke_email'::text AS smoke_email, :'smoke_name'::text AS smoke_name,
    :'org_name'::text AS org_name, :'org_slug'::text AS org_slug,
    :'key_name'::text AS key_name, :'plan_key'::text AS plan_key
), smoke_user AS (
  INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), smoke_email, true, smoke_name, NOW(), NOW()
  FROM input
  ON CONFLICT (email) DO UPDATE SET email_verified = true, name = EXCLUDED.name, updated_at = NOW()
  RETURNING id
), confidential_plan AS (
  INSERT INTO billing_catalog_plans (
    resource_type, plan_key, display_name, price_cents, max_concurrent_ws,
    is_admin_only, cpu_overage_cents, mem_overage_cents, disk_overage_cents,
    created_at, updated_at
  )
  SELECT 'confidential_sandbox', plan_key, 'Dev smoke confidential sandbox', 0,
    1, true, 5.04, 1.62, 0.01, NOW(), NOW() FROM input
  ON CONFLICT (resource_type, plan_key) DO UPDATE SET
    display_name = EXCLUDED.display_name, price_cents = EXCLUDED.price_cents,
    max_concurrent_ws = EXCLUDED.max_concurrent_ws, is_admin_only = EXCLUDED.is_admin_only,
    cpu_overage_cents = EXCLUDED.cpu_overage_cents,
    mem_overage_cents = EXCLUDED.mem_overage_cents,
    disk_overage_cents = EXCLUDED.disk_overage_cents,
    archived_at = NULL, updated_at = NOW()
  RETURNING plan_key
), smoke_org AS (
  INSERT INTO organizations (
    id, name, slug, created_by, billing_plan, billing_status, billing_exempt,
    created_at, updated_at
  )
  SELECT encode(public.gen_random_bytes(16), 'hex'), org_name, org_slug,
    smoke_user.id, input.plan_key, 'active', true, NOW(), NOW()
  FROM input, smoke_user, confidential_plan
  ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name,
    billing_plan = EXCLUDED.billing_plan, billing_status = EXCLUDED.billing_status,
    billing_exempt = EXCLUDED.billing_exempt, updated_at = NOW()
  RETURNING id
), prune_memberships AS (
  DELETE FROM org_members m USING smoke_user, smoke_org
  WHERE m.user_id = smoke_user.id AND m.org_id <> smoke_org.id RETURNING m.id
), update_membership AS (
  UPDATE org_members m SET role = 'owner', updated_at = NOW()
  FROM smoke_user, smoke_org
  WHERE m.user_id = smoke_user.id AND m.org_id = smoke_org.id RETURNING m.id
), insert_membership AS (
  INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
  SELECT encode(public.gen_random_bytes(16), 'hex'), smoke_org.id, smoke_user.id,
    'owner', NOW(), NOW() FROM smoke_user, smoke_org
  WHERE NOT EXISTS (SELECT 1 FROM update_membership) RETURNING id
), raw_key AS (
  SELECT 'cw_' || encode(public.gen_random_bytes(32), 'hex') AS value
), insert_key AS (
  INSERT INTO api_keys (user_id, org_id, name, key_hash, key_prefix, scopes, created_at)
  SELECT smoke_user.id, smoke_org.id, input.key_name,
    encode(public.digest(raw_key.value, 'sha256'), 'hex'),
    substring(raw_key.value FROM 4 FOR 8), ARRAY[]::text[], NOW()
  FROM input, smoke_user, smoke_org, raw_key
  RETURNING id
)
SELECT raw_key.value FROM raw_key, insert_key;
COMMIT;
SQL

awk 'NR == 1 && /^cw_[0-9a-f]{64}$/ { ok=1; next } { ok=0; exit }
  END { exit ok == 1 ? 0 : 1 }' "$KEY_FILE" ||
  die 'database did not return exactly one well-formed candidate key'
candidate_key="$(awk 'NR == 1 { print; exit }' "$KEY_FILE")"
CANDIDATE_HASH="$(printf '%s' "$candidate_key" | sha256sum | awk '{print $1}')"
[[ "$CANDIDATE_HASH" =~ ^[0-9a-f]{64}$ ]] || die 'candidate fingerprint failed'
jq -n --rawfile apiKey "$KEY_FILE" --arg userEmail "$SMOKE_EMAIL" '
  {apiKey: ($apiKey | rtrimstr("\n")), userEmail: $userEmail}
' >"$CANDIDATE_PAYLOAD"

log 'CAS-publishing the candidate to canonical OpenBao'
if ! bao kv put -cas="$old_version" "$OPENBAO_PATH" "@$CANDIDATE_PAYLOAD" \
  >"$BAO_STDOUT" 2>"$BAO_STDERR"; then
  rollback_candidate
  die 'canonical OpenBao CAS publication failed; candidate database key was disabled'
fi
read_openbao_document "$CURRENT_DOCUMENT"
jq -e --slurpfile candidate "$CANDIDATE_PAYLOAD" \
  '.data.data == $candidate[0]' "$CURRENT_DOCUMENT" >/dev/null || {
  restore_old_document
  rollback_candidate
  die 'canonical OpenBao readback failed; prior document was restored'
}

log 'proving the candidate with an isolated API-key client'
set +e
CODEWIRE_API_KEY="$candidate_key" CW_CONFIG_DIR="$PROBE_CONFIG" \
  "$CW_BIN" --server "$CODEWIRE_SERVER_URL" org list --output json \
  >"$PROBE_STDOUT" 2>"$PROBE_STDERR"
probe_exit="$?"
set -e
unset candidate_key
if [[ "$probe_exit" != 0 ]] || ! jq -e --arg slug "$SMOKE_ORG_SLUG" '
  type == "array" and length == 1 and .[0].slug == $slug and .[0].role == "owner"
' "$PROBE_STDOUT" >/dev/null; then
  restore_old_document
  rollback_candidate
  die 'candidate API authentication failed; prior document was restored and candidate disabled'
fi

read_openbao_document "$CURRENT_DOCUMENT"
jq -e --slurpfile candidate "$CANDIDATE_PAYLOAD" \
  '.data.data == $candidate[0]' "$CURRENT_DOCUMENT" >/dev/null ||
  die 'canonical OpenBao document changed concurrently; active keys were retained'

log 'disabling older keys only after publication and API proof'
{
  printf "\\set candidate_hash '%s'\n" "$CANDIDATE_HASH"
  printf "\\set smoke_email '%s'\n" "$SMOKE_EMAIL"
  cat <<'SQL'
BEGIN;
WITH smoke_user AS (
  SELECT id FROM users WHERE email = :'smoke_email'
), candidate_key AS (
  SELECT api_keys.id, api_keys.created_at
  FROM api_keys, smoke_user
  WHERE api_keys.user_id = smoke_user.id
    AND api_keys.key_hash = :'candidate_hash'
    AND api_keys.disabled_at IS NULL
)
UPDATE api_keys SET disabled_at = NOW()
FROM smoke_user, candidate_key
WHERE api_keys.user_id = smoke_user.id
  AND api_keys.key_hash <> :'candidate_hash'
  AND api_keys.created_at < candidate_key.created_at
  AND api_keys.disabled_at IS NULL;
COMMIT;
SQL
} | run_psql >/dev/null

# A sibling SELECT in a data-modifying CTE sees the statement's pre-update
# snapshot. Verify in a fresh statement after COMMIT so this receipt observes
# the keys that were actually revoked.
{
  printf "\\set candidate_hash '%s'\n" "$CANDIDATE_HASH"
  printf "\\set smoke_email '%s'\n" "$SMOKE_EMAIL"
  printf "\\set org_slug '%s'\n" "$SMOKE_ORG_SLUG"
  cat <<'SQL'
-- final database state assertion
WITH smoke_user AS (
  SELECT id FROM users WHERE email = :'smoke_email'
), smoke_org AS (
  SELECT id FROM organizations WHERE slug = :'org_slug'
)
SELECT
  (SELECT COUNT(*) FROM api_keys, smoke_user, smoke_org
    WHERE api_keys.user_id = smoke_user.id AND api_keys.org_id = smoke_org.id
      AND api_keys.key_hash = :'candidate_hash' AND api_keys.disabled_at IS NULL),
  (SELECT COUNT(*) FROM api_keys, smoke_user
    WHERE api_keys.user_id = smoke_user.id AND api_keys.disabled_at IS NULL),
  (SELECT COUNT(*) FROM org_members, smoke_user, smoke_org
    WHERE org_members.user_id = smoke_user.id AND org_members.org_id = smoke_org.id
      AND org_members.role = 'owner');
SQL
} | run_psql >"$DB_RESULT"
[[ "$(<"$DB_RESULT")" == '1|1|1' ]] ||
  die 'post-commit database verification did not observe the exact one-key/one-owner state'

read_openbao_document "$CURRENT_DOCUMENT"
jq -e --slurpfile candidate "$CANDIDATE_PAYLOAD" \
  '.data.data == $candidate[0]' "$CURRENT_DOCUMENT" >/dev/null ||
  die 'canonical OpenBao document changed after database finalization'

cleanup || die 'failed to remove temporary smoke credential material'
trap - EXIT HUP INT TERM
log 'PASS canonical_store=openbao api_probe=true active_database_keys=1 secret_values_printed=false'
