#!/usr/bin/env bash
# Put the Dev browser acceptance organization on the unlimited rate card, so
# Dev acceptance never depends on compute credit once enforcement is on
# (#3381; orchestrator, 2026-11-10: "acceptance must never depend on credit").
# The API smoke organization gets the same through provision-dev-smoke-user.sh.
# Run only through Infra's scoped kube-access wrapper for the Dev cluster. It
# reads and writes no secret and is safe to repeat: an organization already
# unlimited is left unchanged and records nothing.
set -euo pipefail

ORG_SLUG="${ORG_SLUG:-codewire-dev-e2e}"
OWNER_EMAIL="${OWNER_EMAIL:-e2e@codewire.sh}"
KUBE_NAMESPACE="${KUBE_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-codewire}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/make-dev-acceptance-unlimited.sh [options]

Puts the Dev browser acceptance organization on the unlimited rate card and
marks it billing-exempt, then reads the result back. The organization is
named by its slug and must be owned by the expected account; anything else
changes nothing.

Options:
  --org-slug SLUG       Acceptance organization (default: codewire-dev-e2e)
  --owner-email EMAIL   Its expected owner (default: e2e@codewire.sh)
  --context NAME        Optional Kubernetes context inside scoped kube-access
  --namespace NAME      Kubernetes namespace (default: dev)
  -h, --help            Show this help

Safety:
  - run through Infra scripts/kube-access --mode agent for the Dev cluster
  - writes to the database's current primary, found by its CloudNativePG role
USAGE
}

log() { printf '[dev-acceptance-unlimited] %s\n' "$*" >&2; }
die() { printf '[dev-acceptance-unlimited] ERROR: %s\n' "$*" >&2; exit 1; }

while (($# > 0)); do
  case "$1" in
    --org-slug) [[ $# -ge 2 ]] || die '--org-slug requires a value'; ORG_SLUG="$2"; shift 2 ;;
    --owner-email) [[ $# -ge 2 ]] || die '--owner-email requires a value'; OWNER_EMAIL="$2"; shift 2 ;;
    --context) [[ $# -ge 2 ]] || die '--context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace) [[ $# -ge 2 ]] || die '--namespace requires a value'; KUBE_NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$ORG_SLUG" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || die 'organization slug has an invalid shape'
[[ "$OWNER_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] ||
  die 'owner email has an invalid shape'
[[ "$KUBE_NAMESPACE" == dev ]] || die 'this script changes the Dev database only'
command -v kubectl >/dev/null 2>&1 || die 'missing required command: kubectl'
[[ -n "${INFRA_KUBECONFIG_DIR:-}" && -n "${KUBECONFIG:-}" ]] ||
  die 'run through the scoped Infra kube-access wrapper'
[[ "$KUBECONFIG" == "$INFRA_KUBECONFIG_DIR"/* ]] ||
  die 'KUBECONFIG is outside the scoped Infra kube-access directory'

KUBECTL=(kubectl)
[[ -z "$KUBE_CONTEXT" ]] || KUBECTL+=(--context "$KUBE_CONTEXT")

primaries="$("${KUBECTL[@]}" -n "$KUBE_NAMESPACE" get pods \
  -l cnpg.io/cluster=codewire-db,cnpg.io/instanceRole=primary -o name)"
[[ "$(wc -l <<<"$primaries")" == 1 && "$primaries" == pod/codewire-db-* ]] ||
  die 'expected exactly one codewire-db primary'
POSTGRES_POD="${primaries#pod/}"

run_psql() {
  "${KUBECTL[@]}" -n "$KUBE_NAMESPACE" exec -i "$POSTGRES_POD" \
    -c "$POSTGRES_CONTAINER" -- psql -X -qAt -v ON_ERROR_STOP=1 \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" "$@"
}

log "setting ${ORG_SLUG} to unlimited on ${POSTGRES_POD}"
# One transaction: lock the organization owned by the expected account, change
# it only if it is not unlimited yet, and audit that change. Prints the
# organization's ID and its rate card before the change; nothing when no such
# organization exists.
result="$(run_psql --set "org_slug=$ORG_SLUG" --set "owner_email=$OWNER_EMAIL" <<'SQL'
BEGIN;
WITH target AS (
  SELECT o.id, o.rate_card AS previous
    FROM organizations o
   WHERE o.slug = :'org_slug'
     AND EXISTS (
       SELECT 1 FROM org_members m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = o.id AND m.role = 'owner'
          AND lower(u.email) = lower(:'owner_email'))
   FOR UPDATE OF o
), updated AS (
  UPDATE organizations o
     SET rate_card = 'unlimited', billing_exempt = true, updated_at = NOW()
    FROM target
   WHERE o.id = target.id AND (o.rate_card <> 'unlimited' OR NOT o.billing_exempt)
  RETURNING o.id, target.previous
), audited AS (
  INSERT INTO audit_logs (id, timestamp, action, user_id, metadata, severity)
  SELECT gen_random_uuid()::text, NOW(), 'dev.acceptance.rate_card', NULL,
         jsonb_build_object('organization_id', updated.id, 'previous', updated.previous,
                            'rate_card', 'unlimited', 'billing_exempt', true,
                            'by', 'scripts/runtime/dev/make-dev-acceptance-unlimited.sh'),
         'warn'
    FROM updated
  RETURNING 1
)
SELECT target.id || '|' || target.previous || '|' || (SELECT count(*) FROM audited)
  FROM target;
COMMIT;
SQL
)"
[[ -n "$result" ]] || die "no organization ${ORG_SLUG} is owned by ${OWNER_EMAIL}; nothing changed"
IFS='|' read -r org_id previous audited <<<"$result"
[[ "$org_id" =~ ^[0-9a-f]{32}$ ]] || die 'the database returned an unexpected organization ID'

state="$(run_psql --set "org_id=$org_id" <<'SQL'
SELECT rate_card || '|' || billing_exempt::text FROM organizations WHERE id = :'org_id';
SQL
)"
[[ "$state" == 'unlimited|true' ]] || die "organization ${org_id} reads back as ${state}, not unlimited"
if [[ "$audited" == 1 ]]; then
  log "organization ${org_id}: ${previous} -> unlimited, billing-exempt (audited)"
else
  log "organization ${org_id} was already unlimited; nothing changed"
fi
