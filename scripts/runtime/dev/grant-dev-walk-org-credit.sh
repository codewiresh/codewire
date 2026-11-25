#!/usr/bin/env bash
# Give a walk's throwaway Dev organization a bounded compute credit, so a walk
# that deletes an organization with a running Sandbox (#3586) never puts one on
# the unlimited rate card. The organization must be one the synthetic invitee
# (provision-dev-invitee-user.sh) created and owns, named for its walk, whose
# only other member, if any, is the personal-walk identity as a plain member.
# In one transaction its automatic top-up is turned off, its quota becomes one
# Sandbox of the default shape, and its credit is topped up to exactly EUR 2
# by one named grant; then the result is read back. It reads and writes no
# secret, and is safe to repeat. Run only through Infra's scoped kube-access
# wrapper for the Dev cluster.
set -euo pipefail

readonly OWNER_EMAIL="success+codewire-dev-invitee@simulator.amazonses.com"
readonly MEMBER_EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
# EUR 2 in nano-euro, and the default shape (api/admin/capacity.rs): 2 CPUs and 8 GiB.
readonly CREDIT_NANO_EUR=2000000000
readonly QUOTA_CPU_MILLICORES=2000
readonly QUOTA_MEMORY_MB=8192
ORG_SLUG=""
KUBE_NAMESPACE="${KUBE_NAMESPACE:-dev}"
KUBE_CONTEXT="${KUBE_CONTEXT:-}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-postgres}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-codewire}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/dev/grant-dev-walk-org-credit.sh --org-slug SLUG [options]

Bounds the compute of a walk's throwaway Dev organization: automatic top-up
off, a quota of one environment and one Sandbox of 2000 millicores and
8192 MB, and its credit topped up to exactly EUR 2 by one named grant. Then
it reads the organization back and fails unless all of that holds.

SLUG names the walk: w, the issue number, then a name (w3586-del-1). The
organization must be active, on the regular rate card, created and owned by
the synthetic invitee (success+codewire-dev-invitee@simulator.amazonses.com),
with no member but it and, optionally, the personal-walk identity as a plain
member. Anything else changes nothing.

Options:
  --org-slug SLUG       The walk's organization
  --context NAME        Optional Kubernetes context inside scoped kube-access
  --namespace NAME      Kubernetes namespace (default: dev)
  -h, --help            Show this help

Safety:
  - run through Infra scripts/kube-access for the Dev cluster, in its default OIDC mode
  - writes to the database's current primary, found by its CloudNativePG role
  - never the unlimited rate card; the walk deletes the organization after
USAGE
}

log() { printf '[dev-walk-org-credit] %s\n' "$*" >&2; }
die() { printf '[dev-walk-org-credit] ERROR: %s\n' "$*" >&2; exit 1; }

while (($# > 0)); do
  case "$1" in
    --org-slug) [[ $# -ge 2 ]] || die '--org-slug requires a value'; ORG_SLUG="$2"; shift 2 ;;
    --context) [[ $# -ge 2 ]] || die '--context requires a value'; KUBE_CONTEXT="$2"; shift 2 ;;
    --namespace) [[ $# -ge 2 ]] || die '--namespace requires a value'; KUBE_NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$ORG_SLUG" =~ ^w[0-9]{3,5}-[a-z0-9]+(-[a-z0-9]+)*$ && "${#ORG_SLUG}" -le 40 ]] ||
  die 'the organization slug must name its walk, such as w3586-del-1'
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

log "bounding ${ORG_SLUG} on ${POSTGRES_POD}"
# One transaction. The organization is locked only if it is the invitee's walk
# organization as described above; otherwise nothing is written and nothing is
# printed. Every write only narrows it, except the grant, which tops the credit
# up to EUR 2 and never above. The state line is read inside the transaction.
result="$(run_psql --set "org_slug=$ORG_SLUG" --set "owner_email=$OWNER_EMAIL" \
  --set "member_email=$MEMBER_EMAIL" --set "credit=$CREDIT_NANO_EUR" \
  --set "cpu=$QUOTA_CPU_MILLICORES" --set "memory=$QUOTA_MEMORY_MB" <<'SQL'
BEGIN;
-- Always one row, so \gset never fails: found is false when no organization
-- matches.
WITH target AS (
  SELECT o.id
    FROM organizations o JOIN users owner ON owner.id = o.created_by
   WHERE o.slug = :'org_slug' AND lower(owner.email) = lower(:'owner_email')
     AND o.rate_card = 'regular' AND o.deletion_state = 'active' AND o.suspended_at IS NULL
     AND EXISTS (SELECT 1 FROM org_members m WHERE m.org_id = o.id AND m.user_id = owner.id
                   AND m.role = 'owner')
     AND NOT EXISTS (
       SELECT 1 FROM org_members m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = o.id AND m.user_id <> owner.id
          AND NOT (lower(u.email) = lower(:'member_email') AND m.role = 'member'))
     FOR UPDATE OF o
)
SELECT count(*) = 1 AS found, COALESCE(max(id), '') AS org_id FROM target \gset
\if :found
UPDATE organizations SET auto_top_up_enabled = false, updated_at = NOW()
 WHERE id = :'org_id' AND auto_top_up_enabled;
INSERT INTO environment_quotas (org_id, max_concurrent_environments, max_concurrent_sandbox,
  max_cpu_millicores, max_memory_mb)
VALUES (:'org_id', 1, 1, :cpu, :memory)
ON CONFLICT (org_id) DO UPDATE SET max_concurrent_environments = 1, max_concurrent_sandbox = 1,
  max_cpu_millicores = :cpu, max_memory_mb = :memory;
INSERT INTO billing_credit_ledger (organization_id, entry_kind, amount_nano_eur, idempotency_key,
  reason)
SELECT :'org_id', 'grant', :credit - balance,
  'dev-walk-org-credit-' || :'org_id' || '-'
    || to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYYMMDD"T"HH24MISSUS'),
  'Dev walk organization ' || :'org_slug' || ' (#3586): topped up to EUR 2 by its grant script'
FROM (SELECT COALESCE((SELECT balance_nano_eur FROM billing_credit_balances
  WHERE organization_id = :'org_id'), 0) AS balance) AS current
WHERE balance < :credit;
SELECT 'state', :'org_id',
  (SELECT count(*) FROM organizations WHERE id = :'org_id' AND rate_card = 'regular'
    AND NOT auto_top_up_enabled AND deletion_state = 'active'),
  (SELECT count(*) FROM environment_quotas WHERE org_id = :'org_id'
    AND max_concurrent_environments = 1 AND max_concurrent_sandbox = 1
    AND max_cpu_millicores = :cpu AND max_memory_mb = :memory),
  (SELECT COALESCE((SELECT balance_nano_eur FROM billing_credit_balances
    WHERE organization_id = :'org_id'), 0)),
  (SELECT count(*) FROM org_members WHERE org_id = :'org_id');
\endif
COMMIT;
SQL
)" || die "the database write failed; nothing was changed"
[[ -n "$result" ]] ||
  die "no walk organization ${ORG_SLUG} that the invitee created and owns, with no other member but the personal-walk identity; nothing changed"
IFS='|' read -r label org_id flags quota balance members <<<"$result"
[[ "$label" == state && "$org_id" =~ ^[0-9a-f]{32}$ ]] ||
  die 'the database returned an unexpected state line'
[[ "$flags" == 1 ]] || die "organization ${org_id} is not regular, active and without top-up"
[[ "$quota" == 1 ]] || die "organization ${org_id}'s quota is not one Sandbox of the default shape"
[[ "$balance" == "$CREDIT_NANO_EUR" ]] ||
  die "organization ${org_id}'s credit is ${balance} nano-euro, not EUR 2; do not walk with it"
[[ "$members" =~ ^[12]$ ]] || die "organization ${org_id} has ${members} members"
log "PASS org=${ORG_SLUG} id=${org_id} rate_card=regular auto_top_up=off quota=1x${QUOTA_CPU_MILLICORES}m${QUOTA_MEMORY_MB}MB credit_eur=2 members=${members}"
