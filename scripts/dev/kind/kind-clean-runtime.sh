#!/usr/bin/env bash
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-kind-codewire}"
POSTGRES_NAMESPACE="${POSTGRES_NAMESPACE:-default}"
POSTGRES_DEPLOYMENT="${POSTGRES_DEPLOYMENT:-postgres}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
KIND_CLEAN_RUNTIME_RESET_DB="${KIND_CLEAN_RUNTIME_RESET_DB:-0}"
TEMPORAL_NAMESPACE="${TEMPORAL_NAMESPACE:-default}"
TEMPORAL_SYSTEM_NAMESPACE="${TEMPORAL_SYSTEM_NAMESPACE:-temporal-system}"
TEMPORAL_ADMINTOOLS_DEPLOYMENT="${TEMPORAL_ADMINTOOLS_DEPLOYMENT:-temporal-admintools}"
TEMPORAL_ADDRESS="${TEMPORAL_ADDRESS:-temporal-frontend.temporal-system.svc.cluster.local:7233}"

uuid_re='([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'

log() {
  printf '[kind-clean-runtime] %s\n' "$*"
}

db_query() {
  kubectl --context "$KUBE_CONTEXT" -n "$POSTGRES_NAMESPACE" exec "deploy/${POSTGRES_DEPLOYMENT}" -- \
    psql -U codewire -d codewire -At -c "$1"
}

db_exec() {
  kubectl --context "$KUBE_CONTEXT" -n "$POSTGRES_NAMESPACE" exec "deploy/${POSTGRES_DEPLOYMENT}" -- \
    psql -U codewire -d codewire -v ON_ERROR_STOP=1 -q -c "$1" >/dev/null
}

have_postgres() {
  kubectl --context "$KUBE_CONTEXT" -n "$POSTGRES_NAMESPACE" get "deploy/${POSTGRES_DEPLOYMENT}" >/dev/null 2>&1
}

have_temporal_admintools() {
  kubectl --context "$KUBE_CONTEXT" -n "$TEMPORAL_SYSTEM_NAMESPACE" get "deploy/${TEMPORAL_ADMINTOOLS_DEPLOYMENT}" >/dev/null 2>&1
}

contains_line() {
  local needle="$1"
  local haystack="$2"
  [[ -n "$needle" && -n "$haystack" ]] && grep -Fqx "$needle" <<<"$haystack"
}

delete_if_exists() {
  local namespace="$1"
  shift
  kubectl --context "$KUBE_CONTEXT" -n "$namespace" delete "$@" --ignore-not-found --wait=false >/dev/null
}

clear_claim_finalizers() {
  local claim_name="$1"
  kubectl --context "$KUBE_CONTEXT" -n "$SANDBOX_NAMESPACE" patch sandboxclaim "$claim_name" \
    --type=merge -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1 || true
}

terminate_environment_workflows() {
  kubectl --context "$KUBE_CONTEXT" -n "$TEMPORAL_SYSTEM_NAMESPACE" exec "deploy/${TEMPORAL_ADMINTOOLS_DEPLOYMENT}" -- \
    temporal workflow terminate \
      --address "$TEMPORAL_ADDRESS" \
      --namespace "$TEMPORAL_NAMESPACE" \
      --query "WorkflowId STARTS_WITH 'environment/' AND ExecutionStatus='Running'" \
      --reason "local kind runtime reset" \
      --rps 20 \
      --yes \
      --command-timeout 15s \
      >/dev/null 2>&1 || true
}

if ! have_postgres; then
  log "postgres deployment not found; skipping cleanup"
  exit 0
fi

if [[ "$KIND_CLEAN_RUNTIME_RESET_DB" == "1" ]]; then
  reset_sandbox_ids="$(db_query "select id from environments where state <> 'destroyed' and type = 'sandbox' order by id;")"
  if have_temporal_admintools; then
    log "terminating running local environment workflows"
    terminate_environment_workflows
  else
    log "temporal admintools deployment not found; skipping workflow termination"
  fi

  if [[ -n "$reset_sandbox_ids" ]]; then
    log "resetting active sandbox environments in DB for local e2e"
    db_exec "UPDATE environments
             SET state = 'destroyed',
                 desired_state = 'destroyed',
                 destroyed_at = COALESCE(destroyed_at, NOW()),
                 stopped_at = COALESCE(stopped_at, NOW()),
                 deletion_requested_at = COALESCE(deletion_requested_at, NOW()),
                 deletion_grace_until = NULL,
                 error_reason = NULL,
                 recoverable = false,
                 state_changed_at = NOW()
             WHERE state <> 'destroyed'
               AND type = 'sandbox';"
  else
    log "no active sandbox environments to reset in DB"
  fi
fi

active_sandbox_ids="$(db_query "select id from environments where state <> 'destroyed' and type = 'sandbox' order by id;")"
active_non_sandbox_count="$(db_query "select count(*) from environments where state <> 'destroyed' and type <> 'sandbox';")"

log "active sandbox env ids:"
if [[ -n "$active_sandbox_ids" ]]; then
  while IFS= read -r env_id; do
    log "  keep sandbox env ${env_id}"
  done <<<"$active_sandbox_ids"
else
  log "  none"
fi

log "cleaning orphan sandbox resources in namespace ${SANDBOX_NAMESPACE}"

while IFS= read -r pod_name; do
  [[ -z "$pod_name" ]] && continue
  if [[ "$pod_name" =~ $uuid_re ]]; then
    env_id="${BASH_REMATCH[1]}"
    if contains_line "$env_id" "$active_sandbox_ids"; then
      continue
    fi
    log "  deleting orphan sandbox pod/service/pvc/claim for ${env_id}"
    delete_if_exists "$SANDBOX_NAMESPACE" pod "$pod_name"
    delete_if_exists "$SANDBOX_NAMESPACE" service "$pod_name"
    delete_if_exists "$SANDBOX_NAMESPACE" pvc "workspace-${pod_name}"
    clear_claim_finalizers "sandbox-${env_id}"
    delete_if_exists "$SANDBOX_NAMESPACE" sandboxclaim "sandbox-${env_id}"
  fi
done < <(kubectl --context "$KUBE_CONTEXT" -n "$SANDBOX_NAMESPACE" get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

while IFS= read -r claim_name; do
  [[ -z "$claim_name" ]] && continue
  if [[ "$claim_name" =~ $uuid_re ]]; then
    env_id="${BASH_REMATCH[1]}"
    if contains_line "$env_id" "$active_sandbox_ids"; then
      continue
    fi
    log "  deleting orphan sandbox claim ${claim_name}"
    clear_claim_finalizers "$claim_name"
    delete_if_exists "$SANDBOX_NAMESPACE" sandboxclaim "$claim_name"
  fi
done < <(kubectl --context "$KUBE_CONTEXT" -n "$SANDBOX_NAMESPACE" get sandboxclaim -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)

while IFS=$'\t' read -r pool_name env_id; do
  [[ -z "$pool_name" ]] && continue
  if contains_line "$env_id" "$active_sandbox_ids"; then
    continue
  fi
  log "  deleting orphan sandbox claim shadow ${pool_name}"
  delete_if_exists "$SANDBOX_NAMESPACE" sandboxwarmpool "$pool_name"
done < <(kubectl --context "$KUBE_CONTEXT" -n "$SANDBOX_NAMESPACE" get sandboxwarmpool \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.codewire\.sh/environment-id}{"\n"}{end}' 2>/dev/null || true)

while IFS= read -r template_name; do
  [[ -z "$template_name" ]] && continue
  if [[ "$template_name" =~ $uuid_re ]]; then
    env_id="${BASH_REMATCH[1]}"
    if contains_line "$env_id" "$active_sandbox_ids"; then
      continue
    fi
    log "  deleting orphan sandbox template ${template_name}"
    delete_if_exists "$SANDBOX_NAMESPACE" sandboxtemplate "$template_name"
  fi
done < <(kubectl --context "$KUBE_CONTEXT" -n "$SANDBOX_NAMESPACE" get sandboxtemplate -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)

if [[ "${active_non_sandbox_count}" != "0" ]]; then
  log "non-sandbox environments still active in DB; skipping local-tenant namespace cleanup"
  exit 0
fi

while IFS= read -r ns_name; do
  [[ -z "$ns_name" ]] && continue
  log "  deleting orphan local tenant namespace ${ns_name}"
  kubectl --context "$KUBE_CONTEXT" delete namespace "$ns_name" --ignore-not-found --wait=false >/dev/null
done < <(kubectl --context "$KUBE_CONTEXT" get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep '^local-tenant-' || true)

log "cleanup complete"
