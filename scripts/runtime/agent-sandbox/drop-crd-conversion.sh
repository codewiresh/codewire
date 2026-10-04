#!/usr/bin/env bash
# One-time migration for clusters that ran the agent-sandbox controller with
# the v1alpha1 conversion webhook (fork pins up to 4c528d39).
#
# The v1beta1-only CRDs drop spec.conversion. Flux applies them with
# server-side apply, which removes only the conversion fields Flux owns: the
# caBundle the old controller injected stays behind, and the API server
# rejects the result ("spec.conversion.strategy: Required value",
# "webhookClientConfig: Forbidden"). That failure holds the agent-sandbox
# Kustomization and everything that depends on it. Upstream's migration guide
# relies on client-side `kubectl apply`, which replaces the whole block.
#
# This script replaces each CRD's spec.conversion with {strategy: None} in one
# JSON patch, guarded by test operations, so Flux's next apply succeeds. It
# refuses unless every CRD stores only v1beta1 and still points at the old
# webhook Service. It is a dry run unless --apply is given.
#
# Run it when the Kustomization reports the rejection above, or immediately
# before Flux reconciles the pin that drops v1alpha1. Afterwards, with
# --delete-webhook-secret, it removes the controller-created webhook
# certificate Secret once no Deployment or Service still uses the webhook.
# Flux prunes the webhook Service, Role and RoleBinding itself.
set -euo pipefail

NAMESPACE="agent-sandbox-system"
WEBHOOK_SERVICE="agent-sandbox-webhook-service"
WEBHOOK_SECRET="agent-sandbox-webhook-certs"
CRDS=(
  sandboxes.agents.x-k8s.io
  sandboxclaims.extensions.agents.x-k8s.io
  sandboxtemplates.extensions.agents.x-k8s.io
  sandboxwarmpools.extensions.agents.x-k8s.io
)

CONTEXT=""
APPLY=0
DELETE_SECRET=0

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/agent-sandbox/drop-crd-conversion.sh --context NAME [--apply]
  scripts/runtime/agent-sandbox/drop-crd-conversion.sh --context NAME \
    --delete-webhook-secret [--apply]

Replaces spec.conversion with {strategy: None} on the four agent-sandbox CRDs
so Flux can apply the v1beta1-only CRDs. Dry run (server side) unless --apply.

  --context NAME           kubeconfig context to act on (required)
  --apply                  make the change instead of a server-side dry run
  --delete-webhook-secret  after the new controller runs, delete the orphaned
                           webhook certificate Secret instead
USAGE
}

die() { printf 'drop-crd-conversion: %s\n' "$*" >&2; exit 1; }
log() { printf 'drop-crd-conversion: %s\n' "$*" >&2; }

while (($#)); do
  case "$1" in
    --context) [[ $# -ge 2 ]] || die '--context needs a value'; CONTEXT="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --delete-webhook-secret) DELETE_SECRET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ -n "$CONTEXT" ]] || die '--context is required'
command -v kubectl >/dev/null || die 'kubectl is required'
command -v jq >/dev/null || die 'jq is required'

kc() { kubectl --context "$CONTEXT" "$@"; }
dry_run=()
((APPLY)) || dry_run=(--dry-run=server)

if ((DELETE_SECRET)); then
  for crd in "${CRDS[@]}"; do
    strategy="$(kc get crd "$crd" -o json | jq -r '.spec.conversion.strategy // "None"')"
    [[ "$strategy" == None ]] || die "$crd still uses conversion strategy $strategy"
  done
  if kc -n "$NAMESPACE" get service "$WEBHOOK_SERVICE" >/dev/null 2>&1; then
    die "Service $WEBHOOK_SERVICE still exists; let Flux prune it first"
  fi
  if kc -n "$NAMESPACE" get deployments -o json |
    jq -e '[.items[].spec.template.spec.containers[].ports[]? | select(.containerPort == 9443)] | length > 0' >/dev/null; then
    die 'a Deployment still exposes the webhook port 9443; wait for the new controller'
  fi
  if ! kc -n "$NAMESPACE" get secret "$WEBHOOK_SECRET" -o name >/dev/null 2>&1; then
    log "Secret $WEBHOOK_SECRET is already gone"
    exit 0
  fi
  kc -n "$NAMESPACE" delete secret "$WEBHOOK_SECRET" "${dry_run[@]}"
  ((APPLY)) || log 'dry run only; rerun with --apply'
  exit 0
fi

# Check every CRD before changing any of them.
pending=()
for crd in "${CRDS[@]}"; do
  json="$(kc get crd "$crd" -o json)" || die "cannot read CRD $crd"
  stored="$(jq -c '.status.storedVersions' <<<"$json")"
  [[ "$stored" == '["v1beta1"]' ]] ||
    die "$crd stores $stored; finish the v1alpha1 storage migration first"
  strategy="$(jq -r '.spec.conversion.strategy // "None"' <<<"$json")"
  webhook="$(jq -c '.spec.conversion.webhook // null' <<<"$json")"
  if [[ "$strategy" == None && "$webhook" == null ]]; then
    log "$crd: conversion already dropped"
    continue
  fi
  service="$(jq -r '.spec.conversion.webhook.clientConfig.service | "\(.namespace // "")/\(.name // "")"' <<<"$json")"
  [[ "$strategy" == Webhook && "$service" == "$NAMESPACE/$WEBHOOK_SERVICE" ]] ||
    die "$crd has unexpected conversion (strategy $strategy, service $service); refusing"
  pending+=("$crd")
done

patch="$(jq -cn --arg service "$WEBHOOK_SERVICE" '[
  {op: "test", path: "/spec/conversion/strategy", value: "Webhook"},
  {op: "test", path: "/spec/conversion/webhook/clientConfig/service/name", value: $service},
  {op: "replace", path: "/spec/conversion", value: {strategy: "None"}}
]')"
for crd in "${pending[@]}"; do
  kc patch crd "$crd" --type=json -p "$patch" "${dry_run[@]}"
done

if ((APPLY)); then
  for crd in "${CRDS[@]}"; do
    conversion="$(kc get crd "$crd" -o json | jq -c '.spec.conversion // {"strategy":"None"}')"
    [[ "$conversion" == '{"strategy":"None"}' ]] || die "$crd conversion is $conversion after the patch"
  done
  log 'all four CRDs carry conversion {strategy: None}; Flux can apply the v1beta1-only CRDs'
else
  log "dry run only (${#pending[@]} CRD(s) to patch); rerun with --apply"
fi
