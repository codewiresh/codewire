#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/confidential/smoke-dev-confidential-snp.sh"
RESOLVER="$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh"
WRAPPER="$ROOT/scripts/runtime/confidential/with-dev-confidential-coco-config.sh"
PROFILE="$ROOT/deployments/k8s/overlays/dev/config-runtime-profile.yaml"
COMMODITY_PROFILE="$ROOT/deployments/k8s/overlays/dev/config-runtime-profile-commodity.yaml"
CONFIDENTIAL_PROFILE="$ROOT/deployments/k8s/overlays/dev/config-runtime-profile-confidential-snp.yaml"
SMOKE_DIR="$ROOT/deployments/k8s/runtime-profiles/confidential-smoke"

if cmp -s "$PROFILE" "$COMMODITY_PROFILE"; then
  active_profile=commodity
elif cmp -s "$PROFILE" "$CONFIDENTIAL_PROFILE"; then
  active_profile=confidential
else
  printf 'active runtime profile is not an approved source template\n' >&2
  exit 1
fi

if cmp -s "$SMOKE_DIR/kustomization.yaml" "$SMOKE_DIR/kustomization.baseline.yaml"; then
  active_smoke=commodity
elif cmp -s "$SMOKE_DIR/kustomization.yaml" "$SMOKE_DIR/kustomization.confidential-snp.yaml"; then
  active_smoke=confidential
else
  printf 'active confidential smoke Kustomization is not an approved source template\n' >&2
  exit 1
fi

if [[ "$active_profile" != "$active_smoke" ]]; then
  printf 'runtime profile and confidential smoke activation must transition together\n' >&2
  exit 1
fi

bash -n "$SMOKE"
bash -n "$RESOLVER"
[[ ! -e "$WRAPPER" ]] || {
  printf 'imperative confidential ConfigMap wrapper still exists\n' >&2
  exit 1
}

if rg -n '^[[:space:]]*(kubectl|kubectl_dev)([[:space:]]+[^[:space:]]+)*[[:space:]]+(apply|create|delete|edit|patch|replace|scale)\b' "$SMOKE"; then
  printf 'confidential smoke must not mutate Kubernetes or Flux state\n' >&2
  exit 1
fi
if rg -q 'with-dev-confidential-coco-config|COCO_CLEANUP_RECEIPT|kind: Lease|apply-runtime-classes' "$SMOKE"; then
  printf 'confidential smoke still contains an imperative control path\n' >&2
  exit 1
fi

rg -F 'SMOKE_KUSTOMIZATION="codewire-deploy-confidential-smoke-dev"' "$SMOKE" >/dev/null
rg -F 'KUBE_CONTEXT="${KUBE_CONTEXT:-dev-cluster}"' "$SMOKE" >/dev/null
rg -F 'NODE="${CONFIDENTIAL_SNP_NODE:-cw-dev-prod-node-1}"' "$SMOKE" >/dev/null
rg -F './scripts/talos-external-worker verify' "$SMOKE" >/dev/null
if rg -q 'check-node1|node1-codewire-dev|node1\.codewire-dev\.sh|ssh_host\(' "$SMOKE"; then
  printf 'confidential smoke still contains the retired Ubuntu/SSH host gate\n' >&2
  exit 1
fi
rg -F 'COMMODITY_JOB_SELECTOR="app.kubernetes.io/name=codewire-commodity-runtime-smoke"' "$SMOKE" >/dev/null
rg -F 'CONFIDENTIAL_JOB_SELECTOR="app.kubernetes.io/name=codewire-confidential-runtime-smoke"' "$SMOKE" >/dev/null
rg -F 'ATTESTATION_JOB_SELECTOR="app.kubernetes.io/name=codewire-confidential-snp-attestation"' "$SMOKE" >/dev/null
rg -F 'umask 077' "$SMOKE" >/dev/null
rg -F 'chmod 700 "$EVIDENCE_DIR"' "$SMOKE" >/dev/null
rg -F 'expected exactly one $label Job matching $selector' "$SMOKE" >/dev/null
rg -F 'phase == "confidential-snp"' "$SMOKE" >/dev/null
rg -F 'nexus\.example\.invalid/oci-approved/codewire/gateway@sha256:' "$SMOKE" >/dev/null
if rg -F 'git\.example\.invalid/codewire/gateway@sha256:' "$SMOKE" "$RESOLVER"; then
  printf 'confidential smoke accepts the retired Gitea gateway authority\n' >&2
  exit 1
fi
rg -F 'restore the commodity source profile' "$SMOKE" >/dev/null
rg -F -- '--admin-oidc "${smoke_args[@]}"' "$SMOKE" >/dev/null
rg -F 'SMOKE_ISOLATION_TIER=confidential' "$SMOKE" >/dev/null
if rg -F 'with-dev-smoke-auth.sh' "$SMOKE"; then
  printf 'admin-only confidential smoke must not use the API-key auth wrapper\n' >&2
  exit 1
fi
rg -F -- '--gateway-image' "$RESOLVER" >/dev/null
rg -F -- '--source-sha' "$RESOLVER" >/dev/null

rg -F 'SANDBOX_RUNTIME_PROFILE: commodity' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "false"' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_CLASS: commodity' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_PROFILE: confidential' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_CLASS: confidential' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_DOCKER_MODE: guest-dind' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_CONFIDENTIAL_STORAGE_ENABLED: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_CONFIDENTIAL_ADMIN_ONLY: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_WORKSPACE_STORAGE_CLASS: longhorn-confidential' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_KBS_URL: https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080' \
  "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'COCO_KBS_URL="${COCO_KBS_URL:-https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080}"' \
  "$SMOKE" >/dev/null
if rg -F 'http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080' \
  "$SMOKE" "$CONFIDENTIAL_PROFILE"; then
  printf 'confidential KBS contract must require TLS\n' >&2
  exit 1
fi

rg -F 'confidential-smoke-control.yaml' "$SMOKE_DIR/kustomization.yaml" >/dev/null
rg -F 'confidential-smoke-control.yaml' "$SMOKE_DIR/kustomization.baseline.yaml" >/dev/null
rg -F 'commodity-smoke-job.yaml' "$SMOKE_DIR/kustomization.confidential-snp.yaml" >/dev/null
rg -F 'confidential-smoke-job.yaml' "$SMOKE_DIR/kustomization.confidential-snp.yaml" >/dev/null
rg -F 'confidential-attestation-job.yaml' "$SMOKE_DIR/kustomization.confidential-snp.yaml" >/dev/null

for manifest in "$SMOKE_DIR"/*-job.yaml; do
  rg -F 'kind: Job' "$manifest" >/dev/null
  rg -F 'namespace: codewire-runtime-probes' "$manifest" >/dev/null
  rg -F 'automountServiceAccountToken: false' "$manifest" >/dev/null
  if rg -q 'namespace: default|hostNetwork:|hostPID:|hostIPC:|hostPath:' "$manifest"; then
    printf 'Flux-owned runtime Job exceeds its probe boundary: %s\n' "$manifest" >&2
    exit 1
  fi
done

rg -F 'node.codewire.sh/confidential-snp: "true"' "$SMOKE_DIR/confidential-smoke-job.yaml" >/dev/null
rg -F 'node.codewire.sh/confidential-snp: "true"' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null
rg -F 'privileged: true' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null
rg -F 'name: codewire-commodity-runtime-smoke-v56' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'name: codewire-confidential-runtime-smoke-v56' "$SMOKE_DIR/confidential-smoke-job.yaml" >/dev/null
rg -F 'name: codewire-confidential-snp-attestation-v56' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null

command -v kustomize >/dev/null 2>&1 || {
  printf 'kustomize is required for the confidential smoke contract\n' >&2
  exit 1
}
kustomize build "$SMOKE_DIR" >/dev/null
kustomize build "$ROOT/deployments/k8s/overlays/dev" >/dev/null

printf 'Confidential SNP GitOps smoke contract tests passed\n'
