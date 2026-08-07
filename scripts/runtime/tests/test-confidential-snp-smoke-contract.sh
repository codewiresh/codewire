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
rg -F 'phase == "confidential-snp"' "$SMOKE" >/dev/null
rg -F 'restore the commodity source profile' "$SMOKE" >/dev/null
rg -F -- '--gateway-image' "$RESOLVER" >/dev/null
rg -F -- '--source-sha' "$RESOLVER" >/dev/null

rg -F 'SANDBOX_RUNTIME_PROFILE: commodity' "$PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_PROFILE: commodity' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "false"' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_CLASS: commodity' "$PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "false"' "$PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_PROFILE: confidential' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_CLASS: confidential' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_DOCKER_MODE: guest-dind' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_CONFIDENTIAL_STORAGE_ENABLED: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_CONFIDENTIAL_ADMIN_ONLY: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_WORKSPACE_STORAGE_CLASS: longhorn-confidential' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_KBS_URL: https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080' \
  "$CONFIDENTIAL_PROFILE" >/dev/null

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

command -v kustomize >/dev/null 2>&1 || {
  printf 'kustomize is required for the confidential smoke contract\n' >&2
  exit 1
}
kustomize build "$SMOKE_DIR" >/dev/null
kustomize build "$ROOT/deployments/k8s/overlays/dev" >/dev/null

printf 'Confidential SNP GitOps smoke contract tests passed\n'
