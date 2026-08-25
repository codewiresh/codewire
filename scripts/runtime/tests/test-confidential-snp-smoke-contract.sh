#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/confidential/smoke-dev-confidential-snp.sh"
RUNTIME_CONFIGMAP_SELECTOR="$ROOT/scripts/runtime/confidential/select-required-runtime-configmap.jq"
READY_CURRENT_SELECTOR="$ROOT/scripts/runtime/confidential/select-ready-current.jq"
RESOLVER="$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh"
WRAPPER="$ROOT/scripts/runtime/confidential/with-dev-confidential-coco-config.sh"
PROFILE="$ROOT/deployments/k8s/overlays/dev/config-runtime-profile.yaml"
COMMODITY_PROFILE="$ROOT/deployments/k8s/overlays/dev/config-runtime-profile-commodity.yaml"
CONFIDENTIAL_PROFILE="$ROOT/deployments/k8s/overlays/dev/config-runtime-profile-confidential-snp.yaml"
SMOKE_DIR="$ROOT/deployments/k8s/runtime-profiles/confidential-smoke"
RUNTIME_PROFILE_DIR="$ROOT/deployments/k8s/runtime-profiles/base"
ORCHESTRATION_DEPLOYMENT="$ROOT/deployments/k8s/orchestration/deployment.yaml"

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
rg -F 'CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-https://codewire-dev.sh}"' "$SMOKE" >/dev/null
rg -F 'KUBE_CONTEXT="${KUBE_CONTEXT:-dev-cluster}"' "$SMOKE" >/dev/null
rg -F 'SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"' "$SMOKE" >/dev/null
rg -F 'NODE="${CONFIDENTIAL_SNP_NODE:-cw-dev-prod-node-1}"' "$SMOKE" >/dev/null
rg -F 'COMMODITY_NODE="${CONFIDENTIAL_COMMODITY_NODE:-dev-node-1}"' "$SMOKE" >/dev/null
rg -F './scripts/talos-external-worker verify' "$SMOKE" >/dev/null
if rg -q 'check-node1|node1-codewire-dev|node1\.codewire-dev\.sh|ssh_host\(' "$SMOKE"; then
  printf 'confidential smoke contains a nonexistent Ubuntu/SSH host gate\n' >&2
  exit 1
fi
rg -F 'COMMODITY_JOB_SELECTOR="app.kubernetes.io/name=codewire-commodity-runtime-smoke"' "$SMOKE" >/dev/null
rg -F 'record_job "$commodity_job" commodity "$COMMODITY_NODE" longhorn' "$SMOKE" >/dev/null
rg -F 'RUN_COMMODITY_JOB="${RUN_COMMODITY_JOB:-0}"' "$SMOKE" >/dev/null
rg -F -- '--include-commodity-job' "$SMOKE" >/dev/null
rg -F 'CONFIDENTIAL_JOB_SELECTOR="app.kubernetes.io/name=codewire-confidential-runtime-smoke"' "$SMOKE" >/dev/null
rg -F 'ATTESTATION_JOB_SELECTOR="app.kubernetes.io/name=codewire-confidential-snp-attestation"' "$SMOKE" >/dev/null
rg -F 'umask 077' "$SMOKE" >/dev/null
rg -F 'chmod 700 "$EVIDENCE_DIR"' "$SMOKE" >/dev/null
rg -F 'expected exactly one $label Job matching $selector' "$SMOKE" >/dev/null
rg -F 'jq -er -f "$RUNTIME_CONFIGMAP_SELECTOR" "$deployment_json"' "$SMOKE" >/dev/null
rg -F 'phase == "confidential-snp"' "$SMOKE" >/dev/null
rg -F 'if [[ "$RUN_COCO_PRODUCT" != "1" ]]; then' "$SMOKE" >/dev/null
rg -F 'log "skipping product release image resolution"' "$SMOKE" >/dev/null
rg -F 'if [[ "$RUN_COCO_PRODUCT" == "1" ]]; then' "$SMOKE" >/dev/null
rg -F 'nexus\.example\.invalid/oci-approved/codewire/gateway@sha256:' "$SMOKE" >/dev/null
if rg -F 'git\.example\.invalid/codewire/gateway@sha256:' "$SMOKE" "$RESOLVER"; then
  printf 'confidential smoke accepts the retired Gitea gateway authority\n' >&2
  exit 1
fi
rg -F 'restore the commodity source profile' "$SMOKE" >/dev/null
rg -F -- '--admin-oidc "${smoke_args[@]}"' "$SMOKE" >/dev/null
rg -F 'CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_CODEWIRE_DEV_SERVER_URL="$EXPECTED_CODEWIRE_DEV_SERVER_URL"' "$SMOKE" >/dev/null
rg -F 'CODEWIRE_SERVER_NAMESPACE="$CODEWIRE_SERVER_NAMESPACE"' "$SMOKE" >/dev/null
rg -F 'KUBE_CONTEXT="$KUBE_CONTEXT"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_GATEWAY_STUN_HOST="$COCO_GATEWAY_STUN_HOST"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_GATEWAY_STUN_PORT="$COCO_GATEWAY_STUN_PORT"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_TAILNET_DIRECT_UDP_LB_IP="$COCO_DIRECT_UDP_LB_IP"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="$COCO_DIRECT_UDP_TRANSPORT_ZONE"' "$SMOKE" >/dev/null
rg -F 'SMOKE_IMAGE="${SMOKE_IMAGE:-$COCO_WORKSPACE_IMAGE}"' "$SMOKE" >/dev/null
if rg -F 'smoke_args=(--image ' "$SMOKE"; then
  printf 'confidential smoke passes an unsupported image CLI option\n' >&2
  exit 1
fi
rg -F 'SMOKE_ISOLATION_TIER=confidential' "$SMOKE" >/dev/null
if rg -F 'with-dev-smoke-auth.sh' "$SMOKE"; then
  printf 'admin-only confidential smoke must not use the API-key auth wrapper\n' >&2
  exit 1
fi
rg -F -- '--gateway-image' "$RESOLVER" >/dev/null
rg -F -- '--source-sha' "$RESOLVER" >/dev/null

forward_dir="$(mktemp -d "$ROOT/.tmp/confidential-smoke-forwarding.XXXXXX")"
mkdir -p "$forward_dir/root/scripts/runtime/dev"
cat >"$forward_dir/root/scripts/runtime/dev/smoke-dev-commodity.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'server_namespace=%s\n' "${CODEWIRE_SERVER_NAMESPACE:-}"
  printf 'kube_context=%s\n' "${KUBE_CONTEXT:-}"
  printf 'stun_host=%s\n' "${EXPECTED_GATEWAY_STUN_HOST:-}"
  printf 'stun_port=%s\n' "${EXPECTED_GATEWAY_STUN_PORT:-}"
  printf 'direct_udp_ip=%s\n' "${EXPECTED_TAILNET_DIRECT_UDP_LB_IP:-}"
  printf 'transport_zone=%s\n' "${EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE:-}"
} >"${FORWARD_CAPTURE:?}"
EOF
chmod 0755 "$forward_dir/root/scripts/runtime/dev/smoke-dev-commodity.sh"
mkdir -p "$forward_dir/evidence"
(
  export EVIDENCE_DIR="$forward_dir/evidence"
  # shellcheck disable=SC1090
  source <(sed '$d' "$SMOKE")
  ROOT="$forward_dir/root"
  export CODEWIRE_SERVER_NAMESPACE=contract-server
  export SANDBOX_NAMESPACE=contract-sandboxes
  export KUBE_CONTEXT=contract-context
  export COCO_GATEWAY_IMAGE=nexus.example.invalid/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export COCO_WORKSPACE_IMAGE=example.invalid/workspace@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  export COCO_DIND_IMAGE=example.invalid/dind@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  export COCO_GATEWAY_STUN_HOST=stun.example.invalid
  export COCO_GATEWAY_STUN_PORT=3478
  export COCO_DIRECT_UDP_LB_IP=192.0.2.20
  export COCO_DIRECT_UDP_TRANSPORT_ZONE=contract-zone
  FORWARD_CAPTURE="$forward_dir/capture" run_product_command
)
cat >"$forward_dir/expected" <<'EOF'
server_namespace=contract-server
kube_context=contract-context
stun_host=stun.example.invalid
stun_port=3478
direct_udp_ip=192.0.2.20
transport_zone=contract-zone
EOF
cmp "$forward_dir/expected" "$forward_dir/capture"
rm -rf "$forward_dir"

jq -n '{
  metadata: {generation: 7},
  status: {
    observedGeneration: 7,
    conditions: [{type: "Ready", status: "True", observedGeneration: 7}]
  }
}' | jq -e -f "$READY_CURRENT_SELECTOR" >/dev/null || {
  printf 'current Ready condition was rejected\n' >&2
  exit 1
}
if jq -n '{
  metadata: {generation: 7},
  status: {
    observedGeneration: 7,
    conditions: [{type: "Ready", status: "True", observedGeneration: 6}]
  }
}' | jq -e -f "$READY_CURRENT_SELECTOR" >/dev/null; then
  printf 'stale Ready condition was accepted\n' >&2
  exit 1
fi
if jq -n '{
  metadata: {generation: 7},
  status: {
    observedGeneration: 6,
    conditions: [{type: "Ready", status: "True", observedGeneration: 7}]
  }
}' | jq -e -f "$READY_CURRENT_SELECTOR" >/dev/null; then
  printf 'stale object observation was accepted\n' >&2
  exit 1
fi

rg -F 'SANDBOX_RUNTIME_PROFILE: commodity' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "false"' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_CLASS: commodity' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_PROFILE: commodity' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_RUNTIME_CLASS: commodity' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_DOCKER_MODE: profile-default' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_CONFIDENTIAL_STORAGE_ENABLED: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_CONFIDENTIAL_ADMIN_ONLY: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_INIT_DATA_ENABLED: "true"' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_WORKSPACE_STORAGE_CLASS: longhorn' "$COMMODITY_PROFILE" >/dev/null
rg -F 'SANDBOX_WORKSPACE_STORAGE_CLASS: longhorn' "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_KBS_URL: https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080' \
  "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI: kbs:///default/containers/auth' \
  "$CONFIDENTIAL_PROFILE" >/dev/null
rg -F 'SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI: ""' "$COMMODITY_PROFILE" >/dev/null
rg -F 'COCO_IMAGE_REGISTRY_AUTH_URI="${COCO_IMAGE_REGISTRY_AUTH_URI:-kbs:///default/containers/auth}"' \
  "$SMOKE" >/dev/null
rg -F 'SANDBOX_NAMESPACE="$SANDBOX_NAMESPACE"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI="$COCO_IMAGE_REGISTRY_AUTH_URI"' "$SMOKE" >/dev/null
[[ "$(yq -er '.overhead.podFixed.cpu' "$RUNTIME_PROFILE_DIR/runtime-class-commodity.yaml")" == "250m" ]]
[[ "$(yq -er '.overhead.podFixed.memory' "$RUNTIME_PROFILE_DIR/runtime-class-commodity.yaml")" == "130Mi" ]]
[[ "$(yq -er '.overhead.podFixed.cpu' "$RUNTIME_PROFILE_DIR/runtime-class-confidential.yaml")" == "1" ]]
[[ "$(yq -er '.overhead.podFixed.memory' "$RUNTIME_PROFILE_DIR/runtime-class-confidential.yaml")" == "3968Mi" ]]
rg -F 'COCO_KBS_URL="${COCO_KBS_URL:-https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080}"' \
  "$SMOKE" >/dev/null
if rg -F 'http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080' \
  "$SMOKE" "$CONFIDENTIAL_PROFILE"; then
  printf 'confidential KBS contract must require TLS\n' >&2
  exit 1
fi

rg -F 'confidential-smoke-control.yaml' "$SMOKE_DIR/kustomization.yaml" >/dev/null
rg -F 'confidential-smoke-control.yaml' "$SMOKE_DIR/kustomization.baseline.yaml" >/dev/null
if rg -F 'commodity-smoke-job.yaml' "$SMOKE_DIR/kustomization.confidential-snp.yaml"; then
  printf 'Example Metal confidential activation still dispatches the later Helsinki commodity Job\n' >&2
  exit 1
fi
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
rg -F 'kubernetes.io/hostname: dev-node-1' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'storageClassName: longhorn' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'longhorn-workspace-ok' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'privileged: true' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null
rg -F 'name: codewire-commodity-runtime-smoke-v62' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'name: codewire-confidential-runtime-smoke-v63' "$SMOKE_DIR/confidential-smoke-job.yaml" >/dev/null || {
  printf 'confidential runtime probe generation is not v63\n' >&2
  exit 1
}
rg -F 'name: codewire-confidential-snp-attestation-v63' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null || {
  printf 'confidential attestation probe generation is not v63\n' >&2
  exit 1
}

runtime_probe_image="$(awk '$1 == "image:" { print $2 }' "$SMOKE_DIR/confidential-smoke-job.yaml")"
attestation_probe_image="$(awk '$1 == "image:" { print $2 }' "$SMOKE_DIR/confidential-attestation-job.yaml")"
[[ "$runtime_probe_image" == 'ghcr.io/codewiresh/confidential-probe' ]] || {
  printf 'confidential runtime Job does not select the shared probe image input\n' >&2
  exit 1
}
[[ "$attestation_probe_image" == "$runtime_probe_image" ]] || {
  printf 'confidential runtime and attestation probes do not use one exact image\n' >&2
  exit 1
}
if rg -q 'curl|SNP_GUEST_TOOL_(URL|SHA256)|/tmp/snpguest' \
  "$SMOKE_DIR/confidential-smoke-job.yaml" "$SMOKE_DIR/confidential-attestation-job.yaml"; then
  printf 'confidential probe still downloads its attestation binary at runtime\n' >&2
  exit 1
fi
rg -F '/usr/local/bin/snpguest report' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null
rg -F '/usr/local/bin/snpguest display report' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null

probe_digest_count="$(rg -c '^    digest: sha256:[0-9a-f]{64}$' "$SMOKE_DIR/kustomization.confidential-snp.yaml" || true)"
[[ "$probe_digest_count" == "1" ]] || {
  printf 'confidential activation must declare one immutable probe digest\n' >&2
  exit 1
}
probe_digest="$(awk '$1 == "digest:" { print $2 }' "$SMOKE_DIR/kustomization.confidential-snp.yaml")"
[[ "$probe_digest" != 'sha256:0000000000000000000000000000000000000000000000000000000000000000' ]] || {
  printf 'confidential activation still contains the local digest sentinel\n' >&2
  exit 1
}

runtime_configmap="$({
  jq -n '{
    spec: {template: {spec: {containers: [{envFrom: [
      {configMapRef: {name: "codewire-config-25gbmh4k4h"}},
      {secretRef: {name: "codewire-secrets"}},
      {configMapRef: {name: "codewire-confidential-storage-infisical", optional: true}},
      {configMapRef: {name: "codewire-confidential-storage-kbs", optional: true}}
    ]}]}}}
  }'
} | jq -er -f "$RUNTIME_CONFIGMAP_SELECTOR")"
[[ "$runtime_configmap" == "codewire-config-25gbmh4k4h" ]] || {
  printf 'runtime ConfigMap selector rejected approved optional references\n' >&2
  exit 1
}

[[ "$(yq -er '.spec.template.spec.volumes[] | select(.name == "confidential-storage-kbs-ca") | .configMap.name' "$ORCHESTRATION_DEPLOYMENT")" == "codewire-trustee-kbs-ca" ]] || {
  printf 'orchestration does not mount the dedicated trust-manager KBS CA ConfigMap\n' >&2
  exit 1
}
[[ "$(yq -er '.spec.template.spec.containers[] | select(.name == "orchestration") | .volumeMounts[] | select(.name == "confidential-storage-kbs-ca") | .mountPath' "$ORCHESTRATION_DEPLOYMENT")" == "/etc/codewire/confidential-storage-kbs" ]] || {
  printf 'orchestration KBS CA mount path changed\n' >&2
  exit 1
}

if jq -n '{
  spec: {template: {spec: {containers: [{envFrom: [
    {configMapRef: {name: "codewire-config-25gbmh4k4h"}},
    {configMapRef: {name: "codewire-config-2bcdfghkmt"}}
  ]}]}}}
}' | jq -er -f "$RUNTIME_CONFIGMAP_SELECTOR" >/dev/null 2>&1; then
  printf 'runtime ConfigMap selector accepted two required references\n' >&2
  exit 1
fi

if jq -n '{
  spec: {template: {spec: {containers: [{envFrom: [
    {configMapRef: {name: "codewire-config-25gbmh4k4h", optional: true}}
  ]}]}}}
}' | jq -er -f "$RUNTIME_CONFIGMAP_SELECTOR" >/dev/null 2>&1; then
  printf 'runtime ConfigMap selector accepted an optional-only reference\n' >&2
  exit 1
fi

if jq -n '{
  spec: {template: {spec: {containers: [{envFrom: [
    {configMapRef: {name: "codewire-config-not-generated"}}
  ]}]}}}
}' | jq -er -f "$RUNTIME_CONFIGMAP_SELECTOR" >/dev/null 2>&1; then
  printf 'runtime ConfigMap selector accepted a non-generated name\n' >&2
  exit 1
fi

command -v kustomize >/dev/null 2>&1 || {
  printf 'kustomize is required for the confidential smoke contract\n' >&2
  exit 1
}
kustomize build "$SMOKE_DIR" >/dev/null
kustomize build "$ROOT/deployments/k8s/overlays/dev" >/dev/null

activation_dir="$(mktemp -d)"
trap 'rm -rf "$activation_dir"' EXIT
cp "$SMOKE_DIR"/*.yaml "$activation_dir/"
cp "$SMOKE_DIR/kustomization.confidential-snp.yaml" "$activation_dir/kustomization.yaml"
kustomize build "$activation_dir" >"$activation_dir/rendered.yaml"
mapfile -t rendered_probe_images < <(
  awk '$1 == "image:" && $2 ~ /^ghcr\.io\/codewiresh\/confidential-probe@sha256:/ { print $2 }' \
    "$activation_dir/rendered.yaml"
)
[[ "${#rendered_probe_images[@]}" == "2" ]] || {
  printf 'confidential activation did not render exactly two pinned probe images\n' >&2
  exit 1
}
[[ "${rendered_probe_images[0]}" == "${rendered_probe_images[1]}" ]] || {
  printf 'confidential activation rendered different runtime and attestation probes\n' >&2
  exit 1
}
rm -rf "$activation_dir"
trap - EXIT

mkdir -p "$ROOT/.tmp"
bootstrap_dir="$(mktemp -d "$ROOT/.tmp/codewire-confidential-bootstrap-contract.XXXXXX")"
trap 'rm -rf "$bootstrap_dir"' EXIT
mkdir -p "$bootstrap_dir/bin" "$bootstrap_dir/evidence"
cat >"$bootstrap_dir/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--context" ]]; then
  shift 2
fi
case "$*" in
  'get runtimeclass commodity confidential -o json')
    if [[ "${RUNTIMECLASS_OVERHEAD_FIXTURE:-valid}" == "missing" ]]; then
      jq -n '{items: [
        {metadata: {name: "commodity"}, handler: "kata-clh"},
        {metadata: {name: "confidential"}, handler: "kata-qemu-snp", scheduling: {nodeSelector: {"node.codewire.sh/confidential-snp": "true"}}}
      ]}'
    else
      confidential_memory=3968Mi
      if [[ "${RUNTIMECLASS_OVERHEAD_FIXTURE:-valid}" == "legacy-confidential" ]]; then
        confidential_memory=2Gi
      fi
      jq -n --arg confidential_memory "$confidential_memory" '{items: [
        {metadata: {name: "commodity"}, handler: "kata-clh", overhead: {podFixed: {cpu: "250m", memory: "130Mi"}}},
        {metadata: {name: "confidential"}, handler: "kata-qemu-snp", overhead: {podFixed: {cpu: "1", memory: $confidential_memory}}, scheduling: {nodeSelector: {"node.codewire.sh/confidential-snp": "true"}}}
      ]}'
    fi
    ;;
  'get runtimeclass commodity confidential -o yaml')
    printf '%s\n' 'items: []'
    ;;
  'get node cw-dev-prod-node-1 -o json')
    jq -n '{metadata: {labels: {
      "katacontainers.io/kata-runtime": "true",
      "node.codewire.sh/runtime-candidate": "true",
      "node.codewire.sh/confidential-snp": "true"
    }}, status: {conditions: [{type: "Ready", status: "True"}]}}'
    ;;
  'get namespace codewire-runtime-probes -o json')
    jq -n '{metadata: {labels: {"pod-security.kubernetes.io/enforce": "privileged"}}}'
    ;;
  '-n flux-system get kustomization codewire-deploy-workloads-dev -o json'|\
  '-n flux-system get kustomization codewire-deploy-confidential-smoke-dev -o json')
    name="${5}"
    jq -n --arg name "$name" --arg source 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' '{
      metadata: {name: $name, generation: 4, annotations: {"deploy.codewire.sh/source-sha": $source}},
      status: {
        observedGeneration: 4,
        lastAppliedRevision: ("main@sha1:" + $source),
        conditions: [{type: "Ready", status: "True", observedGeneration: 4}]
      }
    }'
    ;;
  '-n codewire-runtime-probes get configmap codewire-confidential-snp-smoke-control -o json')
    jq -n '{data: {phase: "confidential-snp"}}'
    ;;
  *)
    printf 'unexpected mock kubectl arguments: %s\n' "$*" >&2
    exit 70
    ;;
esac
EOF
cat >"$bootstrap_dir/bin/skopeo" <<EOF
#!/usr/bin/env bash
touch '$bootstrap_dir/skopeo-was-called'
exit 88
EOF
chmod +x "$bootstrap_dir/bin/kubectl" "$bootstrap_dir/bin/skopeo"
PATH="$bootstrap_dir/bin:$PATH" \
  KUBECTL_BIN="$bootstrap_dir/bin/kubectl" \
  KUBE_CONTEXT=mock \
  EVIDENCE_DIR="$bootstrap_dir/evidence" \
  "$SMOKE" --skip-host-gate --skip-raw-jobs --skip-guest-attestation --skip-coco \
  >"$bootstrap_dir/stdout" 2>"$bootstrap_dir/stderr" || {
    sed -n '1,120p' "$bootstrap_dir/stderr" >&2
    printf 'bootstrap-only smoke fixture failed\n' >&2
    exit 1
  }
[[ ! -e "$bootstrap_dir/skopeo-was-called" ]] || {
  printf 'bootstrap-only smoke unexpectedly resolved product images\n' >&2
  exit 1
}
rg -F 'skipping product release image resolution' "$bootstrap_dir/stderr" >/dev/null

mkdir -p "$bootstrap_dir/missing-overhead-evidence"
if PATH="$bootstrap_dir/bin:$PATH" \
  KUBECTL_BIN="$bootstrap_dir/bin/kubectl" \
  KUBE_CONTEXT=mock \
  EVIDENCE_DIR="$bootstrap_dir/missing-overhead-evidence" \
  RUNTIMECLASS_OVERHEAD_FIXTURE=missing \
  "$SMOKE" --skip-host-gate --skip-raw-jobs --skip-guest-attestation --skip-coco \
  >"$bootstrap_dir/missing-overhead.stdout" 2>"$bootstrap_dir/missing-overhead.stderr"; then
  printf 'bootstrap-only smoke accepted missing RuntimeClass overhead\n' >&2
  exit 1
fi
rg -F 'RuntimeClass/commodity pod overhead is not the kata-clh contract' \
  "$bootstrap_dir/missing-overhead.stderr" >/dev/null

mkdir -p "$bootstrap_dir/legacy-confidential-overhead-evidence"
if PATH="$bootstrap_dir/bin:$PATH" \
  KUBECTL_BIN="$bootstrap_dir/bin/kubectl" \
  KUBE_CONTEXT=mock \
  EVIDENCE_DIR="$bootstrap_dir/legacy-confidential-overhead-evidence" \
  RUNTIMECLASS_OVERHEAD_FIXTURE=legacy-confidential \
  "$SMOKE" --skip-host-gate --skip-raw-jobs --skip-guest-attestation --skip-coco \
  >"$bootstrap_dir/legacy-confidential-overhead.stdout" \
  2>"$bootstrap_dir/legacy-confidential-overhead.stderr"; then
  printf 'bootstrap-only smoke accepted the legacy confidential RuntimeClass overhead\n' >&2
  exit 1
fi
rg -F 'RuntimeClass/confidential pod overhead is not the kata-qemu-snp contract' \
  "$bootstrap_dir/legacy-confidential-overhead.stderr" >/dev/null
rm -rf "$bootstrap_dir"
trap - EXIT

"$ROOT/scripts/runtime/confidential/tests/test-smoke-dev-private-image-pull.sh"

printf 'Confidential SNP GitOps smoke contract tests passed\n'
