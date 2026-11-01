#!/usr/bin/env bash
set -euo pipefail
export CONFIDENTIAL_SNP_NODE=example-node-1
export CODEWIRE_DEV_CLUSTER=example-dev-cluster

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/confidential/smoke-dev-confidential-snp.sh"
RUNTIME_CONFIGMAP_SELECTOR="$ROOT/scripts/runtime/confidential/select-required-runtime-configmap.jq"
READY_CURRENT_SELECTOR="$ROOT/scripts/runtime/confidential/select-ready-current.jq"
RESOLVER="$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh"
PROBE_POLICY_GENERATOR="$ROOT/scripts/runtime/confidential/generate-confidential-probe-initdata.sh"
GENPOLICY_RUNTIME_CONTRACT="$ROOT/deployments/k8s/runtime-profiles/policy/genpolicy-runtime-contract.json"
WRAPPER="$ROOT/scripts/runtime/confidential/with-dev-confidential-coco-config.sh"
SMOKE_DIR="$ROOT/deployments/k8s/runtime-profiles/confidential-smoke"
RUNTIME_PROFILE_DIR="$ROOT/deployments/k8s/runtime-profiles/base"
ORCHESTRATION_DEPLOYMENT="$ROOT/deployments/k8s/orchestration/deployment.yaml"

# The active Dev runtime profile and its templates live in codewire/deploy
# hosted/; its README owns the two-repository activation, and its hosted guards
# check the profile. This repository keeps the smoke Kustomization templates.
if ! cmp -s "$SMOKE_DIR/kustomization.yaml" "$SMOKE_DIR/kustomization.baseline.yaml" &&
  ! cmp -s "$SMOKE_DIR/kustomization.yaml" "$SMOKE_DIR/kustomization.confidential-snp.yaml"; then
  printf 'active confidential smoke Kustomization is not an approved source template\n' >&2
  exit 1
fi

bash -n "$SMOKE"
bash -n "$RESOLVER"
bash -n "$PROBE_POLICY_GENERATOR"
[[ ! -e "$WRAPPER" ]] || {
  printf 'imperative confidential ConfigMap wrapper still exists\n' >&2
  exit 1
}

mkdir -p "$ROOT/.tmp"
validation_dir="$(mktemp -d "$ROOT/.tmp/confidential-smoke-validation.XXXXXX")"
if "$SMOKE" --existing-env not-a-uuid >"$validation_dir/uuid.out" 2>"$validation_dir/uuid.err"; then
  printf 'confidential smoke accepted a malformed retained environment ID\n' >&2
  exit 1
fi
rg -F -- '--existing-env requires a lowercase UUID' "$validation_dir/uuid.err" >/dev/null
if "$SMOKE" --skip-coco --keep-product >"$validation_dir/keep.out" 2>"$validation_dir/keep.err"; then
  printf 'confidential smoke accepted retention without a product smoke\n' >&2
  exit 1
fi
rg -F -- '--keep-product requires the Codewire product smoke' "$validation_dir/keep.err" >/dev/null
# The Dev cluster binding comes from the operator environment, never source.
if env -u CODEWIRE_DEV_CLUSTER "$SMOKE" --help >"$validation_dir/cluster.out" 2>"$validation_dir/cluster.err"; then
  printf 'confidential smoke ran without a Dev cluster binding\n' >&2
  exit 1
fi
rg -F 'set CODEWIRE_DEV_CLUSTER to the Dev cluster name' "$validation_dir/cluster.err" >/dev/null
rm -rf "$validation_dir"

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
rg -F 'DEV_CLUSTER="${CODEWIRE_DEV_CLUSTER:?set CODEWIRE_DEV_CLUSTER to the Dev cluster name}"' "$SMOKE" >/dev/null
rg -F 'KUBE_CONTEXT="${KUBE_CONTEXT:-$DEV_CLUSTER}"' "$SMOKE" >/dev/null
rg -F 'SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"' "$SMOKE" >/dev/null
rg -F 'NODE="${CONFIDENTIAL_SNP_NODE:?set CONFIDENTIAL_SNP_NODE to the Dev confidential node}"' "$SMOKE" >/dev/null
rg -F './scripts/talos-external-worker verify' "$SMOKE" >/dev/null
rg -F './scripts/check-talos-runtime-artifacts --stack "$HOST_GATE_STACK"' "$SMOKE" >/dev/null
rg -F 'confidential profile isolation passed: shared_fs=none host-share-overrides=denied' \
  "$SMOKE" >/dev/null
if rg -q 'check-node1|node1-codewire-dev|node1\.codewire-dev\.sh|ssh_host\(' "$SMOKE"; then
  printf 'confidential smoke contains a nonexistent Ubuntu/SSH host gate\n' >&2
  exit 1
fi
rg -F 'COMMODITY_JOB_SELECTOR="app.kubernetes.io/name=codewire-commodity-runtime-smoke"' "$SMOKE" >/dev/null
rg -F 'record_job "$commodity_job" commodity "$NODE" linstor-local' "$SMOKE" >/dev/null
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
rg -F '[[ "$image" =~ ^"$CODEWIRE_IMAGE_REGISTRY"/codewire/daemon@sha256:[0-9a-f]{64}$ ]]' "$SMOKE" >/dev/null
rg -F '[[ "$DAEMON_IMAGE" =~ ^"$registry"/codewire/daemon@sha256:[0-9a-f]{64}$ ]]' "$RESOLVER" >/dev/null
rg -F 'restore the commodity Dev profile in codewire/deploy' "$SMOKE" >/dev/null
rg -F '"$ROOT/scripts/runtime/dev/with-dev-smoke-auth.sh" -- \' "$SMOKE" >/dev/null
if rg -F -- '--admin-oidc' "$SMOKE"; then
  printf 'the confidential product smoke runs as the smoke identity, not an admin login\n' >&2
  exit 1
fi
if rg -F 'SANDBOX_CONFIDENTIAL_ADMIN_ONLY' "$SMOKE"; then
  printf 'the confidential smoke still asserts the removed admin-only setting\n' >&2
  exit 1
fi
rg -F 'CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_CODEWIRE_DEV_SERVER_URL="$EXPECTED_CODEWIRE_DEV_SERVER_URL"' "$SMOKE" >/dev/null
rg -F 'CODEWIRE_SERVER_NAMESPACE="$CODEWIRE_SERVER_NAMESPACE"' "$SMOKE" >/dev/null
rg -F 'KUBE_CONTEXT="$KUBE_CONTEXT"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_STUN_HOST="$COCO_GATEWAY_STUN_HOST"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_STUN_PORT="$COCO_GATEWAY_STUN_PORT"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_TAILNET_DIRECT_UDP_LB_IP="$COCO_DIRECT_UDP_LB_IP"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="$COCO_DIRECT_UDP_TRANSPORT_ZONE"' "$SMOKE" >/dev/null
rg -F 'SMOKE_IMAGE="${SMOKE_IMAGE:-$COCO_WORKSPACE_IMAGE}"' "$SMOKE" >/dev/null
rg -F 'SMOKE_ARTIFACT_DIR="$EVIDENCE_DIR/product"' "$SMOKE" >/dev/null
rg -F 'smoke_args+=(--existing-env "$COCO_EXISTING_ENV_ID")' "$SMOKE" >/dev/null
rg -F 'smoke_args+=(--keep)' "$SMOKE" >/dev/null
if rg -F 'smoke_args=(--image ' "$SMOKE"; then
  printf 'confidential smoke passes an unsupported image CLI option\n' >&2
  exit 1
fi
rg -F 'SMOKE_ISOLATION_TIER=confidential' "$SMOKE" >/dev/null
rg -F -- '--daemon-image' "$RESOLVER" >/dev/null
rg -F -- '--source-sha' "$RESOLVER" >/dev/null

forward_dir="$(mktemp -d "$ROOT/.tmp/confidential-smoke-forwarding.XXXXXX")"
mkdir -p "$forward_dir/root/scripts/runtime/dev"
cat >"$forward_dir/root/scripts/runtime/dev/smoke-dev-commodity.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'server_namespace=%s\n' "${CODEWIRE_SERVER_NAMESPACE:-}"
  printf 'kube_context=%s\n' "${KUBE_CONTEXT:-}"
  printf 'stun_host=%s\n' "${EXPECTED_STUN_HOST:-}"
  printf 'stun_port=%s\n' "${EXPECTED_STUN_PORT:-}"
  printf 'direct_udp_ip=%s\n' "${EXPECTED_TAILNET_DIRECT_UDP_LB_IP:-}"
  printf 'transport_zone=%s\n' "${EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE:-}"
  printf 'artifact_dir=%s\n' "$(basename "${SMOKE_ARTIFACT_DIR:-}")"
  printf 'wrapped=%s\n' "${FORWARD_WRAPPED:-}"
  printf 'args=%s\n' "$*"
} >"${FORWARD_CAPTURE:?}"
EOF
chmod 0755 "$forward_dir/root/scripts/runtime/dev/smoke-dev-commodity.sh"
# The smoke identity wrapper: records that it ran, then execs its command.
cat >"$forward_dir/root/scripts/runtime/dev/with-dev-smoke-auth.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "--" ]] && shift
export FORWARD_WRAPPED=smoke-identity
exec "$@"
EOF
chmod 0755 "$forward_dir/root/scripts/runtime/dev/with-dev-smoke-auth.sh"
mkdir -p "$forward_dir/evidence"
(
  export EVIDENCE_DIR="$forward_dir/evidence"
  # This fixture imports functions only; product resolution has its own fake
  # Skopeo fixture below and must not depend on a host-installed binary.
  export RUN_COCO_PRODUCT=0
  # shellcheck disable=SC1090
  source <(sed '$d' "$SMOKE")
  ROOT="$forward_dir/root"
  export CODEWIRE_SERVER_NAMESPACE=contract-server
  export SANDBOX_NAMESPACE=contract-sandboxes
  export KUBE_CONTEXT=contract-context
  export COCO_DAEMON_IMAGE=example.invalid/daemon@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export COCO_WORKSPACE_IMAGE=example.invalid/workspace@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  export COCO_DIND_IMAGE=example.invalid/dind@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  export COCO_GATEWAY_STUN_HOST=stun.example.invalid
  export COCO_GATEWAY_STUN_PORT=3478
  export COCO_DIRECT_UDP_LB_IP=192.0.2.20
  export COCO_DIRECT_UDP_TRANSPORT_ZONE=contract-zone
  export COCO_FULL_PRODUCT=1
  export COCO_KEEP_PRODUCT=1
  export COCO_EXISTING_ENV_ID=11111111-2222-4333-8444-555555555555
  FORWARD_CAPTURE="$forward_dir/capture" run_product_command
)
cat >"$forward_dir/expected" <<'EOF'
server_namespace=contract-server
kube_context=contract-context
stun_host=stun.example.invalid
stun_port=3478
direct_udp_ip=192.0.2.20
transport_zone=contract-zone
artifact_dir=product
wrapped=smoke-identity
args=--existing-env 11111111-2222-4333-8444-555555555555 --keep
EOF
cmp "$forward_dir/expected" "$forward_dir/capture"
rm -rf "$forward_dir"


# B2c lifted the confidential refusal: the product phase runs, never skips.
if rg -F 'PENDING_B2C' "$SMOKE" >/dev/null || rg -F 'exit 77' "$SMOKE" >/dev/null; then
  echo "confidential SNP smoke still skips its product phase" >&2
  exit 1
fi

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

if rg -F 'SANDBOX_RUNTIME_CLASS' \
  "$ROOT/deployments/k8s/base/config.env" \
  "$ROOT/deployments/k8s/overlays/local-kind/configmap-patch.yaml" \
  "$ROOT/deployments/k8s/overlays/local-kind-static/configmap-patch.yaml" >/dev/null; then
  printf 'active deployment config still exposes the removed runtime-class selector\n' >&2
  exit 1
fi
rg -F 'COCO_IMAGE_REGISTRY_AUTH_URI="${COCO_IMAGE_REGISTRY_AUTH_URI:-kbs:///default/containers/auth}"' \
  "$SMOKE" >/dev/null
rg -F 'SANDBOX_NAMESPACE="$SANDBOX_NAMESPACE"' "$SMOKE" >/dev/null
rg -F 'EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI="$COCO_IMAGE_REGISTRY_AUTH_URI"' "$SMOKE" >/dev/null
[[ "$(yq -er '.overhead.podFixed.cpu' "$RUNTIME_PROFILE_DIR/runtime-class-commodity.yaml")" == "250m" ]]
[[ "$(yq -er '.overhead.podFixed.memory' "$RUNTIME_PROFILE_DIR/runtime-class-commodity.yaml")" == "1536Mi" ]]
[[ "$(yq -er '.overhead.podFixed.cpu' "$RUNTIME_PROFILE_DIR/runtime-class-confidential.yaml")" == "1" ]]
[[ "$(yq -er '.overhead.podFixed.memory' "$RUNTIME_PROFILE_DIR/runtime-class-confidential.yaml")" == "3968Mi" ]]
rg -F 'COCO_KBS_URL="${COCO_KBS_URL:-https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080}"' \
  "$SMOKE" >/dev/null
if rg -F 'http://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080' \
  "$SMOKE"; then
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
rg -F 'kubernetes.io/hostname: example-node-1' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'storageClassName: linstor-local' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F 'linstor-workspace-ok' "$SMOKE_DIR/commodity-smoke-job.yaml" >/dev/null
rg -F '.data.SANDBOX_CONFIDENTIAL_WORKSPACE_STORAGE_CLASS == "linstor-confidential"' "$SMOKE" >/dev/null
rg -F 'privileged: true' "$SMOKE_DIR/confidential-attestation-job.yaml" >/dev/null
[[ "$(yq -er '.spec.template.spec.securityContext.supplementalGroups' "$SMOKE_DIR/confidential-smoke-job.yaml" -o=json -I=0)" == '[0]' ]] || {
  printf 'confidential runtime probe does not declare its measured guest-pull groups\n' >&2
  exit 1
}
[[ "$(yq -er '.spec.template.spec.securityContext.supplementalGroups' "$SMOKE_DIR/confidential-attestation-job.yaml" -o=json -I=0)" == '[10]' ]] || {
  printf 'confidential attestation probe does not declare its measured guest-pull groups\n' >&2
  exit 1
}
commodity_job_name="$(yq -er '.metadata.name' "$SMOKE_DIR/commodity-smoke-job.yaml")"
[[ "$commodity_job_name" =~ ^codewire-commodity-runtime-smoke-(v[1-9][0-9]*)$ ]] || {
  printf 'commodity runtime probe name has an invalid generation\n' >&2
  exit 1
}
probe_generation="${BASH_REMATCH[1]}"
[[ "$(yq -er '.metadata.name' "$SMOKE_DIR/confidential-smoke-job.yaml")" == \
  "codewire-confidential-runtime-smoke-$probe_generation" ]] || {
  printf 'confidential runtime probe generation does not match the commodity probe\n' >&2
  exit 1
}
[[ "$(yq -er '.metadata.name' "$SMOKE_DIR/confidential-attestation-job.yaml")" == \
  "codewire-confidential-snp-attestation-$probe_generation" ]] || {
  printf 'confidential attestation probe generation does not match the commodity probe\n' >&2
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

annotation_key='io.katacontainers.config.hypervisor.cc_init_data'
[[ "$(jq -er '.schemaVersion' "$GENPOLICY_RUNTIME_CONTRACT")" == 2 ]]
expected_oci_version="$(jq -er '.ociVersion' "$GENPOLICY_RUNTIME_CONTRACT")"
[[ "$expected_oci_version" == '1.3.0' ]] || {
  printf 'static probes no longer target the live containerd OCI request version\n' >&2
  exit 1
}
[[ "$(jq -er '.privilegedCapabilities.provider' "$GENPOLICY_RUNTIME_CONTRACT")" == talos ]] || {
  printf 'static probes no longer model the Talos privileged capability boundary\n' >&2
  exit 1
}
[[ "$(jq -er '.privilegedCapabilities.sourceCommit' "$GENPOLICY_RUNTIME_CONTRACT")" == \
    '47fcdfcc13fd72b45715853736a1cd6dd31e051e' ]] || {
  printf 'static probes no longer bind the accepted Talos capability source\n' >&2
  exit 1
}
expected_dropped_privileged_caps="$(
  jq -cer '.privilegedCapabilities.drop | sort' "$GENPOLICY_RUNTIME_CONTRACT"
)"
[[ "$expected_dropped_privileged_caps" == '["CAP_SYS_BOOT","CAP_SYS_MODULE"]' ]] || {
  printf 'static probes no longer drop Talos-ungrantable privileged capabilities\n' >&2
  exit 1
}
initdata_dir="$(mktemp -d)"
validate_policy_oci_version() {
  local policy="$1"
  local expected="$2"
  local versions

  versions="$(
    rg -o '\"Version\": \"[^\"]+\"' "$policy" |
      sed -E 's/^\"Version\": \"([^\"]+)\"$/\1/' |
      sort -u
  )"
  [[ "$versions" == "$expected" ]]
}
validate_policy_privileged_caps() {
  local policy="$1"
  local capabilities

  capabilities="$(
    sed -n '/^policy_data := /,$p' "$policy" |
      sed '1s/^policy_data := //' |
      jq -ce '.common.privileged_caps'
  )" || return 1
  jq -en \
    --argjson capabilities "$capabilities" \
    --argjson dropped "$expected_dropped_privileged_caps" \
    '$capabilities | length == 39 and length == (unique | length) and
     index("CAP_MKNOD") != null and ($dropped - .) == $dropped' >/dev/null
}
validate_policy_stream_contract() {
  local policy="$1"
  local request_defaults

  rg -Fx 'default ReadStreamRequest := false' "$policy" >/dev/null || return 1
  request_defaults="$(
    sed -n '/^policy_data := /,$p' "$policy" |
      sed '1s/^policy_data := //' |
      jq -ce '.request_defaults | {ReadStreamRequest, WriteStreamRequest, CloseStdinRequest}'
  )" || return 1
  [[ "$request_defaults" == \
    '{"ReadStreamRequest":true,"WriteStreamRequest":false,"CloseStdinRequest":false}' ]]
}
validate_policy_sandbox_name() {
  local policy="$1"
  local manifest="$2"
  local job_name expected sandbox_names

  job_name="$(yq -er '.metadata.name' "$manifest")" || return 1
  expected="^${job_name}(-[0-9]+)?-[bcdfghjklmnpqrstvwxz2456789]+$"
  sandbox_names="$(
    sed -n '/^policy_data := /,$p' "$policy" |
      sed '1s/^policy_data := //' |
      jq -er '.. | objects | .["io.kubernetes.cri.sandbox-name"]? // empty' |
      sort -u
  )" || return 1
  [[ "$sandbox_names" == "$expected" ]]
}
validate_probe_initdata() {
  local manifest="$1"
  local container_name="$2"
  local encoded decoded policy

  encoded="$(yq -er ".spec.template.metadata.annotations.\"$annotation_key\"" "$manifest")" || return 1
  [[ -n "$encoded" && "${#encoded}" -le 65536 ]] || return 1
  decoded="$initdata_dir/$(basename "$manifest").toml"
  policy="$initdata_dir/$(basename "$manifest").rego"
  printf '%s' "$encoded" | base64 -d | gzip -dc >"$decoded" 2>/dev/null || return 1
  yq -p=toml -oy -e \
    '.version == "0.1.0" and .algorithm == "sha256" and
     (.data | has("policy.rego")) and (.data | length == 1)' \
    "$decoded" >/dev/null || return 1
  yq -p=toml -oy -er '.data."policy.rego"' "$decoded" >"$policy" || return 1
  rg -Fx 'package agent_policy' "$policy" >/dev/null || return 1
  rg -F "$probe_digest" "$policy" >/dev/null || return 1
  rg -F "\"$container_name\"" "$policy" >/dev/null || return 1
  validate_policy_sandbox_name "$policy" "$manifest" || return 1
  validate_policy_oci_version "$policy" "$expected_oci_version" || return 1
  validate_policy_privileged_caps "$policy" || return 1
  validate_policy_stream_contract "$policy" || return 1
}

validate_probe_initdata "$SMOKE_DIR/confidential-smoke-job.yaml" smoke || {
  printf 'confidential runtime probe Init-Data is absent, malformed, or stale\n' >&2
  exit 1
}
validate_probe_initdata "$SMOKE_DIR/confidential-attestation-job.yaml" attest || {
  printf 'confidential attestation probe Init-Data is absent, malformed, or stale\n' >&2
  exit 1
}

wrong_oci_policy="$initdata_dir/wrong-oci-version.rego"
cp "$initdata_dir/confidential-smoke-job.yaml.rego" "$wrong_oci_policy"
sed -i '0,/\"Version\": \"1\.3\.0\"/s//\"Version\": \"1.1.0\"/' "$wrong_oci_policy"
if validate_policy_oci_version "$wrong_oci_policy" "$expected_oci_version"; then
  printf 'confidential probe contract accepted the rejected OCI 1.1.0 policy version\n' >&2
  exit 1
fi

for invalid_stream_case in read-denied write-enabled close-enabled; do
  invalid_stream_policy="$initdata_dir/$invalid_stream_case.rego"
  case "$invalid_stream_case" in
    read-denied)
      request_defaults='{"ReadStreamRequest":false,"WriteStreamRequest":false,"CloseStdinRequest":false}'
      ;;
    write-enabled)
      request_defaults='{"ReadStreamRequest":true,"WriteStreamRequest":true,"CloseStdinRequest":false}'
      ;;
    close-enabled)
      request_defaults='{"ReadStreamRequest":true,"WriteStreamRequest":false,"CloseStdinRequest":true}'
      ;;
  esac
  printf 'default ReadStreamRequest := false\npolicy_data := {"request_defaults":%s}\n' \
    "$request_defaults" >"$invalid_stream_policy"
  if validate_policy_stream_contract "$invalid_stream_policy"; then
    printf 'confidential probe contract accepted invalid stream policy: %s\n' \
      "$invalid_stream_case" >&2
    exit 1
  fi
done

missing_initdata="$initdata_dir/missing.yaml"
malformed_initdata="$initdata_dir/malformed.yaml"
wrong_generation_initdata="$initdata_dir/wrong-generation.yaml"
cp "$SMOKE_DIR/confidential-smoke-job.yaml" "$missing_initdata"
cp "$SMOKE_DIR/confidential-smoke-job.yaml" "$malformed_initdata"
cp "$SMOKE_DIR/confidential-smoke-job.yaml" "$wrong_generation_initdata"
yq -i "del(.spec.template.metadata.annotations.\"$annotation_key\")" "$missing_initdata"
yq -i ".spec.template.metadata.annotations.\"$annotation_key\" = \"not-gzip-base64\"" "$malformed_initdata"
yq -i '.metadata.name = "codewire-confidential-runtime-smoke-v999"' "$wrong_generation_initdata"
if validate_probe_initdata "$missing_initdata" smoke 2>/dev/null; then
  printf 'confidential probe contract accepted missing Init-Data\n' >&2
  exit 1
fi
if validate_probe_initdata "$malformed_initdata" smoke 2>/dev/null; then
  printf 'confidential probe contract accepted malformed Init-Data\n' >&2
  exit 1
fi
if validate_probe_initdata "$wrong_generation_initdata" smoke 2>/dev/null; then
  printf 'confidential probe contract accepted a Job generation absent from its measured policy\n' >&2
  exit 1
fi
rm -rf "$initdata_dir"

rg -F "EXPECTED_KATA_COMMIT='6078fea77c84cb18563cdc6bafff9fd5fda09ab3'" \
  "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F 'genpolicy reports $embedded_commit, but Kata source is $kata_head' \
  "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F 'DOCKER_CONFIG="$workdir/docker-config"' "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F 'genpolicy-runtime-contract.json' "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F 'drop-in-examples/$settings_drop_in_name' "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F '30-talos-privileged-capabilities.json' "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F '40-probe-read-stream.json' "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F '/request_defaults/ReadStreamRequest' "$PROBE_POLICY_GENERATOR" >/dev/null
rg -F 'all Job names and Init-Data updated' "$PROBE_POLICY_GENERATOR" >/dev/null

runtime_configmap="$({
  jq -n '{
    spec: {template: {spec: {containers: [{envFrom: [
      {configMapRef: {name: "codewire-config-25gbmh4k4h"}},
      {secretRef: {name: "codewire-secrets"}},
      {configMapRef: {name: "codewire-confidential-storage-openbao", optional: true}},
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
        {metadata: {name: "commodity"}, handler: "kata-clh", overhead: {podFixed: {cpu: "250m", memory: "1536Mi"}}},
        {metadata: {name: "confidential"}, handler: "kata-qemu-snp", overhead: {podFixed: {cpu: "1", memory: $confidential_memory}}, scheduling: {nodeSelector: {"node.codewire.sh/confidential-snp": "true"}}}
      ]}'
    fi
    ;;
  'get runtimeclass commodity confidential -o yaml')
    printf '%s\n' 'items: []'
    ;;
  'get node example-node-1 -o json')
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
    # The workload child reads the deploy repository's hosted tree, so its
    # applied revision is a deploy commit; the smoke child reads the source.
    if [[ "$name" == codewire-deploy-workloads-dev ]]; then
      repository=codewire-hosted-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      applied="main@sha1:${FLUX_HOSTED_APPLIED:-dddddddddddddddddddddddddddddddddddddddd}"
    else
      repository=codewire-source-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      applied=main@sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    fi
    jq -n --arg name "$name" --arg source 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
      --arg repository "$repository" --arg applied "$applied" '{
      metadata: {name: $name, generation: 4, annotations: {"deploy.codewire.sh/source-sha": $source}},
      spec: {sourceRef: {kind: "GitRepository", name: $repository}},
      status: {
        observedGeneration: 4,
        lastAppliedRevision: $applied,
        conditions: [{type: "Ready", status: "True", observedGeneration: 4}]
      }
    }'
    ;;
  "-n flux-system get gitrepository codewire-hosted-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -o jsonpath={.status.artifact.revision}")
    printf '%s' main@sha1:dddddddddddddddddddddddddddddddddddddddd
    ;;
  "-n flux-system get gitrepository codewire-source-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -o jsonpath={.status.artifact.revision}")
    printf '%s' main@sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
mkdir -p "$bootstrap_dir/infra/scripts"
cat >"$bootstrap_dir/infra/scripts/check-talos-runtime-artifacts" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == '--stack example-dev-cluster' ]]
if [[ -n "${HOST_ARTIFACTS_CALLS:-}" ]]; then
  printf '%s\n' "$*" >>"$HOST_ARTIFACTS_CALLS"
fi
if [[ "${HOST_PROFILE_FIXTURE:-none}" == "none" ]]; then
  printf '%s\n' \
    'check-talos-runtime-artifacts: confidential profile isolation passed: shared_fs=none host-share-overrides=denied'
else
  printf 'check-talos-runtime-artifacts: unsafe fixture shared_fs=%s\n' \
    "$HOST_PROFILE_FIXTURE"
fi
EOF
cat >"$bootstrap_dir/infra/scripts/talos-external-worker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'verify example-dev-cluster example-node-1 1500' ]]
if [[ -n "${HOST_WORKER_CALLS:-}" ]]; then
  printf '%s\n' "$*" >>"$HOST_WORKER_CALLS"
fi
printf '%s\n' 'talos-external-worker: PASS'
EOF
chmod +x \
  "$bootstrap_dir/bin/kubectl" \
  "$bootstrap_dir/bin/skopeo" \
  "$bootstrap_dir/infra/scripts/check-talos-runtime-artifacts" \
  "$bootstrap_dir/infra/scripts/talos-external-worker"
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
# A hosted child that has not applied its GitRepository's artifact is refused.
if PATH="$bootstrap_dir/bin:$PATH" \
  KUBECTL_BIN="$bootstrap_dir/bin/kubectl" \
  KUBE_CONTEXT=mock \
  FLUX_HOSTED_APPLIED=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  EVIDENCE_DIR="$bootstrap_dir/stale-evidence" \
  "$SMOKE" --skip-host-gate --skip-raw-jobs --skip-guest-attestation --skip-coco \
  >"$bootstrap_dir/stale.stdout" 2>"$bootstrap_dir/stale.stderr"; then
  printf 'the smoke accepted a workload child behind its hosted source\n' >&2
  exit 1
fi
rg -F 'codewire-deploy-workloads-dev did not apply source' "$bootstrap_dir/stale.stderr" >/dev/null || {
  sed -n '1,40p' "$bootstrap_dir/stale.stderr" >&2
  printf 'the stale hosted child failed for another reason\n' >&2
  exit 1
}
[[ ! -e "$bootstrap_dir/skopeo-was-called" ]] || {
  printf 'bootstrap-only smoke unexpectedly resolved product images\n' >&2
  exit 1
}
rg -F 'skipping product release image resolution' "$bootstrap_dir/stderr" >/dev/null

mkdir -p "$bootstrap_dir/host-gate-evidence"
PATH="$bootstrap_dir/bin:$PATH" \
  KUBECTL_BIN="$bootstrap_dir/bin/kubectl" \
  KUBE_CONTEXT=mock \
  INFRA_ROOT="$bootstrap_dir/infra" \
  EVIDENCE_DIR="$bootstrap_dir/host-gate-evidence" \
  HOST_ARTIFACTS_CALLS="$bootstrap_dir/host-artifacts.calls" \
  HOST_WORKER_CALLS="$bootstrap_dir/host-worker.calls" \
  "$SMOKE" --skip-raw-jobs --skip-guest-attestation --skip-coco \
  >"$bootstrap_dir/host-gate.stdout" 2>"$bootstrap_dir/host-gate.stderr" || {
    sed -n '1,120p' "$bootstrap_dir/host-gate.stderr" >&2
    printf 'host-profile receipt fixture failed\n' >&2
    exit 1
  }
rg -Fx \
  'check-talos-runtime-artifacts: confidential profile isolation passed: shared_fs=none host-share-overrides=denied' \
  "$bootstrap_dir/host-gate-evidence/host-runtime-gate.log" >/dev/null
rg -Fx -- '--stack example-dev-cluster' "$bootstrap_dir/host-artifacts.calls" >/dev/null
rg -Fx -- 'verify example-dev-cluster example-node-1 1500' \
  "$bootstrap_dir/host-worker.calls" >/dev/null

for unsafe_shared_fs in \
  missing \
  virtio-fs \
  inline-virtio-fs \
  virtio-fs-nydus \
  9p \
  passthrough; do
  mkdir -p "$bootstrap_dir/unsafe-$unsafe_shared_fs-evidence"
  if PATH="$bootstrap_dir/bin:$PATH" \
    KUBECTL_BIN="$bootstrap_dir/bin/kubectl" \
    KUBE_CONTEXT=mock \
    INFRA_ROOT="$bootstrap_dir/infra" \
    EVIDENCE_DIR="$bootstrap_dir/unsafe-$unsafe_shared_fs-evidence" \
    HOST_PROFILE_FIXTURE="$unsafe_shared_fs" \
    "$SMOKE" --skip-raw-jobs --skip-guest-attestation --skip-coco \
    >"$bootstrap_dir/unsafe-$unsafe_shared_fs.stdout" \
    2>"$bootstrap_dir/unsafe-$unsafe_shared_fs.stderr"; then
    printf 'host gate accepted unsafe shared_fs fixture: %s\n' "$unsafe_shared_fs" >&2
    exit 1
  fi
  rg -F \
    'Infra host gate did not prove the rendered QEMU-SNP shared_fs=none isolation contract' \
    "$bootstrap_dir/unsafe-$unsafe_shared_fs.stderr" >/dev/null
done

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
rg -F 'RuntimeClass/commodity pod overhead is not the measured contract' \
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
