#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
NODE="${CONFIDENTIAL_SNP_NODE:-node1-codewire-dev}"
INFRA_ROOT="${INFRA_ROOT:-$HOME/src/infra}"
HOST_GATE_WORKFLOW="${HOST_GATE_WORKFLOW:-check-node1}"
SSH_HOST="${CONFIDENTIAL_SNP_SSH_HOST:-node1.codewire-dev.sh}"
SSH_USER="${CONFIDENTIAL_SNP_SSH_USER:-codewire}"
SSH_IDENTITY="${CONFIDENTIAL_SNP_SSH_IDENTITY:-$HOME/.ssh/codewire-bare-metal.pub}"
SSH_IDENTITY_AGENT="${CONFIDENTIAL_SNP_SSH_IDENTITY_AGENT:-$HOME/.1password/agent.sock}"
PROBE_NAMESPACE="${CONFIDENTIAL_SNP_PROBE_NAMESPACE:-codewire-runtime-probes}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
WAIT_TIMEOUT="${CONFIDENTIAL_SNP_WAIT_TIMEOUT:-300s}"
RUN_HOST_GATE="${RUN_HOST_GATE:-1}"
RUN_RAW_JOBS="${RUN_RAW_JOBS:-1}"
RUN_GUEST_ATTESTATION="${RUN_GUEST_ATTESTATION:-1}"
RUN_COCO_PRODUCT="${RUN_COCO_PRODUCT:-1}"
COCO_FULL_PRODUCT="${COCO_FULL_PRODUCT:-0}"
COCO_EXPECT_REFUSAL="${COCO_EXPECT_REFUSAL:-0}"
COCO_EXPECT_FAILURE_PATTERN="${COCO_EXPECT_FAILURE_PATTERN:-CoCo test resource assertion failed|guest CDH REST|reference.*value|policy.*den|forbid|unauthor|deny}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
COCO_SUPPORT_LOCK="${COCO_SUPPORT_LOCK:-$ROOT/deployments/k8s/runtime-profiles/confidential/coco-support-images.lock.json}"
COCO_GATEWAY_IMAGE=""
COCO_WORKSPACE_IMAGE=""
COCO_DIND_IMAGE=""
COCO_SOURCE_SHA=""
COCO_SMOKE_MEMORY="${COCO_SMOKE_MEMORY:-16384}"
COCO_SMOKE_DISK="${COCO_SMOKE_DISK:-50}"
COCO_SMOKE_TIMEOUT_SECONDS="${COCO_SMOKE_TIMEOUT_SECONDS:-1500}"
COCO_KBS_URL="${COCO_KBS_URL:-https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080}"
COCO_TEST_RESOURCE_URI="${COCO_TEST_RESOURCE_URI:-kbs:///default/codewire/runtime-test-resource}"
COCO_TEST_RESOURCE_PATH="${COCO_TEST_RESOURCE_PATH:-}"
COCO_TEST_RESOURCE_CONTENT="${COCO_TEST_RESOURCE_CONTENT:-codewire confidential trustee test resource}"

COMMODITY_JOB="codewire-commodity-runtime-smoke"
CONFIDENTIAL_JOB="codewire-confidential-runtime-smoke"
ATTESTATION_JOB="codewire-confidential-snp-attestation"
SMOKE_CONTROL_CONFIGMAP="codewire-confidential-snp-smoke-control"
WORKLOAD_KUSTOMIZATION="codewire-deploy-workloads-dev"
SMOKE_KUSTOMIZATION="codewire-deploy-confidential-smoke-dev"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/smoke-dev-confidential-snp.sh [options]

Reads the Flux-promoted confidential SNP smoke activation on Codewire dev. It
never applies, patches, deletes, or suspends Kubernetes or Flux resources.

Options:
  --skip-host-gate         Skip the read-only Infra host SNP gate
  --skip-raw-jobs          Skip Flux-owned commodity/confidential Job checks
  --skip-guest-attestation Skip the Flux-owned in-guest SNP Job check
  --skip-coco              Skip the Codewire product CoCo smoke
  --full-product           Run the complete Codewire product smoke
  --expect-refusal         Require the product smoke to fail with the configured
                           CoCo/KBS refusal pattern
  --evidence-dir DIR       Store evidence in DIR instead of repo .tmp
  -h, --help               Show this help

Before running, merge a reviewed Codewire source activation that copies both
the confidential runtime profile and the confidential-smoke Kustomization
template into their active paths. Wait for the normal source promotion and
Flux reconciliation. Restore commodity through a second reviewed source commit
after evidence collection; never use kubectl to patch the ConfigMap or Jobs.
USAGE
}

log() {
  printf '[confidential-snp-smoke] %s\n' "$*" >&2
}

die() {
  printf '[confidential-snp-smoke] ERROR: %s\n' "$*" >&2
  exit 1
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --skip-host-gate)
      RUN_HOST_GATE=0
      shift
      ;;
    --skip-raw-jobs)
      RUN_RAW_JOBS=0
      shift
      ;;
    --skip-guest-attestation)
      RUN_GUEST_ATTESTATION=0
      shift
      ;;
    --skip-coco)
      RUN_COCO_PRODUCT=0
      shift
      ;;
    --full-product)
      COCO_FULL_PRODUCT=1
      shift
      ;;
    --expect-refusal)
      COCO_EXPECT_REFUSAL=1
      shift
      ;;
    --evidence-dir)
      [[ "$#" -ge 2 ]] || die "--evidence-dir requires a value"
      EVIDENCE_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_bool01() {
  local name="$1"
  local value="$2"
  [[ "$value" == "0" || "$value" == "1" ]] || die "$name must be 0 or 1, got $value"
}

for setting in RUN_HOST_GATE RUN_RAW_JOBS RUN_GUEST_ATTESTATION RUN_COCO_PRODUCT COCO_FULL_PRODUCT COCO_EXPECT_REFUSAL; do
  require_bool01 "$setting" "${!setting}"
done
[[ "$COCO_EXPECT_REFUSAL" == "0" || "$RUN_COCO_PRODUCT" == "1" ]] || \
  die "--expect-refusal requires the Codewire product smoke"

require_cmd jq
require_cmd kubectl
require_cmd rg
require_cmd skopeo
require_cmd base64
require_cmd sha256sum

if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

if [[ -z "$EVIDENCE_DIR" ]]; then
  mkdir -p "$ROOT/.tmp"
  EVIDENCE_DIR="$(mktemp -d "$ROOT/.tmp/codewire-confidential-snp.XXXXXX")"
else
  mkdir -p "$EVIDENCE_DIR"
fi

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    kubectl --context "$KUBE_CONTEXT" "$@"
  else
    kubectl "$@"
  fi
}

ssh_host() {
  ssh \
    -o IdentityAgent="$SSH_IDENTITY_AGENT" \
    -o IdentitiesOnly=yes \
    -o NumberOfPasswordPrompts=0 \
    -i "$SSH_IDENTITY" \
    "$SSH_USER@$SSH_HOST" "$@"
}

assert_jq() {
  local description="$1"
  local file last
  local -a jq_args

  shift
  jq_args=("$@")
  last=$(( ${#jq_args[@]} - 1 ))
  [[ "$last" -ge 0 ]] || die "assert_jq requires a jq filter and file"
  file="${jq_args[$last]}"
  unset 'jq_args[$last]'
  jq -e "${jq_args[@]}" "$file" >/dev/null || die "$description"
}

assert_ready_current() {
  local description="$1"
  local file="$2"

  assert_jq "$description is not Ready at its observed generation" '
    .metadata.generation == .status.observedGeneration and
    any(.status.conditions[]?; .type == "Ready" and .status == "True" and .observedGeneration == .metadata.generation)
  ' "$file"
}

run_host_gate() {
  [[ "$RUN_HOST_GATE" == "1" ]] || {
    log "skipping host SNP gate"
    return 0
  }
  [[ -x "$INFRA_ROOT/scripts/atmos-run" ]] || \
    die "missing infra atmos wrapper at $INFRA_ROOT/scripts/atmos-run"

  log "running Infra host runtime gate $HOST_GATE_WORKFLOW for $NODE"
  (
    cd "$INFRA_ROOT"
    ./scripts/atmos-run workflow "$HOST_GATE_WORKFLOW" -f runtime-node
  ) 2>&1 | tee "$EVIDENCE_DIR/host-runtime-gate.log"

  log "collecting read-only host SEV-SNP evidence"
  ssh_host "sudo sh -c 'printf \"sev=\"; cat /sys/module/kvm_amd/parameters/sev; printf \"sev_es=\"; cat /sys/module/kvm_amd/parameters/sev_es; printf \"sev_snp=\"; cat /sys/module/kvm_amd/parameters/sev_snp; dmesg | grep -E \"SEV-SNP|SNP|RMP\" | tail -n 80 || true'" \
    >"$EVIDENCE_DIR/host-snp-evidence.log"
  rg -q '^sev_snp=Y$' "$EVIDENCE_DIR/host-snp-evidence.log" || \
    die "host SNP evidence does not show sev_snp=Y"
  rg -q 'SEV-SNP.*enabled|kvm_amd: SEV-SNP' "$EVIDENCE_DIR/host-snp-evidence.log" || \
    die "host SNP evidence does not show SEV-SNP enabled in dmesg"
}

check_runtime_contract() {
  local runtimeclasses_json node_json probe_namespace_json

  log "checking RuntimeClass, node, and probe namespace contract"
  runtimeclasses_json="$EVIDENCE_DIR/runtimeclasses.json"
  node_json="$EVIDENCE_DIR/node-$NODE.json"
  probe_namespace_json="$EVIDENCE_DIR/probe-namespace.json"

  kubectl_dev get runtimeclass commodity confidential -o json >"$runtimeclasses_json"
  kubectl_dev get node "$NODE" -o json >"$node_json"
  kubectl_dev get namespace "$PROBE_NAMESPACE" -o json >"$probe_namespace_json"
  kubectl_dev get runtimeclass commodity confidential -o yaml >"$EVIDENCE_DIR/runtimeclasses.yaml"

  assert_jq "RuntimeClass/commodity handler is not kata-clh" \
    '.items[] | select(.metadata.name == "commodity") | .handler == "kata-clh"' \
    "$runtimeclasses_json"
  assert_jq "RuntimeClass/confidential handler is not kata-qemu-snp" \
    '.items[] | select(.metadata.name == "confidential") | .handler == "kata-qemu-snp"' \
    "$runtimeclasses_json"
  assert_jq "RuntimeClass/confidential does not require confidential-snp label" \
    '.items[] | select(.metadata.name == "confidential") | .scheduling.nodeSelector["node.codewire.sh/confidential-snp"] == "true"' \
    "$runtimeclasses_json"
  assert_jq "node $NODE is not Ready" \
    '[.status.conditions[]? | select(.type == "Ready") | .status][0] == "True"' \
    "$node_json"
  assert_jq "node $NODE lacks Kata runtime label" \
    '.metadata.labels["katacontainers.io/kata-runtime"] == "true"' \
    "$node_json"
  assert_jq "node $NODE lacks runtime-candidate label" \
    '.metadata.labels["node.codewire.sh/runtime-candidate"] == "true"' \
    "$node_json"
  assert_jq "node $NODE lacks confidential-snp label" \
    '.metadata.labels["node.codewire.sh/confidential-snp"] == "true"' \
    "$node_json"
  assert_jq "probe namespace $PROBE_NAMESPACE is not privileged" \
    '.metadata.labels["pod-security.kubernetes.io/enforce"] == "privileged"' \
    "$probe_namespace_json"
}

resolve_active_release() {
  local workloads_json smoke_json configmap image line key value
  local configmaps=()

  log "checking exact Flux activation and active runtime configuration"
  workloads_json="$EVIDENCE_DIR/$WORKLOAD_KUSTOMIZATION.json"
  smoke_json="$EVIDENCE_DIR/$SMOKE_KUSTOMIZATION.json"
  kubectl_dev -n flux-system get kustomization "$WORKLOAD_KUSTOMIZATION" -o json >"$workloads_json"
  kubectl_dev -n flux-system get kustomization "$SMOKE_KUSTOMIZATION" -o json >"$smoke_json"
  assert_ready_current "$WORKLOAD_KUSTOMIZATION" "$workloads_json"
  assert_ready_current "$SMOKE_KUSTOMIZATION" "$smoke_json"

  COCO_SOURCE_SHA="$(jq -r '.metadata.annotations["deploy.codewire.sh/source-sha"] // empty' "$workloads_json")"
  [[ "$COCO_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || \
    die "$WORKLOAD_KUSTOMIZATION has no exact source annotation"
  [[ "$(jq -r '.metadata.annotations["deploy.codewire.sh/source-sha"] // empty' "$smoke_json")" == "$COCO_SOURCE_SHA" ]] || \
    die "workload and confidential-smoke Flux children do not share one source SHA"
  [[ "$(jq -r '.status.lastAppliedRevision // empty' "$workloads_json")" == "main@sha1:$COCO_SOURCE_SHA" ]] || \
    die "$WORKLOAD_KUSTOMIZATION did not apply source $COCO_SOURCE_SHA"
  [[ "$(jq -r '.status.lastAppliedRevision // empty' "$smoke_json")" == "main@sha1:$COCO_SOURCE_SHA" ]] || \
    die "$SMOKE_KUSTOMIZATION did not apply source $COCO_SOURCE_SHA"

  kubectl_dev -n "$PROBE_NAMESPACE" get configmap "$SMOKE_CONTROL_CONFIGMAP" -o json \
    >"$EVIDENCE_DIR/$SMOKE_CONTROL_CONFIGMAP.json"
  assert_jq "Flux confidential-smoke control is not active" \
    '.data.phase == "confidential-snp"' \
    "$EVIDENCE_DIR/$SMOKE_CONTROL_CONFIGMAP.json"

  mapfile -t configmaps < <(
    kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-orchestration -o json | \
      jq -r '.spec.template.spec.containers[] | .envFrom[]? | .configMapRef.name? // empty' | sort -u
  )
  [[ "${#configmaps[@]}" -eq 1 ]] || \
    die "expected exactly one active dev runtime ConfigMap"
  configmap="${configmaps[0]}"
  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$configmap" -o json \
    >"$EVIDENCE_DIR/active-runtime-config.json"
  image="$(jq -r '.data.SANDBOX_GATEWAY_IMAGE // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  # Deploy owns the Dev registry overlay. Require its canonical private Nexus
  # authority here; accepting the source-template or public mirror hides drift.
  [[ "$image" =~ ^nexus\.example\.invalid/oci-approved/codewire/gateway@sha256:[0-9a-f]{64}$ ]] || \
    die "active dev ConfigMap has no digest-pinned private gateway image"

  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      gateway_image) COCO_GATEWAY_IMAGE="$value" ;;
      workspace_image) COCO_WORKSPACE_IMAGE="$value" ;;
      dind_image) COCO_DIND_IMAGE="$value" ;;
    esac
  done < <("$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh" \
    --lock "$COCO_SUPPORT_LOCK" \
    --gateway-image "$image" \
    --source-sha "$COCO_SOURCE_SHA")
  [[ -n "$COCO_GATEWAY_IMAGE" && -n "$COCO_WORKSPACE_IMAGE" && -n "$COCO_DIND_IMAGE" ]] || \
    die "CoCo support resolver returned incomplete active release data"

  assert_jq "active runtime profile is not confidential" \
    '.data.SANDBOX_RUNTIME_PROFILE == "confidential"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active runtime class is not confidential" \
    '.data.SANDBOX_RUNTIME_CLASS == "confidential"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active Docker mode is not guest-dind" \
    '.data.SANDBOX_DOCKER_MODE == "guest-dind"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active CoCo init-data is not enabled" \
    '.data.SANDBOX_KATA_COCO_INIT_DATA_ENABLED == "true"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active KBS URL differs from the confidential smoke contract" \
    --arg kbs "$COCO_KBS_URL" ".data.SANDBOX_KATA_COCO_KBS_URL == \$kbs" \
    "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active CoCo test-resource URI differs from the confidential smoke contract" \
    --arg uri "$COCO_TEST_RESOURCE_URI" ".data.SANDBOX_KATA_COCO_TEST_RESOURCE_URI == \$uri" \
    "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active dind image differs from the committed support lock" \
    --arg dind "$COCO_DIND_IMAGE" ".data.SANDBOX_DIND_IMAGE == \$dind" \
    "$EVIDENCE_DIR/active-runtime-config.json"

  cp "$COCO_SUPPORT_LOCK" "$EVIDENCE_DIR/coco-support-images.lock.json"
  jq -n \
    --arg source_sha "$COCO_SOURCE_SHA" \
    --arg config_map "$configmap" \
    --arg gateway_image "$COCO_GATEWAY_IMAGE" \
    --arg workspace_image "$COCO_WORKSPACE_IMAGE" \
    --arg dind_image "$COCO_DIND_IMAGE" \
    '{sourceSha: $source_sha, configMap: $config_map, gatewayImage: $gateway_image, workspaceImage: $workspace_image, dindImage: $dind_image}' \
    >"$EVIDENCE_DIR/active-release-images.json"
}

record_job() {
  local job="$1"
  local expected_runtime="$2"
  local expected_node="$3"
  local job_json pods_json pod_name logs

  log "checking Flux-owned Job/$job"
  kubectl_dev -n "$PROBE_NAMESPACE" wait --for=condition=complete "job/$job" \
    --timeout="$WAIT_TIMEOUT"
  job_json="$EVIDENCE_DIR/$job.json"
  pods_json="$EVIDENCE_DIR/$job-pods.json"
  logs="$EVIDENCE_DIR/$job.log"
  kubectl_dev -n "$PROBE_NAMESPACE" get job "$job" -o json >"$job_json"
  kubectl_dev -n "$PROBE_NAMESPACE" get pods -l "job-name=$job" -o json >"$pods_json"
  kubectl_dev -n "$PROBE_NAMESPACE" logs "job/$job" >"$logs"

  assert_jq "Job/$job does not use RuntimeClass/$expected_runtime" \
    --arg runtime "$expected_runtime" ".spec.template.spec.runtimeClassName == \$runtime" "$job_json"
  assert_jq "Job/$job did not complete exactly once" \
    '.status.succeeded == 1 and .status.failed == null' "$job_json"
  assert_jq "Job/$job has no succeeded pod" \
    '[.items[] | select(.status.phase == "Succeeded")] | length == 1' "$pods_json"
  pod_name="$(jq -r '.items[] | select(.status.phase == "Succeeded") | .metadata.name' "$pods_json")"
  [[ -n "$pod_name" ]] || die "Job/$job has no succeeded pod name"
  if [[ -n "$expected_node" ]]; then
    assert_jq "Job/$job did not schedule on $expected_node" \
      --arg pod "$pod_name" --arg node "$expected_node" \
      ".items[] | select(.metadata.name == \$pod) | .spec.nodeName == \$node" "$pods_json"
  fi
  rg -q "runtimeClass=$expected_runtime" "$logs" || \
    die "Job/$job did not log runtimeClass=$expected_runtime"
}

run_raw_jobs() {
  [[ "$RUN_RAW_JOBS" == "1" ]] || {
    log "skipping Flux-owned raw runtime Jobs"
    return 0
  }
  record_job "$COMMODITY_JOB" commodity ""
  record_job "$CONFIDENTIAL_JOB" confidential "$NODE"
}

run_guest_attestation() {
  local logs report_b64 report_data_b64 report_display report_bin report_data_bin

  [[ "$RUN_GUEST_ATTESTATION" == "1" ]] || {
    log "skipping Flux-owned in-guest SNP attestation Job"
    return 0
  }
  record_job "$ATTESTATION_JOB" confidential "$NODE"
  logs="$EVIDENCE_DIR/$ATTESTATION_JOB.log"
  report_b64="$EVIDENCE_DIR/guest-snp-attestation-report.b64"
  report_data_b64="$EVIDENCE_DIR/guest-snp-attestation-report-data.b64"
  report_display="$EVIDENCE_DIR/guest-snp-attestation-report-display.txt"
  report_bin="$EVIDENCE_DIR/guest-snp-attestation-report.bin"
  report_data_bin="$EVIDENCE_DIR/guest-snp-attestation-report-data.bin"

  rg -q "snp-attestation-report-ok" "$logs" || \
    die "attestation Job did not complete the snpguest report probe"
  rg -q "/dev/sev-guest" "$logs" || \
    die "attestation Job did not see /dev/sev-guest"
  awk '/attestation_report_base64_begin/{flag=1;next}/attestation_report_base64_end/{flag=0}flag' \
    "$logs" >"$report_b64"
  awk '/report_data_base64_begin/{flag=1;next}/report_data_base64_end/{flag=0}flag' \
    "$logs" >"$report_data_b64"
  awk '/Attestation Report/{flag=1}/attestation_report_base64_begin/{flag=0}flag' \
    "$logs" >"$report_display" || true
  base64 -d "$report_b64" >"$report_bin"
  base64 -d "$report_data_b64" >"$report_data_bin"
  [[ -s "$report_bin" && -s "$report_data_bin" ]] || \
    die "attestation Job produced an empty report"
  sha256sum "$report_bin" "$report_data_bin" >"$EVIDENCE_DIR/guest-snp-attestation-sha256.txt"
}

run_product_command() {
  local -a smoke_args=()

  if [[ "$COCO_FULL_PRODUCT" == "1" ]]; then
    [[ -z "${SMOKE_IMAGE:-}" || "$SMOKE_IMAGE" == "$COCO_WORKSPACE_IMAGE" ]] || \
      die "full-product CoCo proof requires the workspace image derived from the active source SHA"
    smoke_args=(--image "$COCO_WORKSPACE_IMAGE")
  else
    smoke_args=(--skip-docker --skip-ssh --only kube --only exec --only coco)
  fi

  SMOKE_NAME="${SMOKE_NAME:-confidential-snp-$(date -u +%Y%m%d%H%M%S)}" \
    SMOKE_IMAGE="${SMOKE_IMAGE:-$COCO_WORKSPACE_IMAGE}" \
    SMOKE_MEMORY="${SMOKE_MEMORY:-$COCO_SMOKE_MEMORY}" \
    SMOKE_DISK="${SMOKE_DISK:-$COCO_SMOKE_DISK}" \
    SMOKE_TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-$COCO_SMOKE_TIMEOUT_SECONDS}" \
    SMOKE_APP_PREVIEW="${SMOKE_APP_PREVIEW:-1}" \
    SMOKE_TAILNET_DEBUG="${SMOKE_TAILNET_DEBUG:-1}" \
    REQUIRE_TAILNET_PATH_PROBE="${REQUIRE_TAILNET_PATH_PROBE:-1}" \
    EXPECTED_TAILNET_PATH_TRANSPORT="${EXPECTED_TAILNET_PATH_TRANSPORT:-direct_udp}" \
    EXPECTED_RUNTIME_CLASS=confidential \
    EXPECTED_GATEWAY_IMAGE="$COCO_GATEWAY_IMAGE" \
    EXPECTED_DOCKER_MODE=guest-dind \
    EXPECTED_DIND_IMAGE="$COCO_DIND_IMAGE" \
    EXPECTED_NODE="${EXPECTED_NODE:-$NODE}" \
    EXPECTED_NODE_KATA_LABEL="${EXPECTED_NODE_KATA_LABEL:-node.codewire.sh/confidential-snp}" \
    EXPECTED_NODE_KATA_VALUE="${EXPECTED_NODE_KATA_VALUE:-true}" \
    EXPECTED_KATA_AGENT_POLICY_ANNOTATION=1 \
    EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION=1 \
    EXPECTED_KATA_COCO_KBS_URL="$COCO_KBS_URL" \
    EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI="" \
    EXPECTED_KATA_COCO_TEST_RESOURCE_URI="$COCO_TEST_RESOURCE_URI" \
    EXPECTED_KATA_COCO_TEST_RESOURCE_PATH="$COCO_TEST_RESOURCE_PATH" \
    EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT="$COCO_TEST_RESOURCE_CONTENT" \
    "$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh" \
      --admin-oidc "${smoke_args[@]}"
}

run_coco_product() {
  local product_log="$EVIDENCE_DIR/coco-product.log"

  [[ "$RUN_COCO_PRODUCT" == "1" ]] || {
    log "skipping Codewire product CoCo smoke"
    return 0
  }
  log "running Codewire product smoke against the Flux-promoted confidential profile"
  if run_product_command >"$product_log" 2>&1; then
    [[ "$COCO_EXPECT_REFUSAL" == "0" ]] || \
      die "CoCo product smoke succeeded when the selected GitOps profile should refuse it"
  else
    [[ "$COCO_EXPECT_REFUSAL" == "1" ]] || \
      die "CoCo product smoke failed; inspect $product_log"
    rg -q "$COCO_EXPECT_FAILURE_PATTERN" "$product_log" || \
      die "CoCo refusal failed before the configured KBS/attestation assertion"
    log "CoCo product refusal occurred as expected"
  fi
}

main() {
  log "evidence directory: $EVIDENCE_DIR"
  run_host_gate
  check_runtime_contract
  resolve_active_release
  run_raw_jobs
  run_guest_attestation
  run_coco_product
  log "confidential SNP smoke passed"
  log "restore the commodity source profile and baseline smoke Kustomization through a reviewed source commit"
}

main "$@"
