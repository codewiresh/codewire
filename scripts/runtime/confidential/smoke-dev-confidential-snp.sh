#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
EXPECTED_CODEWIRE_DEV_SERVER_URL="${EXPECTED_CODEWIRE_DEV_SERVER_URL:-https://codewire-dev.sh}"
KUBE_CONTEXT="${KUBE_CONTEXT:-dev-cluster}"
NODE="${CONFIDENTIAL_SNP_NODE:-cw-dev-prod-node-1}"
INFRA_ROOT="${INFRA_ROOT:-$HOME/src/infra}"
HOST_GATE_STACK="${CONFIDENTIAL_SNP_HOST_GATE_STACK:-dev-cluster}"
HOST_GATE_MIN_EPHEMERAL_GIB="${CONFIDENTIAL_SNP_HOST_GATE_MIN_EPHEMERAL_GIB:-1500}"
HOST_PROFILE_ISOLATION_RECEIPT='check-talos-runtime-artifacts: confidential profile isolation passed: shared_fs=none host-share-overrides=denied'
PROBE_NAMESPACE="${CONFIDENTIAL_SNP_PROBE_NAMESPACE:-codewire-runtime-probes}"
CODEWIRE_SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
WAIT_TIMEOUT="${CONFIDENTIAL_SNP_WAIT_TIMEOUT:-300s}"
RUN_HOST_GATE="${RUN_HOST_GATE:-1}"
RUN_RAW_JOBS="${RUN_RAW_JOBS:-1}"
RUN_GUEST_ATTESTATION="${RUN_GUEST_ATTESTATION:-1}"
RUN_COCO_PRODUCT="${RUN_COCO_PRODUCT:-1}"
COCO_FULL_PRODUCT="${COCO_FULL_PRODUCT:-0}"
COCO_KEEP_PRODUCT="${COCO_KEEP_PRODUCT:-0}"
COCO_EXISTING_ENV_ID="${COCO_EXISTING_ENV_ID:-}"
COCO_EXPECT_REFUSAL="${COCO_EXPECT_REFUSAL:-0}"
COCO_EXPECT_FAILURE_PATTERN="${COCO_EXPECT_FAILURE_PATTERN:-CoCo test resource assertion failed|guest CDH REST|reference.*value|policy.*den|forbid|unauthor|deny}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
COCO_SUPPORT_LOCK="${COCO_SUPPORT_LOCK:-$ROOT/deployments/k8s/runtime-profiles/confidential/coco-support-images.lock.json}"
RUNTIME_CONFIGMAP_SELECTOR="$ROOT/scripts/runtime/confidential/select-required-runtime-configmap.jq"
READY_CURRENT_SELECTOR="$ROOT/scripts/runtime/confidential/select-ready-current.jq"
COCO_DAEMON_IMAGE=""
COCO_WORKSPACE_IMAGE=""
COCO_DIND_IMAGE=""
COCO_SOURCE_SHA=""
COCO_GATEWAY_STUN_HOST=""
COCO_GATEWAY_STUN_PORT=""
COCO_DIRECT_UDP_LB_IP=""
COCO_DIRECT_UDP_TRANSPORT_ZONE=""
COCO_SMOKE_MEMORY="${COCO_SMOKE_MEMORY:-16384}"
COCO_SMOKE_DISK="${COCO_SMOKE_DISK:-50}"
COCO_SMOKE_TIMEOUT_SECONDS="${COCO_SMOKE_TIMEOUT_SECONDS:-1800}"
COCO_KBS_URL="${COCO_KBS_URL:-https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080}"
COCO_IMAGE_REGISTRY_AUTH_URI="${COCO_IMAGE_REGISTRY_AUTH_URI:-kbs:///default/containers/auth}"
COCO_TEST_RESOURCE_URI="${COCO_TEST_RESOURCE_URI:-kbs:///default/codewire/runtime-test-resource}"
COCO_TEST_RESOURCE_PATH="${COCO_TEST_RESOURCE_PATH:-}"
COCO_TEST_RESOURCE_CONTENT="${COCO_TEST_RESOURCE_CONTENT:-codewire confidential trustee test resource}"

COMMODITY_JOB_SELECTOR="app.kubernetes.io/name=codewire-commodity-runtime-smoke"
CONFIDENTIAL_JOB_SELECTOR="app.kubernetes.io/name=codewire-confidential-runtime-smoke"
ATTESTATION_JOB_SELECTOR="app.kubernetes.io/name=codewire-confidential-snp-attestation"
SMOKE_CONTROL_CONFIGMAP="codewire-confidential-snp-smoke-control"
WORKLOAD_KUSTOMIZATION="codewire-deploy-workloads-dev"
SMOKE_KUSTOMIZATION="codewire-deploy-confidential-smoke-dev"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/smoke-dev-confidential-snp.sh [options]

Reads the Flux-promoted confidential SNP smoke activation on Codewire dev. It
never mutates Codewire or Flux desired state. The Infra-owned Talos verifier
may create and remove its documented short-lived runtime probe pods.

Options:
  --skip-host-gate         Reuse an already accepted Infra Talos host gate
  --skip-raw-jobs          Skip Flux-owned commodity/confidential Job checks
  --skip-guest-attestation Skip the Flux-owned in-guest SNP Job check
  --skip-coco              Skip the Codewire product CoCo smoke
  --full-product           Run the complete Codewire product smoke
  --keep-product           Retain the product environment and record its ID
  --existing-env ID        Reuse and retain one existing product environment
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
    --keep-product)
      COCO_KEEP_PRODUCT=1
      shift
      ;;
    --existing-env)
      [[ "$#" -ge 2 ]] || die "--existing-env requires a value"
      COCO_EXISTING_ENV_ID="$2"
      shift 2
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
  if [[ "$1" == */* ]]; then
    [[ -x "$1" ]] || die "missing required command: $1"
  else
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
  fi
}

require_bool01() {
  local name="$1"
  local value="$2"
  [[ "$value" == "0" || "$value" == "1" ]] || die "$name must be 0 or 1, got $value"
}

for setting in RUN_HOST_GATE RUN_RAW_JOBS RUN_GUEST_ATTESTATION RUN_COCO_PRODUCT COCO_FULL_PRODUCT COCO_KEEP_PRODUCT COCO_EXPECT_REFUSAL; do
  require_bool01 "$setting" "${!setting}"
done
[[ "$COCO_EXPECT_REFUSAL" == "0" || "$RUN_COCO_PRODUCT" == "1" ]] || \
  die "--expect-refusal requires the Codewire product smoke"
[[ "$COCO_KEEP_PRODUCT" == "0" || "$RUN_COCO_PRODUCT" == "1" ]] || \
  die "--keep-product requires the Codewire product smoke"
[[ -z "$COCO_EXISTING_ENV_ID" || "$RUN_COCO_PRODUCT" == "1" ]] || \
  die "--existing-env requires the Codewire product smoke"
if [[ -n "$COCO_EXISTING_ENV_ID" \
  && ! "$COCO_EXISTING_ENV_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  die "--existing-env requires a lowercase UUID"
fi

require_cmd jq
require_cmd "$KUBECTL_BIN"
require_cmd rg
require_cmd base64
require_cmd sha256sum
if [[ "$RUN_COCO_PRODUCT" == "1" ]]; then
  require_cmd skopeo
fi

if [[ -z "${KUBECONFIG:-}" && -f "$HOME/src/infra/kubeconfig-oidc.yaml" ]]; then
  export KUBECONFIG="$HOME/src/infra/kubeconfig-oidc.yaml"
fi

if [[ -z "$EVIDENCE_DIR" ]]; then
  mkdir -p "$ROOT/.tmp"
  EVIDENCE_DIR="$(mktemp -d "$ROOT/.tmp/codewire-confidential-snp.XXXXXX")"
else
  [[ ! -L "$EVIDENCE_DIR" ]] || die "evidence directory must not be a symlink"
  mkdir -p "$EVIDENCE_DIR"
fi
chmod 700 "$EVIDENCE_DIR"

kubectl_dev() {
  if [[ -n "$KUBE_CONTEXT" ]]; then
    "$KUBECTL_BIN" --context "$KUBE_CONTEXT" "$@"
  else
    "$KUBECTL_BIN" "$@"
  fi
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

  assert_jq "$description is not Ready at its observed generation" \
    -f "$READY_CURRENT_SELECTOR" "$file"
}

run_host_gate() {
  [[ "$RUN_HOST_GATE" == "1" ]] || {
    log "skipping host SNP gate"
    return 0
  }
  [[ -x "$INFRA_ROOT/scripts/check-talos-runtime-artifacts" ]] || \
    die "missing Infra Talos runtime-artifact verifier at $INFRA_ROOT/scripts/check-talos-runtime-artifacts"
  [[ -x "$INFRA_ROOT/scripts/talos-external-worker" ]] || \
    die "missing Infra Talos external-worker wrapper at $INFRA_ROOT/scripts/talos-external-worker"
  [[ "$HOST_GATE_STACK" == "dev-cluster" ]] || \
    die "confidential SNP host gate must use dev-cluster"
  [[ "$HOST_GATE_MIN_EPHEMERAL_GIB" =~ ^[0-9]+$ ]] || \
    die "confidential SNP host-gate ephemeral threshold must be an integer"

  log "running Infra Talos runtime-artifact and external-worker gates for $NODE"
  (
    cd "$INFRA_ROOT"
    ./scripts/check-talos-runtime-artifacts --stack "$HOST_GATE_STACK"
    ./scripts/talos-external-worker verify \
      "$HOST_GATE_STACK" "$NODE" "$HOST_GATE_MIN_EPHEMERAL_GIB"
  ) 2>&1 | tee "$EVIDENCE_DIR/host-runtime-gate.log"
  grep -Fxq -- "$HOST_PROFILE_ISOLATION_RECEIPT" \
    "$EVIDENCE_DIR/host-runtime-gate.log" || \
    die "Infra host gate did not prove the rendered QEMU-SNP shared_fs=none isolation contract"
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
  assert_jq "RuntimeClass/commodity pod overhead is not the kata-clh contract" \
    '.items[] | select(.metadata.name == "commodity") | .overhead.podFixed == {"cpu":"250m","memory":"130Mi"}' \
    "$runtimeclasses_json"
  assert_jq "RuntimeClass/confidential handler is not kata-qemu-snp" \
    '.items[] | select(.metadata.name == "confidential") | .handler == "kata-qemu-snp"' \
    "$runtimeclasses_json"
  assert_jq "RuntimeClass/confidential pod overhead is not the kata-qemu-snp contract" \
    '.items[] | select(.metadata.name == "confidential") | .overhead.podFixed == {"cpu":"1","memory":"3968Mi"}' \
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
  local workloads_json smoke_json deployment_json configmap image line key value transport_zones

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

  if [[ "$RUN_COCO_PRODUCT" != "1" ]]; then
    log "skipping product release image resolution"
    return 0
  fi

  deployment_json="$EVIDENCE_DIR/codewire-orchestration-deployment.json"
  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get deployment codewire-orchestration -o json \
    >"$deployment_json"
  configmap="$(jq -er -f "$RUNTIME_CONFIGMAP_SELECTOR" "$deployment_json")" || \
    die "orchestration does not reference exactly one required generated runtime ConfigMap"
  kubectl_dev -n "$CODEWIRE_SERVER_NAMESPACE" get configmap "$configmap" -o json \
    >"$EVIDENCE_DIR/active-runtime-config.json"
  image="$(jq -r '.data.SANDBOX_DAEMON_IMAGE // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  # Deploy owns the Dev registry overlay. Require its canonical private Harbor
  # authority here; accepting the source-template or public mirror hides drift.
  [[ "$image" =~ ^registry\.example\.invalid/codewire/daemon@sha256:[0-9a-f]{64}$ ]] || \
    die "active dev ConfigMap has no digest-pinned private daemon image"

  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      daemon_image) COCO_DAEMON_IMAGE="$value" ;;
      workspace_image) COCO_WORKSPACE_IMAGE="$value" ;;
      dind_image) COCO_DIND_IMAGE="$value" ;;
    esac
  done < <("$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh" \
    --lock "$COCO_SUPPORT_LOCK" \
    --daemon-image "$image" \
    --source-sha "$COCO_SOURCE_SHA")
  [[ -n "$COCO_DAEMON_IMAGE" && -n "$COCO_WORKSPACE_IMAGE" && -n "$COCO_DIND_IMAGE" ]] || \
    die "CoCo support resolver returned incomplete active release data"

  assert_jq "active default runtime profile is not commodity" \
    '.data.SANDBOX_RUNTIME_PROFILE == "commodity"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "active Docker mode is not profile-default" \
    '.data.SANDBOX_DOCKER_MODE == "profile-default"' "$EVIDENCE_DIR/active-runtime-config.json"
  # The confidential activation profile still pins ordinary Longhorn for
  # commodity workspaces; the Dev commodity profile uses local-path while Dev's
  # Longhorn is retired (Program #2238).
  assert_jq "active default workspace storage class is not ordinary Longhorn" \
    '.data.SANDBOX_WORKSPACE_STORAGE_CLASS == "longhorn"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "confidential creation is not enabled" \
    '.data.SANDBOX_CONFIDENTIAL_STORAGE_ENABLED == "true"' "$EVIDENCE_DIR/active-runtime-config.json"
  assert_jq "confidential creation is not admin-only" \
    '.data.SANDBOX_CONFIDENTIAL_ADMIN_ONLY == "true"' "$EVIDENCE_DIR/active-runtime-config.json"
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

  COCO_GATEWAY_STUN_HOST="$(jq -r '.data.STUN_HOST // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  COCO_GATEWAY_STUN_PORT="$(jq -r '.data.STUN_PORT // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  COCO_DIRECT_UDP_LB_IP="$(jq -r '.data.CODEWIRE_DIRECT_UDP_LB_IP // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  COCO_DIRECT_UDP_TRANSPORT_ZONE="$(jq -r '.data.CODEWIRE_DIRECT_UDP_TRANSPORT_ZONE // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  transport_zones="$(jq -r '.data.CODEWIRE_RUNTIME_TRANSPORT_ZONES_JSON // empty' "$EVIDENCE_DIR/active-runtime-config.json")"
  [[ -n "$COCO_GATEWAY_STUN_HOST" ]] || die "active STUN_HOST is empty"
  [[ "$COCO_GATEWAY_STUN_PORT" == "3478" ]] || \
    die "active STUN_PORT=$COCO_GATEWAY_STUN_PORT, want 3478"
  [[ -n "$COCO_DIRECT_UDP_LB_IP" ]] || die "active CODEWIRE_DIRECT_UDP_LB_IP is empty"
  [[ -n "$COCO_DIRECT_UDP_TRANSPORT_ZONE" ]] || \
    die "active CODEWIRE_DIRECT_UDP_TRANSPORT_ZONE is empty"
  jq -e \
    --arg zone "$COCO_DIRECT_UDP_TRANSPORT_ZONE" \
    --arg ip "$COCO_DIRECT_UDP_LB_IP" \
    --arg stun "$COCO_GATEWAY_STUN_HOST:$COCO_GATEWAY_STUN_PORT" \
    '.version == 1 and any(.zones[]?;
      .name == $zone
      and .direct_udp.vip == $ip
      and ((.stun.endpoints // []) | index($stun)))' \
    <<<"$transport_zones" >/dev/null || \
    die "active transport-zone registry does not match its STUN and direct-UDP inputs"

  cp "$COCO_SUPPORT_LOCK" "$EVIDENCE_DIR/coco-support-images.lock.json"
  jq -n \
    --arg source_sha "$COCO_SOURCE_SHA" \
    --arg config_map "$configmap" \
    --arg daemon_image "$COCO_DAEMON_IMAGE" \
    --arg workspace_image "$COCO_WORKSPACE_IMAGE" \
    --arg dind_image "$COCO_DIND_IMAGE" \
    '{sourceSha: $source_sha, configMap: $config_map, daemonImage: $daemon_image, workspaceImage: $workspace_image, dindImage: $dind_image}' \
    >"$EVIDENCE_DIR/active-release-images.json"
}

record_job() {
  local job="$1"
  local expected_runtime="$2"
  local expected_node="$3"
  local expected_storage_class="${4:-}"
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
  if [[ -n "$expected_storage_class" ]]; then
    assert_jq "Job/$job does not mount an ephemeral $expected_storage_class workspace" \
      --arg storage_class "$expected_storage_class" \
      'any(.spec.template.spec.volumes[]?;
        .name == "workspace" and
        .ephemeral.volumeClaimTemplate.spec.storageClassName == $storage_class)' \
      "$job_json"
    rg -q "${expected_storage_class}-workspace-ok" "$logs" || \
      die "Job/$job did not prove its $expected_storage_class workspace mount"
  fi
  rg -q "runtimeClass=$expected_runtime" "$logs" || \
    die "Job/$job did not log runtimeClass=$expected_runtime"
}

resolve_job_name() {
  local label="$1"
  local selector="$2"
  local jobs_json="$EVIDENCE_DIR/$label-jobs.json"
  local count

  kubectl_dev -n "$PROBE_NAMESPACE" get jobs -l "$selector" -o json >"$jobs_json"
  count="$(jq '.items | length' "$jobs_json")"
  [[ "$count" == "1" ]] || \
    die "expected exactly one $label Job matching $selector, found $count"
  jq -r '.items[0].metadata.name' "$jobs_json"
}

run_raw_jobs() {
  local commodity_job confidential_job

  [[ "$RUN_RAW_JOBS" == "1" ]] || {
    log "skipping Flux-owned raw runtime Jobs"
    return 0
  }
  commodity_job="$(resolve_job_name commodity "$COMMODITY_JOB_SELECTOR")"
  record_job "$commodity_job" commodity "$NODE" longhorn
  confidential_job="$(resolve_job_name confidential "$CONFIDENTIAL_JOB_SELECTOR")"
  record_job "$confidential_job" confidential "$NODE"
}

run_guest_attestation() {
  local job logs report_b64 report_data_b64 report_display report_bin report_data_bin

  [[ "$RUN_GUEST_ATTESTATION" == "1" ]] || {
    log "skipping Flux-owned in-guest SNP attestation Job"
    return 0
  }
  job="$(resolve_job_name attestation "$ATTESTATION_JOB_SELECTOR")"
  record_job "$job" confidential "$NODE"
  logs="$EVIDENCE_DIR/$job.log"
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
    # smoke-dev-commodity.sh consumes the image through SMOKE_IMAGE; it has no
    # --image option.
  else
    smoke_args=(--skip-docker --skip-ssh --only kube --only exec --only coco)
  fi
  if [[ -n "$COCO_EXISTING_ENV_ID" ]]; then
    smoke_args+=(--existing-env "$COCO_EXISTING_ENV_ID")
  fi
  if [[ "$COCO_KEEP_PRODUCT" == "1" ]]; then
    smoke_args+=(--keep)
  fi

  CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" \
    EXPECTED_CODEWIRE_DEV_SERVER_URL="$EXPECTED_CODEWIRE_DEV_SERVER_URL" \
    CODEWIRE_SERVER_NAMESPACE="$CODEWIRE_SERVER_NAMESPACE" \
    SANDBOX_NAMESPACE="$SANDBOX_NAMESPACE" \
    KUBE_CONTEXT="$KUBE_CONTEXT" \
    SMOKE_NAME="${SMOKE_NAME:-confidential-snp-$(date -u +%Y%m%d%H%M%S)}" \
    SMOKE_IMAGE="${SMOKE_IMAGE:-$COCO_WORKSPACE_IMAGE}" \
    SMOKE_MEMORY="${SMOKE_MEMORY:-$COCO_SMOKE_MEMORY}" \
    SMOKE_DISK="${SMOKE_DISK:-$COCO_SMOKE_DISK}" \
    SMOKE_TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-$COCO_SMOKE_TIMEOUT_SECONDS}" \
    SMOKE_ARTIFACT_DIR="$EVIDENCE_DIR/product" \
    SMOKE_ISOLATION_TIER=confidential \
    SMOKE_APP_PREVIEW="${SMOKE_APP_PREVIEW:-1}" \
    SMOKE_TAILNET_DEBUG="${SMOKE_TAILNET_DEBUG:-1}" \
    REQUIRE_TAILNET_PATH_PROBE="${REQUIRE_TAILNET_PATH_PROBE:-1}" \
    EXPECTED_TAILNET_PATH_TRANSPORT="${EXPECTED_TAILNET_PATH_TRANSPORT:-direct_udp}" \
    EXPECTED_STUN_HOST="$COCO_GATEWAY_STUN_HOST" \
    EXPECTED_STUN_PORT="$COCO_GATEWAY_STUN_PORT" \
    EXPECTED_TAILNET_DIRECT_UDP_LB_IP="$COCO_DIRECT_UDP_LB_IP" \
    EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE="$COCO_DIRECT_UDP_TRANSPORT_ZONE" \
    EXPECTED_RUNTIME_CLASS=confidential \
    EXPECTED_DAEMON_IMAGE="$COCO_DAEMON_IMAGE" \
    EXPECTED_DOCKER_MODE=guest-dind \
    EXPECTED_DIND_IMAGE="$COCO_DIND_IMAGE" \
    EXPECTED_NODE="${EXPECTED_NODE:-$NODE}" \
    EXPECTED_NODE_KATA_LABEL="${EXPECTED_NODE_KATA_LABEL:-node.codewire.sh/confidential-snp}" \
    EXPECTED_NODE_KATA_VALUE="${EXPECTED_NODE_KATA_VALUE:-true}" \
    EXPECTED_KATA_AGENT_POLICY_ANNOTATION=1 \
    EXPECTED_KATA_COCO_INIT_DATA_ANNOTATION=1 \
    EXPECTED_KATA_COCO_KBS_URL="$COCO_KBS_URL" \
    EXPECTED_KATA_COCO_IMAGE_REGISTRY_AUTH_URI="$COCO_IMAGE_REGISTRY_AUTH_URI" \
    EXPECTED_KATA_COCO_TEST_RESOURCE_URI="$COCO_TEST_RESOURCE_URI" \
    EXPECTED_KATA_COCO_TEST_RESOURCE_PATH="$COCO_TEST_RESOURCE_PATH" \
    EXPECTED_KATA_COCO_TEST_RESOURCE_CONTENT="$COCO_TEST_RESOURCE_CONTENT" \
    "$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh" \
      --admin-oidc "${smoke_args[@]}"
}

# Pending B2c: the product phase creates a confidential environment, and
# confidential environments cannot bind to the workspace binding yet. Since
# daemon-hosted access (#2460) serves SSH and the tailnet only from a bound
# daemon, the API refuses them with "confidential isolation is temporarily
# unavailable". The phase is skipped explicitly and the run never reports a
# pass while it is skipped.
COCO_PRODUCT_PENDING_B2C=1
COCO_PRODUCT_SKIPPED=0

run_coco_product() {
  local product_log="$EVIDENCE_DIR/coco-product.log"

  [[ "$RUN_COCO_PRODUCT" == "1" ]] || {
    log "skipping Codewire product CoCo smoke"
    return 0
  }
  if [[ "$COCO_PRODUCT_PENDING_B2C" == "1" ]]; then
    log "SKIPPED pending B2c: the Codewire product CoCo smoke creates a confidential environment, and confidential isolation is temporarily unavailable"
    COCO_PRODUCT_SKIPPED=1
    return 0
  fi
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
  if [[ "$COCO_PRODUCT_SKIPPED" == "1" ]]; then
    log "confidential SNP smoke NOT PASSED: platform checks completed; the product CoCo phase is skipped pending B2c (rerun with --skip-coco to accept the platform checks alone)"
    exit 77
  fi
  log "confidential SNP smoke passed"
  log "restore the commodity source profile and baseline smoke Kustomization through a reviewed source commit"
}

main "$@"
