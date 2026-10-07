#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KUBE_CONTEXT="${KUBE_CONTEXT:-dev-cluster}"
SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
NODE="${CONFIDENTIAL_SNP_NODE:-cw-dev-prod-node-1}"
WAIT_SECONDS="${PRIVATE_PULL_WAIT_SECONDS:-360}"
KEEP_PROBE="${PRIVATE_PULL_KEEP_PROBE:-0}"
ENCRYPTED_EMPTYDIR="${PRIVATE_PULL_ENCRYPTED_EMPTYDIR:-0}"
IMAGE_ROLE="${PRIVATE_PULL_IMAGE_ROLE:-daemon}"
ASSERT_REST_DISABLED="${PRIVATE_PULL_ASSERT_REST_DISABLED:-0}"
PROBE_UUID="${PRIVATE_PULL_PROBE_UUID:-}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"
readonly IMAGE_RESOURCE_TIMEOUT_SECS=300

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/smoke-dev-private-image-pull.sh [options]

Runs one short-lived confidential Pod that pulls an exact image from the active
Dev release. The probe exercises Kata guest CDH, Trustee attestation, and KBS
registry authorization without creating a Codewire environment or PVC.

Options:
  --node NAME          Confidential SNP node (default: cw-dev-prod-node-1)
  --image-role ROLE    Exact active image: daemon, workspace, dind, or the
                       combined product image/cache shape
                       (default: daemon)
  --assert-rest-disabled
                       Prove the workload cannot reach a guest-local CDH REST
                       listener (workspace/product only)
  --wait-seconds N     Terminal wait horizon (default: 360)
  --keep-probe         Keep the Pod and CiliumNetworkPolicy for inspection
  --encrypted-emptydir Exercise an init-to-main shared encrypted emptyDir
  --evidence-dir DIR   Store private evidence in DIR
  -h, --help           Show this help

Run this script only through the Infra Kubernetes access wrapper. It reads
ConfigMaps but no Secrets. Its temporary Cilium policy permits only cluster
DNS, Trustee KBS on its exact namespace/port, and TCP 443 to either the exact
private Harbor hostname or the public-address space used by product workspaces.
USAGE
}

log() {
  printf '[private-image-pull] %s\n' "$*" >&2
}

die() {
  printf '[private-image-pull] ERROR: %s\n' "$*" >&2
  exit 1
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --node)
      [[ "$#" -ge 2 ]] || die "--node requires a value"
      NODE="$2"
      shift 2
      ;;
    --wait-seconds)
      [[ "$#" -ge 2 ]] || die "--wait-seconds requires a value"
      WAIT_SECONDS="$2"
      shift 2
      ;;
    --image-role)
      [[ "$#" -ge 2 ]] || die "--image-role requires a value"
      IMAGE_ROLE="$2"
      shift 2
      ;;
    --assert-rest-disabled)
      ASSERT_REST_DISABLED=1
      shift
      ;;
    --keep-probe)
      KEEP_PROBE=1
      shift
      ;;
    --encrypted-emptydir)
      ENCRYPTED_EMPTYDIR=1
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

for command in "$KUBECTL_BIN" jq awk gzip base64; do
  require_cmd "$command"
done
[[ "$WAIT_SECONDS" =~ ^[1-9][0-9]*$ ]] || die "--wait-seconds must be a positive integer"
(( WAIT_SECONDS > IMAGE_RESOURCE_TIMEOUT_SECS )) || \
  die "--wait-seconds must exceed the ${IMAGE_RESOURCE_TIMEOUT_SECS}s guest image-resource timeout"
[[ "$IMAGE_ROLE" == "daemon" || "$IMAGE_ROLE" == "workspace" || \
   "$IMAGE_ROLE" == "dind" || "$IMAGE_ROLE" == "product" ]] || \
  die "--image-role must be daemon, workspace, dind, or product"
[[ "$ASSERT_REST_DISABLED" == "0" || "$ASSERT_REST_DISABLED" == "1" ]] || \
  die "PRIVATE_PULL_ASSERT_REST_DISABLED must be 0 or 1"
if [[ "$ASSERT_REST_DISABLED" == "1" ]]; then
  [[ "$IMAGE_ROLE" == "workspace" || "$IMAGE_ROLE" == "product" ]] || \
    die "--assert-rest-disabled requires --image-role workspace or product"
fi
[[ "$KEEP_PROBE" == "0" || "$KEEP_PROBE" == "1" ]] || die "PRIVATE_PULL_KEEP_PROBE must be 0 or 1"
[[ "$ENCRYPTED_EMPTYDIR" == "0" || "$ENCRYPTED_EMPTYDIR" == "1" ]] || \
  die "PRIVATE_PULL_ENCRYPTED_EMPTYDIR must be 0 or 1"
[[ "$NODE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || die "invalid node name"

if [[ -z "$EVIDENCE_DIR" ]]; then
  mkdir -p "$ROOT/.tmp"
  EVIDENCE_DIR="$(mktemp -d "$ROOT/.tmp/codewire-private-image-pull.XXXXXX")"
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

configmap_json="$EVIDENCE_DIR/runtime-config.json"
deployment_json="$EVIDENCE_DIR/orchestration-deployment.json"
ca_json="$EVIDENCE_DIR/kbs-ca.json"
service_account_json="$EVIDENCE_DIR/sandbox-service-account.json"
manifest="$EVIDENCE_DIR/probe.yaml"
pod_evidence="$EVIDENCE_DIR/pod.json"
event_evidence="$EVIDENCE_DIR/events.json"
container_log="$EVIDENCE_DIR/container.log"

kubectl_dev -n "$SERVER_NAMESPACE" get deployment codewire-orchestration -o json >"$deployment_json"
mapfile -t configmap_names < <(
  jq -er '
    .spec.template.spec.containers[]
    | select(.name == "orchestration")
    | .envFrom[]?
    | select(.configMapRef.name? != null)
    | .configMapRef.name
  ' \
    "$deployment_json"
)
active_configmap=""
for configmap_name in "${configmap_names[@]}"; do
  candidate="$EVIDENCE_DIR/configmap-$configmap_name.json"
  kubectl_dev -n "$SERVER_NAMESPACE" get configmap "$configmap_name" -o json >"$candidate"
  if jq -e '.data.SANDBOX_DAEMON_IMAGE != null' "$candidate" >/dev/null; then
    [[ -z "$active_configmap" ]] || die "multiple runtime ConfigMaps provide SANDBOX_DAEMON_IMAGE"
    active_configmap="$configmap_name"
    mv "$candidate" "$configmap_json"
  else
    rm -f "$candidate"
  fi
done
[[ -n "$active_configmap" ]] || die "active orchestration runtime ConfigMap was not found"

daemon_image="$(jq -er '.data.SANDBOX_DAEMON_IMAGE' "$configmap_json")"
dind_image="$(jq -er '.data.SANDBOX_DIND_IMAGE' "$configmap_json")"
kbs_url="$(jq -er '.data.SANDBOX_KATA_COCO_KBS_URL' "$configmap_json")"
registry_auth_uri="$(jq -er '.data.SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI' "$configmap_json")"
coco_enabled="$(jq -er '.data.SANDBOX_KATA_COCO_INIT_DATA_ENABLED' "$configmap_json")"
test_resource_uri="$(jq -er '.data.SANDBOX_KATA_COCO_TEST_RESOURCE_URI' "$configmap_json")"

[[ "$daemon_image" =~ ^registry\.example\.invalid/codewire/daemon@sha256:[a-f0-9]{64}$ ]] || \
  die "promoted daemon image is not an exact Harbor digest"
[[ "$dind_image" =~ ^docker\.io/library/docker:[0-9]+\.[0-9]+\.[0-9]+-dind@sha256:[a-f0-9]{64}$ ]] || \
  die "active dind image is not an exact official Docker digest"
[[ "$kbs_url" == "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080" ]] || \
  die "unexpected Trustee KBS URL"
[[ "$registry_auth_uri" == "kbs:///default/containers/auth" ]] || \
  die "unexpected KBS registry-auth resource URI"
[[ "$coco_enabled" == "true" ]] || die "Dev CoCo init-data is not enabled"
[[ "$test_resource_uri" == "kbs:///default/codewire/runtime-test-resource" ]] || \
  die "unexpected CoCo test-resource URI"

probe_image="$daemon_image"
probe_container_name=version
probe_command='/usr/local/bin/cw'
probe_args_yaml='["--version"]'
probe_uid=65532
probe_gid=65532
probe_privileged=false
probe_run_as_non_root=true
probe_allow_privilege_escalation=false
probe_read_only_root_filesystem=true
probe_memory_request=128Mi
probe_memory_limit=512Mi
public_registry_egress=0
managed_workspace_identity=0
product_dind_yaml=""
if [[ "$IMAGE_ROLE" == "workspace" || "$IMAGE_ROLE" == "product" ]]; then
  require_cmd skopeo
  workloads_json="$EVIDENCE_DIR/codewire-deploy-workloads-dev.json"
  kubectl_dev -n flux-system get kustomization codewire-deploy-workloads-dev -o json >"$workloads_json"
  source_sha="$(jq -er '.metadata.annotations["deploy.codewire.sh/source-sha"]' "$workloads_json")"
  [[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "active workload has no exact source SHA"
  [[ "$(jq -r '.status.lastAppliedRevision // empty' "$workloads_json")" == "main@sha1:$source_sha" ]] || \
    die "active workload revision does not match its source annotation"
  resolved_dind_image=""
  while IFS= read -r release_line; do
    release_key="${release_line%%=*}"
    release_value="${release_line#*=}"
    case "$release_key" in
      workspace_image) probe_image="$release_value" ;;
      dind_image) resolved_dind_image="$release_value" ;;
    esac
  done < <("$ROOT/scripts/runtime/confidential/resolve-coco-support-lock.sh" \
    --daemon-image "$daemon_image" \
    --source-sha "$source_sha")
  [[ "$probe_image" =~ ^ghcr\.io/codewiresh/workspace@sha256:[a-f0-9]{64}$ ]] || \
    die "support lock did not resolve an exact workspace image"
  [[ "$resolved_dind_image" == "$dind_image" ]] || \
    die "active dind image differs from the support lock"
  probe_command='/bin/sh'
  probe_args_yaml='["-c", "printf workspace-image-ok\\n"]'
  probe_uid=1000
  probe_gid=1000
  # Match the real confidential workspace plus DinD aggregate limit. Kata
  # sizes the encrypted guest /run from the VM memory envelope; a tiny probe
  # would turn a valid large image into an artificial ENOSPC failure.
  probe_memory_request=20480Mi
  probe_memory_limit=20480Mi
  public_registry_egress=1
  if [[ "$IMAGE_ROLE" == "product" ]]; then
    ENCRYPTED_EMPTYDIR=1
    probe_memory_request=16384Mi
    probe_memory_limit=16384Mi
    managed_workspace_identity=1
  fi
elif [[ "$IMAGE_ROLE" == "dind" ]]; then
  probe_image="$dind_image"
  probe_container_name=dind
  probe_command='/usr/local/bin/docker'
  probe_uid=0
  probe_gid=0
  probe_privileged=true
  probe_run_as_non_root=false
  probe_allow_privilege_escalation=true
  probe_read_only_root_filesystem=false
  probe_memory_request=20480Mi
  probe_memory_limit=20480Mi
  managed_workspace_identity=1
  public_registry_egress=1
fi

if [[ "$ASSERT_REST_DISABLED" == "1" ]]; then
  test_resource_path="${test_resource_uri#kbs:///}"
  test_resource_script="$(cat <<SCRIPT
set -eu
path='$test_resource_path'
if ! command -v curl >/dev/null 2>&1; then
  printf 'coco_rest_disabled=probe_missing\n'
  exit 25
fi
set +e
curl --max-time 3 -sS -o /dev/null "http://127.0.0.1:8006/cdh/resource/\$path"
status=\$?
set -e
if [ "\$status" -eq 0 ]; then
  printf 'coco_rest_disabled=listener_present\n'
  exit 24
fi
if [ "\$status" -ne 7 ]; then
  printf 'coco_rest_disabled=unexpected_transport_%s\n' "\$status"
  exit 25
fi
printf 'coco_rest_disabled=passed\n'
SCRIPT
)"
  probe_args_yaml="$(jq -cn --arg script "$test_resource_script" '["-c", $script]')"
fi

kubectl_dev -n "$SANDBOX_NAMESPACE" get serviceaccount codewire-sandbox -o json >"$service_account_json"
jq -e 'any(.imagePullSecrets[]?; .name == "harbor-registry")' "$service_account_json" >/dev/null || \
  die "codewire-sandbox ServiceAccount does not select the Harbor pull Secret"

kubectl_dev -n "$SERVER_NAMESPACE" get configmap codewire-trustee-kbs-ca -o json >"$ca_json"
kbs_ca="$(jq -er '.data["ca.crt"]' "$ca_json")"
[[ "$kbs_ca" == '-----BEGIN CERTIFICATE-----'* ]] || die "Trustee CA ConfigMap has no PEM certificate"
[[ "$kbs_ca" == *'-----END CERTIFICATE-----' ]] || die "Trustee CA ConfigMap has an incomplete PEM certificate"
(( ${#kbs_ca} <= 32768 )) || die "Trustee CA exceeds the probe bound"

if [[ -z "$PROBE_UUID" ]]; then
  PROBE_UUID="$(< /proc/sys/kernel/random/uuid)"
fi
[[ "$PROBE_UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
  die "probe UUID is not canonical"
probe_suffix="${PROBE_UUID%%-*}"
name="codewire-private-pull-$probe_suffix"
managed_workspace_label_yaml=""
workspace_annotation_yaml=""
if [[ "$managed_workspace_identity" == "1" ]]; then
  managed_workspace_label_yaml="    agents.x-k8s.io/sandbox-name-hash: $name"
  workspace_annotation_yaml='    codewire.sh/workspace: "true"'
fi
if [[ "$IMAGE_ROLE" == "product" ]]; then
  product_dind_yaml="$(printf '%s\n' \
    '    - name: dind' \
    "      image: $dind_image" \
    '      imagePullPolicy: Always' \
    '      command: ["/usr/local/bin/docker"]' \
    '      args: ["--version"]' \
    '      securityContext:' \
    '        privileged: true' \
    '        runAsUser: 0' \
    '        runAsGroup: 0' \
    '      volumeMounts:' \
    '        - name: secure-scratch' \
    '          mountPath: /workspace' \
    '      resources:' \
    '        requests:' \
    '          cpu: 500m' \
    '          memory: 1Gi' \
    '        limits:' \
    '          cpu: "2"' \
    '          memory: 4Gi')"
fi

registry_egress_yaml=$'    - toFQDNs:\n        - matchName: registry.example.invalid\n      toPorts:\n        - ports:\n            - port: "443"\n              protocol: TCP\n'
dns_rules_yaml=$'          rules:\n            dns:\n              - matchName: registry.example.invalid\n              - matchName: codewire-trustee-kbs.codewire-trustee.svc.cluster.local\n'
if [[ "$public_registry_egress" == "1" ]]; then
  dns_rules_yaml=""
  registry_egress_yaml=$'    - toCIDRSet:\n        - cidr: 0.0.0.0/0\n          except:\n            - 10.0.0.0/8\n            - 100.64.0.0/10\n            - 127.0.0.0/8\n            - 169.254.0.0/16\n            - 172.16.0.0/12\n            - 192.168.0.0/16\n        - cidr: ::/0\n          except:\n            - fc00::/7\n      toPorts:\n        - ports:\n            - port: "443"\n              protocol: TCP\n'
fi
if [[ "$IMAGE_ROLE" == "product" ]]; then
  registry_egress_yaml+=$'    - toFQDNs:\n        - matchName: registry.example.invalid\n      toPorts:\n        - ports:\n            - port: "443"\n              protocol: TCP\n'
fi

policy_source="$ROOT/crates/codewire-orchestration/src/sandbox/template/encoding.rs"
policy_rego="$(awk '
  /^const CODEWIRE_KATA_AGENT_POLICY_REGO: &str = r#"/ {
    sub(/^.*r#"/, "")
    print
    found = 1
    next
  }
  found && /^"#;$/ { ended = 1; exit }
  found { print }
  END { if (!found || !ended) exit 1 }
' "$policy_source")" || die "could not extract the canonical Kata agent policy"
[[ "$policy_rego" == package\ agent_policy* ]] || die "canonical Kata agent policy has an unexpected header"
[[ "$policy_rego" != *"'''"* ]] || die "canonical Kata agent policy cannot be TOML-embedded"
# The shared Rust constant is only the policy preamble. Production appends a
# CreateContainerRequest rule for the selected storage contract. This probe has
# no confidential workspace block volume, so mirror production's no-storage
# branch.
policy_rego+=$'\ndefault CreateContainerRequest := true\n'

toml_quote() {
  jq -Rs .
}

kbs_url_toml="$(printf '%s' "$kbs_url" | toml_quote)"
kbs_ca_toml="$(printf '%s' "$kbs_ca" | toml_quote)"
triple_quote="'''"
init_data="$({
  printf 'version = "0.1.0"\nalgorithm = "sha256"\n\n[data]\n'
  printf '"policy.rego" = %s\n%s\n%s\n' "$triple_quote" "$policy_rego" "$triple_quote"
  printf '\n"aa.toml" = %s\n[token_configs]\n[token_configs.kbs]\nurl = %s\ncert = %s\n%s\n' \
    "$triple_quote" "$kbs_url_toml" "$kbs_ca_toml" "$triple_quote"
  printf '\n"cdh.toml" = %s\nsocket = "unix:///run/confidential-containers/cdh.sock"\nprotected_resource_uri_prefixes = ["kbs:///default/codewire-workspace-luks/"]\n\n[kbc]\nname = "cc_kbc"\nurl = %s\nkbs_cert = %s\n%s\n' \
    "$triple_quote" "$kbs_url_toml" "$kbs_ca_toml" "$triple_quote"
} | gzip -n -c | base64 -w0)"
kernel_params="agent.image_registry_auth=$registry_auth_uri agent.image_resource_timeout_secs=$IMAGE_RESOURCE_TIMEOUT_SECS agent.guest_components_procs=confidential-data-hub agent.aa_kbc_params=cc_kbc::$kbs_url agent.log_vport=1025"
emptydir_volume_yaml=""
emptydir_mount_yaml=""
emptydir_security_yaml=""
emptydir_init_yaml=""
if [[ "$ENCRYPTED_EMPTYDIR" == "1" ]]; then
  emptydir_volume_yaml=$'  volumes:\n    - name: secure-scratch\n      emptyDir: {}\n'
  emptydir_mount_yaml=$'      volumeMounts:\n        - name: secure-scratch\n          mountPath: /tmp/codewire-secure-mount-probe\n'
  emptydir_security_yaml=$'    runAsUser: 1000\n    runAsGroup: 1000\n    fsGroup: 1000\n'
  emptydir_init_yaml="$(printf '%s\n' \
    '  initContainers:' \
    '    - name: secure-scratch-init' \
    "      image: $daemon_image" \
    '      imagePullPolicy: Always' \
    '      command: ["/usr/local/bin/cw"]' \
    '      args: ["--version"]' \
    '      volumeMounts:' \
    '        - name: secure-scratch' \
    '          mountPath: /tmp/codewire-secure-mount-probe')"
  emptydir_init_yaml+=$'\n'
fi

cat >"$manifest" <<YAML
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: $name
  namespace: $SANDBOX_NAMESPACE
spec:
  endpointSelector:
    matchLabels:
      codewire.sh/probe-id: $name
  egress:
    - toServices:
        - k8sService:
            serviceName: kube-dns
            namespace: kube-system
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
${dns_rules_yaml}
${registry_egress_yaml}    - toServices:
        - k8sService:
            serviceName: codewire-trustee-kbs
            namespace: codewire-trustee
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
---
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $SANDBOX_NAMESPACE
  labels:
    codewire.sh/probe: private-image-pull
    codewire.sh/probe-id: $name
    codewire.sh/isolation-tier: confidential
${managed_workspace_label_yaml}
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: $init_data
    io.katacontainers.config.hypervisor.kernel_params: "$kernel_params"
${workspace_annotation_yaml}
spec:
  automountServiceAccountToken: false
  serviceAccountName: codewire-sandbox
  enableServiceLinks: false
  restartPolicy: Never
  runtimeClassName: confidential
  securityContext:
    seccompProfile:
      type: RuntimeDefault
${emptydir_security_yaml}  nodeSelector:
    kubernetes.io/hostname: $NODE
    node.codewire.sh/confidential-snp: "true"
  tolerations:
    - key: node.codewire.sh/runtime-candidate
      operator: Equal
      value: "true"
      effect: NoSchedule
${emptydir_volume_yaml}${emptydir_init_yaml}  containers:
    - name: $probe_container_name
      image: $probe_image
      imagePullPolicy: Always
      command: ["$probe_command"]
      args: $probe_args_yaml
      securityContext:
        allowPrivilegeEscalation: $probe_allow_privilege_escalation
        readOnlyRootFilesystem: $probe_read_only_root_filesystem
        privileged: $probe_privileged
        runAsNonRoot: $probe_run_as_non_root
        runAsUser: $probe_uid
        runAsGroup: $probe_gid
        capabilities:
          drop: ["ALL"]
${emptydir_mount_yaml}      resources:
        requests:
          cpu: 100m
          memory: $probe_memory_request
        limits:
          cpu: 500m
          memory: $probe_memory_limit
${product_dind_yaml}
YAML
chmod 600 "$manifest"

collect_evidence() {
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$name" -o json >"$pod_evidence" 2>/dev/null || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" get events \
    --field-selector "involvedObject.name=$name" -o json >"$event_evidence" 2>/dev/null || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$name" -c "$probe_container_name" >"$container_log" 2>/dev/null || true
}

# Invoked by the EXIT trap through on_exit.
# shellcheck disable=SC2329
cleanup() {
  if [[ "$KEEP_PROBE" == "1" ]]; then
    log "keeping probe resources by request: $name"
    return
  fi
  kubectl_dev -n "$SANDBOX_NAMESPACE" delete pod "$name" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" delete ciliumnetworkpolicy "$name" --ignore-not-found >/dev/null 2>&1 || true
}

# Invoked by name from trap.
# shellcheck disable=SC2329
on_exit() {
  local rc="$?"
  trap - EXIT
  collect_evidence
  cleanup
  exit "$rc"
}

trap on_exit EXIT

log "evidence=$EVIDENCE_DIR"
log "stage=apply image_role=$IMAGE_ROLE exact_image=true encrypted_emptydir=$ENCRYPTED_EMPTYDIR rest_disabled=$ASSERT_REST_DISABLED"
kubectl_dev apply -f "$manifest" >/dev/null

deadline=$((SECONDS + WAIT_SECONDS))
while (( SECONDS < deadline )); do
  pod_json="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$name" -o json 2>/dev/null || true)"
  phase="$(jq -r '.status.phase // ""' <<<"$pod_json" 2>/dev/null || true)"
  case "$phase" in
    Succeeded)
      collect_evidence
      if [[ "$ASSERT_REST_DISABLED" == "1" ]] && \
         ! grep -qx 'coco_rest_disabled=passed' "$container_log"; then
        die "probe completed without the required disabled-REST receipt"
      fi
      log "stage=complete image_role=$IMAGE_ROLE guest_pull=passed"
      exit 0
      ;;
    Failed)
      collect_evidence
      die "probe Pod failed; full events are in $event_evidence"
      ;;
  esac

  sandbox_ready="$(jq -r '
    [.status.conditions[]? | select(.type == "PodReadyToStartContainers") | .status]
    | first // ""
  ' <<<"$pod_json" 2>/dev/null || true)"
  if [[ "$sandbox_ready" == "False" ]]; then
    sandbox_events="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get events \
      --field-selector "involvedObject.name=$name" -o json 2>/dev/null || true)"
    sandbox_policy_failure="$(jq -r '
      any(.items[]?;
        .reason == "FailedCreatePodSandBox"
        and ((.message // "") | contains(
          "CreateContainerRequest: internal error policy check: unexpected eval_query result len"
        ))
      )
    ' <<<"$sandbox_events" 2>/dev/null || true)"
    if [[ "$sandbox_policy_failure" == "true" ]]; then
      collect_evidence
      die "probe reached terminal sandbox state reason=AgentPolicyEvaluation; full events are in $event_evidence"
    fi
  fi

  terminal_wait="$(jq -r '
    [.status.initContainerStatuses[]?, .status.containerStatuses[]?]
    | map(select(
        .state.waiting.reason == "ErrImagePull"
        or .state.waiting.reason == "ImagePullBackOff"
        or .state.waiting.reason == "CreateContainerError"
        or .state.waiting.reason == "RunContainerError"
        or .state.waiting.reason == "InvalidImageName"
      ))
    | first
    | if . == null then "" else [.name, .state.waiting.reason] | @tsv end
  ' <<<"$pod_json" 2>/dev/null || true)"
  if [[ -n "$terminal_wait" ]]; then
    IFS=$'\t' read -r terminal_container terminal_reason <<<"$terminal_wait"
    collect_evidence
    die "probe reached terminal container state container=$terminal_container reason=$terminal_reason; full events are in $event_evidence"
  fi
  sleep 2
done

collect_evidence
die "probe timed out before a terminal result; full events are in $event_evidence"
