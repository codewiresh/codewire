#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
KUBE_CONTEXT="${KUBE_CONTEXT:-dev-cluster}"
SERVER_NAMESPACE="${CODEWIRE_SERVER_NAMESPACE:-dev}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
NODE="${CONFIDENTIAL_SNP_NODE:-cw-dev-prod-node-1}"
WAIT_SECONDS="${PRIVATE_PULL_WAIT_SECONDS:-180}"
KEEP_PROBE="${PRIVATE_PULL_KEEP_PROBE:-0}"
PROBE_UUID="${PRIVATE_PULL_PROBE_UUID:-}"
EVIDENCE_DIR="${EVIDENCE_DIR:-}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/smoke-dev-private-image-pull.sh [options]

Runs one short-lived confidential Pod that pulls the exact private gateway
image promoted into Dev. The probe exercises Kata guest CDH, Trustee
attestation, and KBS registry authorization without creating a Codewire
environment, PVC, or support image.

Options:
  --node NAME          Confidential SNP node (default: cw-dev-prod-node-1)
  --wait-seconds N     Terminal wait horizon (default: 180)
  --keep-probe         Keep the Pod and CiliumNetworkPolicy for inspection
  --evidence-dir DIR   Store private evidence in DIR
  -h, --help           Show this help

Run this script only through the Infra Kubernetes access wrapper. It reads
ConfigMaps but no Secrets. Its temporary Cilium policy permits only exact
cluster DNS, the promoted Nexus hostname on TCP 443, and Trustee KBS on its
exact namespace/port.
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
    --keep-probe)
      KEEP_PROBE=1
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
[[ "$KEEP_PROBE" == "0" || "$KEEP_PROBE" == "1" ]] || die "PRIVATE_PULL_KEEP_PROBE must be 0 or 1"
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
  if jq -e '.data.SANDBOX_GATEWAY_IMAGE != null' "$candidate" >/dev/null; then
    [[ -z "$active_configmap" ]] || die "multiple runtime ConfigMaps provide SANDBOX_GATEWAY_IMAGE"
    active_configmap="$configmap_name"
    mv "$candidate" "$configmap_json"
  else
    rm -f "$candidate"
  fi
done
[[ -n "$active_configmap" ]] || die "active orchestration runtime ConfigMap was not found"

gateway_image="$(jq -er '.data.SANDBOX_GATEWAY_IMAGE' "$configmap_json")"
kbs_url="$(jq -er '.data.SANDBOX_KATA_COCO_KBS_URL' "$configmap_json")"
registry_auth_uri="$(jq -er '.data.SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI' "$configmap_json")"
coco_enabled="$(jq -er '.data.SANDBOX_KATA_COCO_INIT_DATA_ENABLED' "$configmap_json")"

[[ "$gateway_image" =~ ^nexus\.example\.invalid/oci-approved/codewire/gateway@sha256:[a-f0-9]{64}$ ]] || \
  die "promoted gateway image is not an exact approved Nexus digest"
[[ "$kbs_url" == "https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080" ]] || \
  die "unexpected Trustee KBS URL"
[[ "$registry_auth_uri" == "kbs:///default/containers/auth" ]] || \
  die "unexpected KBS registry-auth resource URI"
[[ "$coco_enabled" == "true" ]] || die "Dev CoCo init-data is not enabled"

kubectl_dev -n "$SANDBOX_NAMESPACE" get serviceaccount codewire-sandbox -o json >"$service_account_json"
jq -e 'any(.imagePullSecrets[]?; .name == "nexus-registry")' "$service_account_json" >/dev/null || \
  die "codewire-sandbox ServiceAccount does not select the Nexus pull Secret"

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

toml_quote() {
  jq -Rs .
}

kbs_url_toml="$(printf '%s' "$kbs_url" | toml_quote)"
kbs_ca_toml="$(printf '%s' "$kbs_ca" | toml_quote)"
uuid_toml="$(printf '%s' "$PROBE_UUID" | toml_quote)"
storage_registry="$(jq -cn --arg id "$PROBE_UUID" --arg uri "kbs:///default/codewire-workspace-luks/$PROBE_UUID" \
  '{version:1,volumes:[{profile:"luks2-integrity-ext4",volumeId:$id,keyUri:$uri}]}')"
storage_registry_toml="$(printf '%s' "$storage_registry" | toml_quote)"
triple_quote="'''"
init_data="$({
  printf 'version = "0.1.0"\nalgorithm = "sha256"\n\n[data]\n'
  printf '"policy.rego" = %s\n%s\n%s\n' "$triple_quote" "$policy_rego" "$triple_quote"
  printf '"codewire_workspace_storage_key_id" = %s\n' "$uuid_toml"
  printf '"confidential_storage" = %s\n' "$storage_registry_toml"
  printf '\n"aa.toml" = %s\n[token_configs]\n[token_configs.kbs]\nurl = %s\ncert = %s\n%s\n' \
    "$triple_quote" "$kbs_url_toml" "$kbs_ca_toml" "$triple_quote"
  printf '\n"cdh.toml" = %s\nsocket = "unix:///run/confidential-containers/cdh.sock"\n\n[kbc]\nname = "cc_kbc"\nurl = %s\nkbs_cert = %s\n%s\n' \
    "$triple_quote" "$kbs_url_toml" "$kbs_ca_toml" "$triple_quote"
} | gzip -n -c | base64 -w0)"
kernel_params="agent.image_registry_auth=$registry_auth_uri agent.guest_components_rest_api=resource agent.aa_kbc_params=cc_kbc::$kbs_url"

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
          rules:
            dns:
              - matchName: nexus.example.invalid
              - matchName: codewire-trustee-kbs.codewire-trustee.svc.cluster.local
    - toFQDNs:
        - matchName: nexus.example.invalid
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    - toServices:
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
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: $init_data
    io.katacontainers.config.hypervisor.kernel_params: "$kernel_params"
spec:
  automountServiceAccountToken: false
  serviceAccountName: codewire-sandbox
  enableServiceLinks: false
  restartPolicy: Never
  runtimeClassName: confidential
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  nodeSelector:
    kubernetes.io/hostname: $NODE
    node.codewire.sh/confidential-snp: "true"
  tolerations:
    - key: node.codewire.sh/runtime-candidate
      operator: Equal
      value: "true"
      effect: NoSchedule
  containers:
    - name: version
      image: $gateway_image
      imagePullPolicy: Always
      command: ["/usr/local/bin/cw"]
      args: ["--version"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        capabilities:
          drop: ["ALL"]
      resources:
        requests:
          cpu: 100m
          memory: 128Mi
        limits:
          cpu: 500m
          memory: 512Mi
YAML
chmod 600 "$manifest"

collect_evidence() {
  kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$name" -o json >"$pod_evidence" 2>/dev/null || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" get events \
    --field-selector "involvedObject.name=$name" -o json >"$event_evidence" 2>/dev/null || true
  kubectl_dev -n "$SANDBOX_NAMESPACE" logs "$name" -c version >"$container_log" 2>/dev/null || true
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
log "stage=apply exact_private_image=true"
kubectl_dev apply -f "$manifest" >/dev/null

deadline=$((SECONDS + WAIT_SECONDS))
while (( SECONDS < deadline )); do
  pod_json="$(kubectl_dev -n "$SANDBOX_NAMESPACE" get pod "$name" -o json 2>/dev/null || true)"
  phase="$(jq -r '.status.phase // ""' <<<"$pod_json" 2>/dev/null || true)"
  case "$phase" in
    Succeeded)
      collect_evidence
      log "stage=complete private_image_guest_pull=passed"
      exit 0
      ;;
    Failed)
      collect_evidence
      die "probe Pod failed; full events are in $event_evidence"
      ;;
  esac

  terminal_wait="$(jq -r '
    [.status.containerStatuses[]?.state.waiting.reason]
    | map(select(. == "ErrImagePull" or . == "ImagePullBackOff" or . == "CreateContainerError" or . == "RunContainerError" or . == "InvalidImageName"))
    | first // ""
  ' <<<"$pod_json" 2>/dev/null || true)"
  if [[ -n "$terminal_wait" ]]; then
    collect_evidence
    die "probe reached terminal container state $terminal_wait; full events are in $event_evidence"
  fi
  sleep 2
done

collect_evidence
die "probe timed out before a terminal result; full events are in $event_evidence"
