#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
SCRIPT="$ROOT/scripts/runtime/confidential/smoke-dev-private-image-pull.sh"
mkdir -p "$ROOT/.tmp"
TMP="$(mktemp -d "$ROOT/.tmp/test-private-image-pull.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
chmod 700 "$TMP"

for command in jq yq base64 gzip; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing test command: %s\n' "$command" >&2
    exit 1
  }
done

cat >"$TMP/kubectl" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_KUBECTL_CALLS"
if [[ "${1:-}" == "--context" ]]; then
  shift 2
fi

case "$*" in
  '-n dev get deployment codewire-orchestration -o json')
    jq -cn '{spec:{template:{spec:{containers:[{name:"orchestration",envFrom:[{secretRef:{name:"codewire-secrets"}},{configMapRef:{name:"codewire-config-live"}}]}]}}}}'
    ;;
  '-n dev get configmap codewire-config-live -o json')
    jq -cn '{data:{SANDBOX_GATEWAY_IMAGE:"nexus.example.invalid/oci-approved/codewire/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",SANDBOX_KATA_COCO_KBS_URL:"https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080",SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI:"kbs:///default/containers/auth",SANDBOX_KATA_COCO_INIT_DATA_ENABLED:"true"}}'
    ;;
  '-n dev get configmap codewire-trustee-kbs-ca -o json')
    jq -cn '{data:{"ca.crt":"-----BEGIN CERTIFICATE-----\nPUBLIC-TEST-CA\n-----END CERTIFICATE-----\n"}}'
    ;;
  '-n dev-sandboxes get serviceaccount codewire-sandbox -o json')
    jq -cn '{imagePullSecrets:[{name:"nexus-registry"}]}'
    ;;
  'apply -f '*)
    cp "${*: -1}" "$FAKE_KUBECTL_CAPTURE/probe.yaml"
    ;;
  '-n dev-sandboxes get pod codewire-private-pull-be31063a -o json')
    if [[ "${FAKE_POD_MODE:-success}" == "init_failure" ]]; then
      jq -cn '{status:{phase:"Pending",initContainerStatuses:[{name:"secure-scratch-init",state:{waiting:{reason:"CreateContainerError"}}}],containerStatuses:[{name:"version",state:{waiting:{reason:"PodInitializing"}}}]}}'
    elif [[ "${FAKE_POD_MODE:-success}" == "failure" ]]; then
      jq -cn '{status:{phase:"Pending",containerStatuses:[{name:"version",state:{waiting:{reason:"CreateContainerError"}}}]}}'
    else
      jq -cn '{status:{phase:"Succeeded",containerStatuses:[{state:{terminated:{exitCode:0}}}]}}'
    fi
    ;;
  '-n dev-sandboxes get events --field-selector involvedObject.name=codewire-private-pull-be31063a -o json')
    jq -cn '{items:[{type:"Warning",reason:"Failed",message:"guest image pull failed: Not authorized"}]}'
    ;;
  '-n dev-sandboxes logs codewire-private-pull-be31063a -c version')
    printf 'cw 0.8.1\n'
    ;;
  '-n dev-sandboxes delete pod codewire-private-pull-be31063a --ignore-not-found --wait=false'|\
  '-n dev-sandboxes delete ciliumnetworkpolicy codewire-private-pull-be31063a --ignore-not-found')
    ;;
  *)
    printf 'unexpected kubectl arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
FAKE
chmod 755 "$TMP/kubectl"

export FAKE_KUBECTL_CALLS="$TMP/kubectl.calls"
export FAKE_KUBECTL_CAPTURE="$TMP/capture"
mkdir -p "$FAKE_KUBECTL_CAPTURE"

success_evidence="$TMP/success"
KUBECTL_BIN="$TMP/kubectl" \
KUBE_CONTEXT='' \
PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
EVIDENCE_DIR="$success_evidence" \
  "$SCRIPT" --wait-seconds 5 --encrypted-emptydir

manifest="$FAKE_KUBECTL_CAPTURE/probe.yaml"
[[ "$(yq -r 'select(.kind == "CiliumNetworkPolicy") | .metadata.name' "$manifest")" == \
  'codewire-private-pull-be31063a' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.runtimeClassName' "$manifest")" == 'confidential' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.automountServiceAccountToken' "$manifest")" == 'false' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.serviceAccountName' "$manifest")" == 'codewire-sandbox' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.securityContext.seccompProfile.type' "$manifest")" == \
  'RuntimeDefault' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .metadata.labels."codewire.sh/isolation-tier"' "$manifest")" == \
  'confidential' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .metadata.annotations."io.katacontainers.config.hypervisor.kernel_params"' "$manifest")" == \
  *'agent.log_vport=1025'* ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.volumes[] | select(.name == "secure-scratch") | .emptyDir' "$manifest")" == \
  '{}' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.securityContext.fsGroup' "$manifest")" == '1000' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.initContainers[0].name' "$manifest")" == \
  'secure-scratch-init' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.initContainers[0].volumeMounts[0].name' "$manifest")" == \
  'secure-scratch' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].volumeMounts[] | select(.name == "secure-scratch") | .mountPath' "$manifest")" == \
  '/tmp/codewire-secure-mount-probe' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].image' "$manifest")" == \
  'nexus.example.invalid/oci-approved/codewire/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
rg -F 'matchName: nexus.example.invalid' "$manifest" >/dev/null
rg -F 'matchName: codewire-trustee-kbs.codewire-trustee.svc.cluster.local' "$manifest" >/dev/null
policy_json="$(yq -o=json 'select(.kind == "CiliumNetworkPolicy")' "$manifest")"
jq -e '
  [.spec.egress[] | .toServices[]?.k8sService
    | select(.serviceName == "kube-dns" and .namespace == "kube-system")]
  | length == 1
' <<<"$policy_json" >/dev/null
jq -e '
  [.spec.egress[] | .toServices[]?.k8sService
    | select(.serviceName == "codewire-trustee-kbs" and .namespace == "codewire-trustee")]
  | length == 1
' <<<"$policy_json" >/dev/null
if rg -q '0\.0\.0\.0/0|kind: Secret|imagePullSecrets' "$manifest"; then
  printf '%s\n' 'private pull probe broadened egress or gained a credential dependency' >&2
  exit 1
fi

encoded="$(yq -r 'select(.kind == "Pod") | .metadata.annotations."io.katacontainers.config.hypervisor.cc_init_data"' "$manifest")"
decoded="$(printf '%s' "$encoded" | base64 -d | gzip -dc)"
rg -F 'package agent_policy' <<<"$decoded" >/dev/null
rg -F '"codewire_workspace_storage_key_id" = "be31063a-8ec8-46d5-aa17-75cda1729370"' <<<"$decoded" >/dev/null
cdh_config="$(yq -p=toml -r '.data."cdh.toml"' <<<"$decoded")"
[[ "$(yq -p=toml -r '.kbc.kbs_cert' <<<"$cdh_config")" == \
  $'-----BEGIN CERTIFICATE-----\nPUBLIC-TEST-CA\n-----END CERTIFICATE-----' ]]
if rg -q '^\[image\]|extra_root_certificates' <<<"$decoded"; then
  printf '%s\n' 'private pull probe emitted a partial image table that suppresses kernel auth' >&2
  exit 1
fi
rg -F 'delete pod codewire-private-pull-be31063a' "$FAKE_KUBECTL_CALLS" >/dev/null
if rg -q 'get secret| secrets ' "$FAKE_KUBECTL_CALLS"; then
  printf '%s\n' 'private pull probe attempted to read a Secret' >&2
  exit 1
fi
if rg -F 'get configmap null' "$FAKE_KUBECTL_CALLS"; then
  printf '%s\n' 'private pull probe treated a Secret reference as a ConfigMap' >&2
  exit 1
fi

failure_evidence="$TMP/failure"
if FAKE_POD_MODE=failure \
  KUBECTL_BIN="$TMP/kubectl" \
  KUBE_CONTEXT='' \
  PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
  EVIDENCE_DIR="$failure_evidence" \
    "$SCRIPT" --wait-seconds 5 >"$TMP/failure.out" 2>"$TMP/failure.err"; then
  printf '%s\n' 'terminal guest pull failure unexpectedly passed' >&2
  exit 1
fi
rg -F 'terminal container state container=version reason=CreateContainerError' "$TMP/failure.err" >/dev/null
rg -F 'guest image pull failed: Not authorized' "$failure_evidence/events.json" >/dev/null

init_failure_evidence="$TMP/init-failure"
if FAKE_POD_MODE=init_failure \
  KUBECTL_BIN="$TMP/kubectl" \
  KUBE_CONTEXT='' \
  PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
  EVIDENCE_DIR="$init_failure_evidence" \
    "$SCRIPT" --wait-seconds 5 --encrypted-emptydir >"$TMP/init-failure.out" 2>"$TMP/init-failure.err"; then
  printf '%s\n' 'terminal init-container failure unexpectedly passed' >&2
  exit 1
fi
rg -F 'terminal container state container=secure-scratch-init reason=CreateContainerError' \
  "$TMP/init-failure.err" >/dev/null

printf '%s\n' 'test-smoke-dev-private-image-pull: PASS'
