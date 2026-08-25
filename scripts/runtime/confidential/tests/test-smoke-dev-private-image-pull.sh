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
    jq -cn '{data:{SANDBOX_GATEWAY_IMAGE:"nexus.example.invalid/oci-approved/codewire/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",SANDBOX_DIND_IMAGE:"docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",SANDBOX_KATA_COCO_KBS_URL:"https://codewire-trustee-kbs.codewire-trustee.svc.cluster.local:8080",SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI:"kbs:///default/containers/auth",SANDBOX_KATA_COCO_TEST_RESOURCE_URI:"kbs:///default/codewire/runtime-test-resource",SANDBOX_KATA_COCO_INIT_DATA_ENABLED:"true"}}'
    ;;
  '-n flux-system get kustomization codewire-deploy-workloads-dev -o json')
    jq -cn '{metadata:{annotations:{"deploy.codewire.sh/source-sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},status:{lastAppliedRevision:"main@sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
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
    elif [[ "${FAKE_POD_MODE:-success}" == "resource_failure" ]]; then
      jq -cn '{status:{phase:"Failed",containerStatuses:[{name:"version",state:{terminated:{exitCode:22}}}]}}'
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
    if [[ "${FAKE_LOG_MODE:-success}" == "resource_failure" ]]; then
      printf 'cdh_http_status=500\n'
    else
      printf 'cdh_http_status=200\n'
      printf 'cdh_test_resource=passed\n'
    fi
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

cat >"$TMP/skopeo" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
case "${*: -1}" in
  docker://ghcr.io/codewiresh/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
    jq -cn '{Digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",Labels:{"org.opencontainers.image.revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
    ;;
  docker://ghcr.io/codewiresh/workspace:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
    jq -cn '{Digest:"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",Labels:{"org.opencontainers.image.revision":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}'
    ;;
  docker://docker.io/library/docker@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c)
    jq -cn '{Digest:"sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c",Labels:{}}'
    ;;
  *)
    printf 'unexpected skopeo arguments: %s\n' "$*" >&2
    exit 64
    ;;
esac
FAKE
chmod 755 "$TMP/skopeo"
export PATH="$TMP:$PATH"

export FAKE_KUBECTL_CALLS="$TMP/kubectl.calls"
export FAKE_KUBECTL_CAPTURE="$TMP/capture"
mkdir -p "$FAKE_KUBECTL_CAPTURE"

success_evidence="$TMP/success"
KUBECTL_BIN="$TMP/kubectl" \
KUBE_CONTEXT='' \
PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
EVIDENCE_DIR="$success_evidence" \
  "$SCRIPT" --wait-seconds 301 --encrypted-emptydir

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
  *'agent.image_resource_timeout_secs=300'* ]]
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

workspace_evidence="$TMP/workspace"
KUBECTL_BIN="$TMP/kubectl" \
KUBE_CONTEXT='' \
PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
EVIDENCE_DIR="$workspace_evidence" \
  "$SCRIPT" --wait-seconds 301 --image-role workspace
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].image' "$manifest")" == \
  'ghcr.io/codewiresh/workspace@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].securityContext.runAsUser' "$manifest")" == '1000' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].resources.limits.memory' "$manifest")" == '20480Mi' ]]

product_evidence="$TMP/product"
KUBECTL_BIN="$TMP/kubectl" \
KUBE_CONTEXT='' \
PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
EVIDENCE_DIR="$product_evidence" \
  "$SCRIPT" --wait-seconds 301 --image-role product --assert-test-resource
[[ "$(yq -r 'select(.kind == "Pod") | .spec.initContainers[0].image' "$manifest")" == \
  'nexus.example.invalid/oci-approved/codewire/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].image' "$manifest")" == \
  'ghcr.io/codewiresh/workspace@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].resources.limits.memory' "$manifest")" == '16384Mi' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[1].name' "$manifest")" == 'dind' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[1].resources.limits.memory' "$manifest")" == '4Gi' ]]
rg -qF 'http://127.0.0.1:8006/cdh/resource/' "$manifest"
rg -qF 'curl --max-time 310' "$manifest"
rg -qF 'cdh_http_status=%s' "$manifest"
product_script="$(yq -r 'select(.kind == "Pod") | .spec.containers[0].args[1]' "$manifest")"
rg -qF 'response="$(curl ' <<<"$product_script"
if rg -qF '/tmp/cdh-resource.out' <<<"$product_script"; then
  printf '%s\n' 'resource probe writes through the read-only workspace root filesystem' >&2
  exit 1
fi
product_policy_json="$(yq -o=json 'select(.kind == "CiliumNetworkPolicy")' "$manifest")"
jq -e '[.spec.egress[] | select(.toFQDNs[0].matchName == "nexus.example.invalid")] | length == 1' \
  <<<"$product_policy_json" >/dev/null
workspace_policy_json="$(yq -o=json 'select(.kind == "CiliumNetworkPolicy")' "$manifest")"
jq -e '
  any(.spec.egress[]?.toCIDRSet[]?;
    .cidr == "0.0.0.0/0" and (.except | index("10.0.0.0/8")))
' <<<"$workspace_policy_json" >/dev/null

resource_failure_evidence="$TMP/resource-failure"
if FAKE_POD_MODE=resource_failure \
  FAKE_LOG_MODE=resource_failure \
  KUBECTL_BIN="$TMP/kubectl" \
  KUBE_CONTEXT='' \
  PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
  EVIDENCE_DIR="$resource_failure_evidence" \
    "$SCRIPT" --wait-seconds 301 --image-role workspace --assert-test-resource \
      >"$TMP/resource-failure.out" 2>"$TMP/resource-failure.err"; then
  printf '%s\n' 'failed CDH resource request unexpectedly passed' >&2
  exit 1
fi
rg -F 'stage=resource image_role=workspace http_status=500' "$TMP/resource-failure.err" >/dev/null
rg -F 'cdh_http_status=500' "$resource_failure_evidence/container.log" >/dev/null

dind_evidence="$TMP/dind"
KUBECTL_BIN="$TMP/kubectl" \
KUBE_CONTEXT='' \
PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
EVIDENCE_DIR="$dind_evidence" \
  "$SCRIPT" --wait-seconds 301 --image-role dind
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].image' "$manifest")" == \
  'docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].securityContext.privileged' "$manifest")" == 'true' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].name' "$manifest")" == 'dind' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .metadata.annotations."codewire.sh/workspace"' "$manifest")" == 'true' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .metadata.labels."agents.x-k8s.io/sandbox-name-hash"' "$manifest")" == \
  'codewire-private-pull-be31063a' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].securityContext.runAsUser' "$manifest")" == '0' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].securityContext.allowPrivilegeEscalation' "$manifest")" == 'true' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].securityContext.readOnlyRootFilesystem' "$manifest")" == 'false' ]]
[[ "$(yq -r 'select(.kind == "Pod") | .spec.containers[0].resources.limits.memory' "$manifest")" == '20480Mi' ]]

failure_evidence="$TMP/failure"
if FAKE_POD_MODE=failure \
  KUBECTL_BIN="$TMP/kubectl" \
  KUBE_CONTEXT='' \
  PRIVATE_PULL_PROBE_UUID='be31063a-8ec8-46d5-aa17-75cda1729370' \
  EVIDENCE_DIR="$failure_evidence" \
    "$SCRIPT" --wait-seconds 301 >"$TMP/failure.out" 2>"$TMP/failure.err"; then
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
    "$SCRIPT" --wait-seconds 301 --encrypted-emptydir >"$TMP/init-failure.out" 2>"$TMP/init-failure.err"; then
  printf '%s\n' 'terminal init-container failure unexpectedly passed' >&2
  exit 1
fi
rg -F 'terminal container state container=secure-scratch-init reason=CreateContainerError' \
  "$TMP/init-failure.err" >/dev/null

printf '%s\n' 'test-smoke-dev-private-image-pull: PASS'
