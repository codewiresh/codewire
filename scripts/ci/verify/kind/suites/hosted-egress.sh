#!/usr/bin/env bash
# Hosted egress on Kind (#6387): verifies cw-egress DaemonSet scheduling and
# resolver wiring, Kind's gateway stand-in with live ingress-nginx endpoints,
# verified-TLS DERP, interception CA wiring, and broker-mode Sandbox admission
# (Kata stand-in `commodity` on any Kind cluster, plus full `standard` VM
# checks including `cw exec`, DNS, allowed/refused curl + policy log, Docker
# busybox, and `cw-egress` restart when `standard` runtime images are present).
#
# All cluster mutations are reversible: the EXIT trap restores
# ConfigMap/codewire-hosted-egress, Deployment/codewire-orchestration, and
# deletes every kind-egress-* environment and policy this suite creates.
set -euo pipefail

if [ "${KIND_E2E_COMMON_LOADED:-0}" != 1 ]; then
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"
fi

HOSTED_EGRESS_ORG=org_contract_2
HOSTED_EGRESS_CREATED_ENVS=()
HOSTED_EGRESS_CREATED_POLICIES=()
HOSTED_EGRESS_ORIG_ENABLED=""
HOSTED_EGRESS_ORIG_PROFILE=""
HOSTED_EGRESS_ORIG_DAEMON_IMAGE=""
HOSTED_EGRESS_ORIG_STD_DISK_REF=""
HOSTED_EGRESS_MUTATED=0
HOSTED_EGRESS_KATA_PV=""
HOSTED_EGRESS_KATA_LOOP=""
HOSTED_EGRESS_KATA_IMG=""
HOSTED_EGRESS_KATA_POD=""
HOSTED_EGRESS_KATA_DAEMON_TAG=""

run_retained_hosted_egress_suite() {
  require_kind_errexit
  require_tool curl
  require_tool docker
  require_tool jq
  require_tool kind
  require_tool kubectl
  require_tool python3

  trap hosted_egress_suite_cleanup EXIT
  validate_retained_cluster
  build_retained_kind_smokes hosted-egress

  hosted_egress_verify_topology
  hosted_egress_capture_state

  local cli_home
  cli_home="$(mktemp -d "${TMPDIR:-/tmp}/kind-egress-cli.XXXXXX")"
  chmod 700 "$cli_home"
  KIND_CREDENTIAL_CLI_HOME="$cli_home"
  # prepare_kind_credential_cli requires tmpfs; fall back to /dev/shm when
  # TMPDIR is not tmpfs.
  if [ "$(stat -f -c %T "$cli_home" 2>/dev/null || true)" != tmpfs ]; then
    rm -rf "$cli_home"
    cli_home="$(mktemp -d "/dev/shm/kind-egress-cli.XXXXXX")"
    chmod 700 "$cli_home"
    KIND_CREDENTIAL_CLI_HOME="$cli_home"
  fi
  prepare_kind_credential_cli
  kind_credential_cli org set "$HOSTED_EGRESS_ORG" >/dev/null

  hosted_egress_enable_switch
  hosted_egress_verify_kata_standin
  local standard_runtime_img standard_disk_img
  standard_runtime_img="$(kubectl -n "$NS" get configmap/codewire-standard-runtime \
    -o 'jsonpath={.data.SANDBOX_STANDARD_RUNTIME_IMAGE}' 2>/dev/null || true)"
  standard_disk_img="$(kubectl -n "$NS" get configmap/codewire-standard-runtime \
    -o 'jsonpath={.data.SANDBOX_STANDARD_IMAGE_DISK}' 2>/dev/null || true)"
  if [ -z "$standard_runtime_img" ]; then
    standard_runtime_img="$(kubectl -n "$NS" get deployment/codewire-orchestration \
      -o 'jsonpath={.spec.template.spec.containers[?(@.name=="orchestration")].env[?(@.name=="SANDBOX_STANDARD_RUNTIME_IMAGE")].value}')"
  fi
  if [ -z "$standard_disk_img" ]; then
    standard_disk_img="$(kubectl -n "$NS" get deployment/codewire-orchestration \
      -o 'jsonpath={.spec.template.spec.containers[?(@.name=="orchestration")].env[?(@.name=="SANDBOX_STANDARD_IMAGE_DISK")].value}')"
  fi
  if [ -n "$standard_runtime_img" ] && [ -n "$standard_disk_img" ]; then
    hosted_egress_verify_standard_journey "$standard_disk_img"
  else
    log "standard runtime images are not configured on this cluster; skipping standard VM checks"
  fi
  log "retained hosted-egress suite green"
}

# shellcheck disable=SC2329 # Invoked by the EXIT trap.
hosted_egress_suite_cleanup() {
  local status=$? env_id policy_name restore_status
  set +e
  if [ -n "${KIND_CREDENTIAL_CLI_HOME:-}" ] && [ -d "${KIND_CREDENTIAL_CLI_HOME:-}" ]; then
    for env_id in "${HOSTED_EGRESS_CREATED_ENVS[@]}"; do
      kind_credential_cli --cloud rm "$env_id" --yes --output json >/dev/null 2>&1
    done
    for policy_name in "${HOSTED_EGRESS_CREATED_POLICIES[@]}"; do
      local del_rc
      for _ in $(seq 1 15); do
        kind_credential_cli --cloud policy delete "$policy_name" >/dev/null 2>&1
        del_rc=$?
        [ "$del_rc" = 0 ] && break
        sleep 1
      done
    done
    rm -rf -- "$KIND_CREDENTIAL_CLI_HOME"
  fi
  if [ "$HOSTED_EGRESS_MUTATED" = 1 ]; then
    hosted_egress_restore_state
    restore_status=$?
    [ "$restore_status" = 0 ] || status=1
  fi
  hosted_egress_cleanup_kata_block_pv
  (exit "$status")
  retained_suite_cleanup
}

hosted_egress_cleanup_kata_block_pv() {
  local node="${KIND_CLUSTER_NAME}-control-plane"
  if [ -n "${HOSTED_EGRESS_KATA_POD:-}" ]; then
    kubectl -n "$SANDBOX_NS" delete pod "$HOSTED_EGRESS_KATA_POD" --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1 || true
    HOSTED_EGRESS_KATA_POD=""
  fi
  if [ -n "${HOSTED_EGRESS_KATA_PV:-}" ]; then
    kubectl delete pv "$HOSTED_EGRESS_KATA_PV" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    HOSTED_EGRESS_KATA_PV=""
  fi
  if [ -n "${HOSTED_EGRESS_KATA_LOOP:-}" ]; then
    docker exec "$node" losetup -d "$HOSTED_EGRESS_KATA_LOOP" >/dev/null 2>&1 || true
    HOSTED_EGRESS_KATA_LOOP=""
  fi
  if [ -n "${HOSTED_EGRESS_KATA_IMG:-}" ]; then
    docker exec "$node" rm -f "$HOSTED_EGRESS_KATA_IMG" >/dev/null 2>&1 || true
    HOSTED_EGRESS_KATA_IMG=""
  fi
  if [ -n "${HOSTED_EGRESS_KATA_DAEMON_TAG:-}" ]; then
    docker rmi -f "$HOSTED_EGRESS_KATA_DAEMON_TAG" >/dev/null 2>&1 || true
    HOSTED_EGRESS_KATA_DAEMON_TAG=""
  fi
}

# Kind's local-path-provisioner provisions only Filesystem PVCs, whereas the
# Kata stand-in (commodity) uses a raw Block PVC. Provide a temporary
# loop-backed local Block PV on the Kind node so the Kata stand-in schedules
# and reaches hosted-egress-tun + cw-egress admission.
hosted_egress_create_kata_block_pv() {
  local node="${KIND_CLUSTER_NAME}-control-plane" pv_name img_path loop_dev
  pv_name="kind-egress-kata-block-$(date +%s)"
  img_path="/var/local-path-provisioner/${pv_name}.img"
  docker exec "$node" sh -ec "
    for n in \$(seq 0 15); do
      [ -b \"/dev/loop\${n}\" ] || mknod -m 0660 \"/dev/loop\${n}\" b 7 \"\$n\"
    done
    truncate -s 2G '${img_path}'
  "
  HOSTED_EGRESS_KATA_IMG="$img_path"
  loop_dev="$(docker exec "$node" losetup -f --show "$img_path")"
  [ -n "$loop_dev" ] || {
    echo "::error::could not attach loop device on ${node} for Kata stand-in Block PV" >&2
    return 1
  }
  HOSTED_EGRESS_KATA_LOOP="$loop_dev"
  HOSTED_EGRESS_KATA_PV="$pv_name"
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${pv_name}
spec:
  capacity:
    storage: 2Gi
  volumeMode: Block
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: standard
  local:
    path: ${loop_dev}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - ${node}
YAML
}

hosted_egress_verify_topology() {
  local node label ready_count dns_policy dns_ns gw_ip endpoints gw_name gw_ns derp_port broker_host cred_ns
  node="${KIND_CLUSTER_NAME}-control-plane"
  label="$(kubectl get node "$node" -o 'jsonpath={.metadata.labels.node\.codewire\.sh/purpose}')"
  [ "$label" = sandbox-runtime ] || {
    echo "::error::Kind node ${node} lacks node.codewire.sh/purpose=sandbox-runtime (got '${label}')" >&2
    return 1
  }

  kubectl -n "$NS" rollout status daemonset/codewire-egress --timeout=120s >/dev/null
  ready_count="$(kubectl -n "$NS" get daemonset/codewire-egress -o 'jsonpath={.status.numberReady}')"
  [ "${ready_count:-0}" -ge 1 ] || {
    echo "::error::DaemonSet/codewire-egress has ${ready_count:-0} ready Pods" >&2
    return 1
  }
  dns_policy="$(kubectl -n "$NS" get daemonset/codewire-egress -o 'jsonpath={.spec.template.spec.dnsPolicy}')"
  dns_ns="$(kubectl -n "$NS" get daemonset/codewire-egress -o 'jsonpath={.spec.template.spec.dnsConfig.nameservers[0]}')"
  [ "$dns_policy" = None ] && [ -n "$dns_ns" ] && [ "$dns_ns" != "192.0.2.53" ] || {
    echo "::error::DaemonSet/codewire-egress DNS misconfigured: dnsPolicy=${dns_policy} nameserver=${dns_ns}" >&2
    return 1
  }

  gw_ip="$(kubectl -n ingress-nginx get service/codewire-kind-gateway -o 'jsonpath={.spec.clusterIP}')"
  [ "$gw_ip" = "10.96.0.243" ] || {
    echo "::error::Service ingress-nginx/codewire-kind-gateway clusterIP is '${gw_ip}', want 10.96.0.243" >&2
    return 1
  }
  endpoints="$(kubectl -n ingress-nginx get endpointslices -l kubernetes.io/service-name=codewire-kind-gateway \
    -o 'jsonpath={.items[*].endpoints[?(@.conditions.ready==true)].addresses[*]}')"
  [ -n "$endpoints" ] || {
    echo "::error::Service ingress-nginx/codewire-kind-gateway has no ready endpoints" >&2
    return 1
  }

  gw_name="$(kubectl -n ingress-nginx get pods -l app.kubernetes.io/component=controller \
    -o 'jsonpath={.items[0].metadata.labels.gateway\.envoyproxy\.io/owning-gateway-name}')"
  gw_ns="$(kubectl -n ingress-nginx get pods -l app.kubernetes.io/component=controller \
    -o 'jsonpath={.items[0].metadata.labels.gateway\.envoyproxy\.io/owning-gateway-namespace}')"
  [ "$gw_name" = codewire-kind-public ] && [ "$gw_ns" = ingress-nginx ] || {
    echo "::error::ingress-nginx-controller lacks Envoy owning-gateway labels (got name=${gw_name} ns=${gw_ns})" >&2
    return 1
  }

  derp_port="$(kubectl -n "$NS" get service/codewire-derp -o 'jsonpath={.spec.ports[?(@.name=="https")].port}')"
  [ "$derp_port" = "8443" ] || {
    echo "::error::Service ${NS}/codewire-derp lacks https port 8443" >&2
    return 1
  }
  kubectl -n "$NS" get secret/codewire-kind-derp-tls >/dev/null || {
    echo "::error::Secret ${NS}/codewire-kind-derp-tls is missing" >&2
    return 1
  }
  broker_host="$(kubectl -n "$NS" get deployment/codewire-coordinator \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="coordinator")].env[?(@.name=="KIND_DERP_BROKER_HOST")].value}')"
  [ "$broker_host" = "codewire-derp.${NS}.svc.cluster.local" ] || {
    echo "::error::codewire-coordinator KIND_DERP_BROKER_HOST is '${broker_host}', want codewire-derp.${NS}.svc.cluster.local" >&2
    return 1
  }

  cred_ns="$(kubectl -n "$NS" get deployment/codewire-credential-service \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="credential-service")].env[?(@.name=="CREDENTIAL_SANDBOX_NAMESPACE")].value}')"
  [ "$cred_ns" = "$SANDBOX_NS" ] || {
    echo "::error::codewire-credential-service CREDENTIAL_SANDBOX_NAMESPACE is '${cred_ns}', want ${SANDBOX_NS}" >&2
    return 1
  }
  kubectl -n "$NS" logs deployment/codewire-credential-service --tail=200 | grep -q 'interception CAs wired' || {
    echo "::error::codewire-credential-service did not report interception CAs wired" >&2
    return 1
  }

  log "Kind hosted-egress topology verified (egress=${dns_ns}, gateway=${gw_ip}->${endpoints}, derp-tls=${broker_host})"
}

hosted_egress_capture_state() {
  HOSTED_EGRESS_ORIG_ENABLED="$(kubectl -n "$NS" get configmap/codewire-hosted-egress \
    -o 'jsonpath={.data.CODEWIRE_HOSTED_EGRESS_ENABLED}')"
  HOSTED_EGRESS_ORIG_STD_DISK_REF="$(kubectl -n "$NS" get configmap/codewire-hosted-egress \
    -o 'jsonpath={.data.CODEWIRE_STANDARD_IMAGE_DISK_REFERENCE}')"
  HOSTED_EGRESS_ORIG_PROFILE="$(kubectl -n "$NS" get deployment/codewire-orchestration \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="orchestration")].env[?(@.name=="SANDBOX_RUNTIME_PROFILE")].value}')"
  HOSTED_EGRESS_ORIG_DAEMON_IMAGE="$(kubectl -n "$NS" get deployment/codewire-orchestration \
    -o 'jsonpath={.spec.template.spec.containers[?(@.name=="orchestration")].env[?(@.name=="SANDBOX_DAEMON_IMAGE")].value}')"
}

hosted_egress_wait_single_orchestration_pod() {
  local count _
  kubectl -n "$NS" rollout status deployment/codewire-orchestration --timeout=180s >/dev/null
  # Wait for Terminating old orchestration Pods to exit so a stale Temporal
  # worker with the previous SANDBOX_RUNTIME_PROFILE cannot pick up the next
  # create activity.
  for _ in $(seq 1 60); do
    count="$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=orchestration \
      -o json | jq '.items | length')"
    [ "$count" = "1" ] && return 0
    sleep 1
  done
  echo "::error::old codewire-orchestration Pods did not finish terminating" >&2
  return 1
}

hosted_egress_restore_state() {
  log "restoring hosted-egress switch and orchestration runtime profile"
  kubectl -n "$NS" patch configmap/codewire-hosted-egress --type=merge \
    -p "$(jq -cn --arg enabled "${HOSTED_EGRESS_ORIG_ENABLED:-false}" \
      --arg disk "${HOSTED_EGRESS_ORIG_STD_DISK_REF:-}" \
      '{data: {CODEWIRE_HOSTED_EGRESS_ENABLED: $enabled, CODEWIRE_STANDARD_IMAGE_DISK_REFERENCE: $disk}}')" >/dev/null
  kubectl -n "$NS" set env deployment/codewire-orchestration --containers=orchestration \
    "SANDBOX_RUNTIME_PROFILE=${HOSTED_EGRESS_ORIG_PROFILE:-runc}" \
    "SANDBOX_DAEMON_IMAGE=${HOSTED_EGRESS_ORIG_DAEMON_IMAGE:-codewire-daemon:e2e}" >/dev/null
  kubectl -n "$NS" rollout restart deployment/codewire-orchestration >/dev/null
  hosted_egress_wait_single_orchestration_pod
}

hosted_egress_enable_switch() {
  HOSTED_EGRESS_MUTATED=1
  kubectl -n "$NS" patch configmap/codewire-hosted-egress --type=merge \
    -p '{"data":{"CODEWIRE_HOSTED_EGRESS_ENABLED":"true"}}' >/dev/null
  kubectl -n "$NS" rollout restart deployment/codewire-orchestration >/dev/null
  hosted_egress_wait_single_orchestration_pod
  log "hosted-egress switch enabled and orchestration rolled out cleanly"
}

# Alias the loaded daemon image inside Kind's containerd under
# codewire.local/codewire/daemon@sha256:<digest> so warm-pool-authz admits
# hosted-egress-tun without weakening daemonRepositories. On Kind's Kubernetes
# 1.34, ImageVolume mounts the image root rather than subPath="usr/local/bin",
# so add a relative /cw -> usr/local/bin/cw link in a Kind-only stand-in layer
# when the base daemon image is present in the local Docker daemon.
hosted_egress_digest_pinned_daemon_image() {
  local node="${KIND_CLUSTER_NAME}-control-plane" current_image source_image digest pinned
  current_image="${HOSTED_EGRESS_ORIG_DAEMON_IMAGE:-codewire-daemon:e2e}"
  if [[ "$current_image" =~ ^codewire\.local/codewire/daemon@sha256:[0-9a-f]{64}$ ]]; then
    printf '%s\n' "$current_image"
    return 0
  fi
  source_image="$current_image"
  if docker image inspect "$current_image" >/dev/null 2>&1; then
    local standin_tag="codewire-daemon:kind-kata-standin"
    # Single-manifest image (--provenance=false --sbom=false) so containerd's
    # reported imageID digest matches the spec image digest checked at binding.
    docker build --quiet --provenance=false --sbom=false --tag "$standin_tag" - >/dev/null <<DOCKERFILE
FROM ${current_image}
RUN ln -sf usr/local/bin/cw /cw
DOCKERFILE
    docker exec "$node" ctr -n k8s.io images rm "docker.io/library/${standin_tag}" >/dev/null 2>&1 || true
    kind load docker-image --name "$KIND_CLUSTER_NAME" "$standin_tag" >/dev/null 2>&1
    HOSTED_EGRESS_KATA_DAEMON_TAG="$standin_tag"
    source_image="$standin_tag"
  fi
  digest="$(docker exec "$node" ctr -n k8s.io images ls | awk -v ref="$source_image" '
    ($1 == ref || $1 == ("docker.io/library/" ref)) && $3 ~ /^sha256:[0-9a-f]{64}$/ { print $3; exit }')"
  [ -n "$digest" ] || {
    echo "::error::could not resolve containerd digest for ${source_image} on ${node}" >&2
    return 1
  }
  pinned="codewire.local/codewire/daemon@${digest}"
  # Remove any stale codewire.local/codewire/daemon@sha256:* aliases so
  # containerd reports exactly this one repoDigest as status.imageID.
  docker exec "$node" sh -ec "
    for ref in \$(ctr -n k8s.io images ls -q | grep '^codewire\\.local/codewire/daemon@sha256:' || true); do
      [ \"\$ref\" = '${pinned}' ] || ctr -n k8s.io images rm \"\$ref\" >/dev/null 2>&1 || true
    done
  "
  if ! docker exec "$node" ctr -n k8s.io images ls -q | grep -Fxq "$pinned"; then
    local source_ref
    source_ref="$(docker exec "$node" ctr -n k8s.io images ls | awk -v ref="$source_image" '
      ($1 == ref || $1 == ("docker.io/library/" ref)) { print $1; exit }')"
    docker exec "$node" ctr -n k8s.io images tag --force "$source_ref" "$pinned" >/dev/null
  fi
  printf '%s\n' "$pinned"
}

hosted_egress_verify_kata_standin() {
  local daemon_ref env_name env_id pod_name pod_uid _ tun_exit admitted
  daemon_ref="$(hosted_egress_digest_pinned_daemon_image)"
  kubectl -n "$NS" set env deployment/codewire-orchestration --containers=orchestration \
    SANDBOX_RUNTIME_PROFILE=commodity \
    "SANDBOX_DAEMON_IMAGE=${daemon_ref}" >/dev/null
  hosted_egress_wait_single_orchestration_pod

  local workspace_image
  workspace_image="$(retained_managed_workspace_image)"
  hosted_egress_create_kata_block_pv
  env_name="kind-egress-kata-$(date +%s)"
  log "creating Kata stand-in (commodity) broker-mode sandbox ${env_name}"
  env_id="$(kind_credential_cli --cloud create --name "$env_name" --no-file --no-profile \
    --image "$workspace_image" --cpu 500m --memory 2Gi --disk 2Gi --ttl 1h \
    --no-network --no-wait --yes --output json | jq -er '.id')"
  HOSTED_EGRESS_CREATED_ENVS+=("$env_id")

  pod_name=""
  for _ in $(seq 1 60); do
    pod_name="$(kubectl -n "$SANDBOX_NS" get pods -l "codewire.sh/environment-id=${env_id}" \
      -o json | jq -r '.items[0].metadata.name // empty')"
    if [ -n "$pod_name" ]; then
      HOSTED_EGRESS_KATA_POD="$pod_name"
      pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o 'jsonpath={.metadata.uid}')"
      break
    fi
    sleep 2
  done
  [ -n "$pod_name" ] || {
    echo "::error::no broker-mode Kata stand-in Pod appeared in ${SANDBOX_NS} for ${env_id}" >&2
    return 1
  }

  # Wait for hosted-egress-tun init container to exit 0 and cw-egress to admit
  # the Pod's stream and report enforcement without PeerIsNotThePod.
  local pg_pod enforcement_state
  pg_pod="$(kubectl -n "$NS" get pods --no-headers | awk '/postgres/{print $1; exit}')"
  admitted=0
  for _ in $(seq 1 45); do
    tun_exit="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" \
      -o 'jsonpath={.status.initContainerStatuses[?(@.name=="hosted-egress-tun")].state.terminated.exitCode}')"
    if [ "$tun_exit" = "0" ]; then
      if kubectl -n "$NS" logs daemonset/codewire-egress --tail=300 | grep -F "$pod_uid" | grep -q 'PeerIsNotThePod'; then
        echo "::error::cw-egress refused Kata stand-in Pod ${pod_name} (${pod_uid}) with PeerIsNotThePod" >&2
        return 1
      fi
      enforcement_state="$(kubectl -n "$NS" exec "$pg_pod" -- psql -U codewire -d codewire -tAc \
        "SELECT state FROM sandbox_egress_enforcement WHERE pod_uid = '${pod_uid}' AND state IN ('enforced','failed_closed');" 2>/dev/null || true)"
      if [ -n "$enforcement_state" ]; then
        admitted=1
        break
      fi
    fi
    sleep 2
  done

  [ "$admitted" = 1 ] || {
    kubectl -n "$SANDBOX_NS" logs "$pod_name" -c workspace --tail=100 >&2 || true
    kubectl -n "$SANDBOX_NS" describe pod "$pod_name" >&2 || true
    kubectl -n "$NS" logs daemonset/codewire-egress --tail=100 >&2 || true
    echo "::error::Kata stand-in Pod ${pod_name} (${pod_uid}) did not achieve an admitted cw-egress stream" >&2
    return 1
  }
  log "Kata stand-in Pod ${pod_name} (${pod_uid}): hosted-egress-tun exited 0 and cw-egress admitted stream (state=${enforcement_state})"
  if [ -n "${env_id:-}" ]; then
    (set +e; kind_credential_cli --cloud rm "$env_id" --yes --output json >/dev/null 2>&1)
    HOSTED_EGRESS_CREATED_ENVS=()
  fi
  hosted_egress_cleanup_kata_block_pv
}

hosted_egress_verify_standard_journey() {
  local standard_disk_img="$1" standard_workspace_img pg_pod enforcement_state
  local env_name policy_name env_id pod_name pod_uid exec_out refusal_count refused_status=0 cluster_dns_status=0
  standard_workspace_img="$(awk '{print $4}' <<<"$standard_disk_img")"
  pg_pod="$(kubectl -n "$NS" get pods --no-headers | awk '/postgres/{print $1; exit}')"
  kubectl -n "$NS" set env deployment/codewire-orchestration --containers=orchestration \
    SANDBOX_RUNTIME_PROFILE=standard >/dev/null
  hosted_egress_wait_single_orchestration_pod

  policy_name="kind-egress-pol-$(date +%s)"
  HOSTED_EGRESS_CREATED_POLICIES+=("$policy_name")
  kind_credential_cli --cloud policy create "$policy_name" \
    --allow example.com --allow registry-1.docker.io --allow auth.docker.io \
    --allow production.cloudflare.docker.com --allow production.cloudfront.docker.com >/dev/null

  env_name="kind-egress-std-$(date +%s)"
  log "creating standard broker-mode sandbox ${env_name} with policy ${policy_name}"
  env_id="$(kind_credential_cli --cloud create --name "$env_name" --no-file --no-profile \
    --image "$standard_workspace_img" --cpu 2 --memory 4GB --disk 12GB --ttl 1h \
    --no-network --policy "$policy_name" --yes --output json | jq -er '.id')"
  HOSTED_EGRESS_CREATED_ENVS+=("$env_id")
  wait_kind_credential_environment "$env_id" running

  pod_name="$(kubectl -n "$SANDBOX_NS" get pods -l "codewire.sh/environment-id=${env_id}" \
    -o json | jq -r '.items[0].metadata.name // empty')"
  [ -n "$pod_name" ] || {
    echo "::error::no running standard Pod found in ${SANDBOX_NS} for ${env_id}" >&2
    return 1
  }
  pod_uid="$(kubectl -n "$SANDBOX_NS" get pod "$pod_name" -o 'jsonpath={.metadata.uid}')"

  # Check 4: admitted stream recorded as enforced with zero PeerIsNotThePod.
  enforcement_state="$(kubectl -n "$NS" exec "$pg_pod" -- psql -U codewire -d codewire -tAc \
    "SELECT state FROM sandbox_egress_enforcement WHERE pod_uid = '${pod_uid}' AND environment_id = '${env_id}';")"
  [ "$enforcement_state" = "enforced" ] || {
    echo "::error::sandbox_egress_enforcement for ${pod_uid} is '${enforcement_state}', want 'enforced'" >&2
    return 1
  }
  ! kubectl -n "$NS" logs daemonset/codewire-egress --tail=300 | grep -F "$pod_uid" | grep -q 'PeerIsNotThePod' || {
    echo "::error::cw-egress reported PeerIsNotThePod for standard Pod ${pod_uid}" >&2
    return 1
  }

  # Surface the guest's own network/binding state (routes, rules, hosted mounts,
  # and binding roots) so standard VM failures are immediately diagnosable (#6387).
  CW_CLI_HOME="$KIND_CREDENTIAL_CLI_HOME" \
    CODEWIRE_SERVER_URL="$KIND_INGRESS_URL" \
    CW_BIN="${CARGO_CI_DIR}/cw" \
    KIND_CLUSTER_NAME="$KIND_CLUSTER_NAME" \
    "$ROOT/scripts/dev/kind/inspect-standard-guest.sh" "$env_id"

  # Check 3: DNS lookup inside VM + cluster DNS (10.96.0.10) refused.
  kind_credential_cli exec --cloud --in "$env_id" -- getent hosts example.com >/dev/null
  cluster_dns_status=0
  (
    set +e
    kind_credential_cli exec --cloud --in "$env_id" -- python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01', ('10.96.0.10', 53))
s.recvfrom(512)
" >/dev/null 2>&1
    exit $?
  ) || cluster_dns_status=$?
  [ "$cluster_dns_status" -ne 0 ] || {
    echo "::error::cluster DNS 10.96.0.10 unexpectedly responded inside standard VM" >&2
    return 1
  }

  # Check 2: allowed curl succeeds; refused curl fails and is recorded in
  # orchestration's hosted refusal log (environment_egress_records).
  kind_credential_cli exec --cloud --in "$env_id" -- curl -fsS --max-time 15 https://example.com >/dev/null
  refused_status=0
  (
    set +e
    kind_credential_cli exec --cloud --in "$env_id" -- curl -fsS --max-time 10 https://example.org >/dev/null 2>&1
    exit $?
  ) || refused_status=$?
  [ "$refused_status" -ne 0 ] || {
    echo "::error::refused destination https://example.org unexpectedly succeeded" >&2
    return 1
  }
  refusal_count=0
  for _ in $(seq 1 15); do
    refusal_count="$(kubectl -n "$NS" exec "$pg_pod" -- psql -U codewire -d codewire -tAc \
      "SELECT COALESCE(SUM(count), 0) FROM environment_egress_records WHERE environment_id = '${env_id}' AND destination = 'example.org' AND outcome = 'refused';")"
    [ "${refusal_count:-0}" -ge 1 ] && break
    sleep 1
  done
  [ "${refusal_count:-0}" -ge 1 ] || {
    echo "::error::hosted refusal log did not record refused destination example.org for ${env_id}" >&2
    return 1
  }

  # Check 1 + Check 3 (in-container DNS): busybox pull, run, and DNS lookup inside Docker.
  exec_out="$(kind_credential_cli exec --cloud --in "$env_id" -- docker run --rm busybox echo hello)"
  [ "$(printf '%s' "$exec_out" | tr -d '\r\n')" = "hello" ] || {
    echo "::error::busybox container returned '${exec_out}', want 'hello'" >&2
    return 1
  }
  kind_credential_cli exec --cloud --in "$env_id" -- docker run --rm busybox nslookup example.com >/dev/null

  # Check 5: cw-egress restart recovery.
  kubectl -n "$NS" rollout restart daemonset/codewire-egress >/dev/null
  kubectl -n "$NS" rollout status daemonset/codewire-egress --timeout=180s >/dev/null
  kind_credential_cli exec --cloud --in "$env_id" -- curl -fsS --max-time 15 https://example.com >/dev/null
  ! kubectl -n "$NS" logs daemonset/codewire-egress --tail=300 | grep -F "$pod_uid" | grep -q 'PeerIsNotThePod' || {
    echo "::error::cw-egress reported PeerIsNotThePod after restart for ${pod_uid}" >&2
    return 1
  }

  log "standard broker-mode checks passed on ${env_name} (${pod_name}, ${pod_uid})"
}
