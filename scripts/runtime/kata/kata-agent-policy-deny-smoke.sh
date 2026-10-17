#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

KUBE_CONTEXT="${KUBE_CONTEXT:-dev-cluster}"
KATA_POLICY_DENY_NAMESPACE="${KATA_POLICY_DENY_NAMESPACE:-}"
KATA_POLICY_DENY_POD="${KATA_POLICY_DENY_POD:-kata-policy-deny-exec}"
KATA_POLICY_DENY_RUNTIME_CLASS="${KATA_POLICY_DENY_RUNTIME_CLASS:-commodity}"
KATA_POLICY_DENY_IMAGE="${KATA_POLICY_DENY_IMAGE:-docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f}"
KATA_POLICY_DENY_EXPECTED_NODE="${KATA_POLICY_DENY_EXPECTED_NODE:?set KATA_POLICY_DENY_EXPECTED_NODE to the Dev node}"
KATA_POLICY_DENY_TIMEOUT="${KATA_POLICY_DENY_TIMEOUT:-180s}"
KATA_POLICY_DENY_KEEP="${KATA_POLICY_DENY_KEEP:-0}"
SMOKE_TMP_PARENT="${SMOKE_TMP_PARENT:-$ROOT/.tmp}"

die() {
  printf '[kata-policy-deny] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[kata-policy-deny] %s\n' "$*" >&2
}

case "$-" in
  *x*) die "shell tracing is enabled; rerun without set -x" ;;
esac

for cmd in base64 gzip kubectl mktemp; do
  command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
done

mkdir -p "$SMOKE_TMP_PARENT"
evidence_dir="$(mktemp -d "$SMOKE_TMP_PARENT/kata-agent-policy-deny.XXXXXXXX")"
if [[ -z "$KATA_POLICY_DENY_NAMESPACE" ]]; then
  suffix="$(basename "$evidence_dir")"
  suffix="${suffix##*.}"
  suffix="$(printf '%s' "$suffix" | tr '[:upper:]' '[:lower:]')"
  KATA_POLICY_DENY_NAMESPACE="codewire-kata-policy-smoke-$suffix"
fi
initdata="$evidence_dir/init-data.toml"
manifest="$evidence_dir/pod.yaml"
exec_stdout="$evidence_dir/kubectl-exec.stdout"
exec_stderr="$evidence_dir/kubectl-exec.stderr"
logs_out="$evidence_dir/pod.logs"

cleanup() {
  if [[ "$KATA_POLICY_DENY_KEEP" != "1" ]]; then
    kubectl --context "$KUBE_CONTEXT" delete namespace "$KATA_POLICY_DENY_NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

cat >"$initdata" <<'POLICY'
version = "0.1.0"
algorithm = "sha256"

[data]
"policy.rego" = '''
package agent_policy

default AddARPNeighborsRequest := true
default AddSwapPathRequest := true
default AddSwapRequest := true
default CloseStdinRequest := true
default CopyFileRequest := true
default CreateContainerRequest := true
default CreateSandboxRequest := true
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetDiagnosticDataRequest := false
default GetIPTablesRequest := true
default GetMetricsRequest := true
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := true
default ListRoutesRequest := true
default MemAgentCompactConfig := true
default MemAgentMemcgConfig := true
default MemHotplugByProbeRequest := true
default OnlineCPUMemRequest := true
default PauseContainerRequest := true
default PullImageRequest := true
default ReadStreamRequest := true
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := true
default ResizeVolumeRequest := true
default ResumeContainerRequest := true
default SetGuestDateTimeRequest := true
default SetIPTablesRequest := true
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := false
default StatsContainerRequest := true
default StopTracingRequest := false
default TtyWinResizeRequest := true
default UpdateContainerRequest := true
default UpdateEphemeralMountsRequest := true
default UpdateInterfaceRequest := true
default UpdateRoutesRequest := true
default VolumeStatsRequest := true
default WaitProcessRequest := true
default WriteStreamRequest := true
'''
POLICY

encoded="$(gzip -c "$initdata" | base64 | tr -d '\n')"

kubectl --context "$KUBE_CONTEXT" create namespace "$KATA_POLICY_DENY_NAMESPACE" --dry-run=client -o yaml |
  kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null

cat >"$manifest" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $KATA_POLICY_DENY_POD
  namespace: $KATA_POLICY_DENY_NAMESPACE
  labels:
    app.kubernetes.io/name: codewire-kata-agent-policy-deny-smoke
    codewire.sh/runtime-profile: commodity
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: $encoded
spec:
  runtimeClassName: $KATA_POLICY_DENY_RUNTIME_CLASS
  restartPolicy: Never
  containers:
    - name: smoke
      image: $KATA_POLICY_DENY_IMAGE
      command:
        - sh
        - -c
        - echo kata-policy-deny-ready && sleep 300
YAML

kubectl --context "$KUBE_CONTEXT" apply -f "$manifest" >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$KATA_POLICY_DENY_NAMESPACE" wait \
  --for=condition=Ready "pod/$KATA_POLICY_DENY_POD" --timeout="$KATA_POLICY_DENY_TIMEOUT" >/dev/null

node="$(
  kubectl --context "$KUBE_CONTEXT" -n "$KATA_POLICY_DENY_NAMESPACE" get pod "$KATA_POLICY_DENY_POD" \
    -o jsonpath='{.spec.nodeName}'
)"
if [[ -n "$KATA_POLICY_DENY_EXPECTED_NODE" && "$node" != "$KATA_POLICY_DENY_EXPECTED_NODE" ]]; then
  die "pod scheduled to $node, want $KATA_POLICY_DENY_EXPECTED_NODE"
fi

kubectl --context "$KUBE_CONTEXT" -n "$KATA_POLICY_DENY_NAMESPACE" logs "$KATA_POLICY_DENY_POD" >"$logs_out"
grep -qx 'kata-policy-deny-ready' "$logs_out" || die "pod logs did not prove ReadStreamRequest still works"

if kubectl --context "$KUBE_CONTEXT" -n "$KATA_POLICY_DENY_NAMESPACE" exec "$KATA_POLICY_DENY_POD" -- true \
  >"$exec_stdout" 2>"$exec_stderr"; then
  die "kubectl exec unexpectedly succeeded even though ExecProcessRequest is denied"
fi

if ! grep -Eiq 'exec|policy|denied|forbidden|permission|failed|agent|ttrpc' "$exec_stderr"; then
  log "exec failed as expected, but stderr did not include a stable policy marker; see $exec_stderr"
else
  log "exec denial evidence captured in $exec_stderr"
fi
log "Kata Agent Policy denial smoke passed on $node; evidence in $evidence_dir"
