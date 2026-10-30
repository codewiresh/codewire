#!/usr/bin/env bash
# Offline contract for the Dev confidential-binding proof (Program #2238 B2c):
# its Pod and init-data checks accept the reviewed confidential rendering
# (the orchestration golden fixture) and refuse each drift they guard, and it
# reaches Kubernetes read-only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROOF="$ROOT/scripts/runtime/confidential/prove-dev-confidential-binding.sh"
GOLDEN="$ROOT/crates/codewire-orchestration/tests/fixtures/sandbox/confidential-sandboxtemplate.golden.json"
ENVIRONMENT="be31063a-8ec8-46d5-aa17-75cda1729370"
OTHER="b3a9c6f2-1d4e-4f5a-8b7c-6d5e4f3a2b1c"

mkdir -p "$ROOT/.tmp"
work="$(mktemp -d "$ROOT/.tmp/confidential-binding-proof.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT

fail() { printf 'test-confidential-binding-proof: %s\n' "$*" >&2; exit 1; }

bash -n "$PROOF"
"$PROOF" --help | grep -F 'prove-dev-confidential-binding.sh' >/dev/null
# Kubernetes is read with get only, through the one guarded wrapper.
if grep -nE 'kubectl[[:space:]]+(apply|delete|patch|create|edit|exec|port-forward|label|annotate|scale|replace|cordon|drain)' \
  "$PROOF" >/dev/null; then
  fail "the proof names a mutating kubectl verb"
fi
[[ "$(grep -c 'kubectl --context' "$PROOF")" == 1 ]] || fail "kubectl is called outside its read-only wrapper"
(
  # shellcheck disable=SC1090
  source <(sed '$d' "$PROOF")
  # A shim the wrapper would reach if it let the verb through.
  # shellcheck disable=SC2329
  kubectl() { printf 'kubectl called\n' >"$work/kubectl-called"; }
  if (kubectl_ro delete pod workspace) 2>/dev/null; then
    fail "the read-only wrapper ran a delete"
  fi
  [[ ! -e "$work/kubectl-called" ]] || fail "the read-only wrapper reached kubectl for a delete"
)
# Creates run as the smoke identity, through the environment only, on the
# confidential tier.
grep -F -- '--isolation confidential' "$PROOF" >/dev/null || fail "the proof does not create a confidential environment"
# The proof drives the current CLI: `cw env *` and `cw config-ssh` were
# removed, and the cw binary lives in codewire-cli-bin.
if grep -nE '\bcw (env|config-ssh)\b|[^-](env (create|info|stop|start|rm)) ' "$PROOF" >/dev/null; then
  fail "the proof still calls a removed cw command"
fi
grep -F -- '-p codewire-cli-bin --bin cw' "$PROOF" >/dev/null || fail "the proof builds cw from the wrong package"
grep -F -- 'setup ssh --ssh-config-file' "$PROOF" >/dev/null || fail "the proof does not write its SSH config with cw setup ssh"
grep -F 'export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"' "$PROOF" >/dev/null ||
  fail "the proof does not act as the smoke identity"
grep -F 'export CW_CONFIG_DIR="$TMPDIR_PROOF/cw-config"' "$PROOF" >/dev/null ||
  fail "the proof could reuse a saved login instead of the smoke identity"
# An API key is not an OAuth access token, so `cw whoami` (OAuth userinfo)
# always refuses it; the identity check lists the key's organizations instead.
if grep -nE '\bcw whoami\b' "$PROOF" >/dev/null; then
  fail "the proof checks the API key with cw whoami, which never accepts one"
fi
grep -F 'cw org list --output json' "$PROOF" >/dev/null ||
  fail "the proof does not verify the smoke organization"
# `cw run` names its environment with --in (a bare argument is an agent), and
# cloud environments are SSH hosts `cw-cloud-<id>`, as `cw setup ssh` writes.
if grep -nE 'run --no-tty "\$ENV_ID"|cw-\$ENV_ID' "$PROOF" >/dev/null; then
  fail "the proof uses the pre-v0.4 run or SSH host form"
fi
grep -F 'run --no-tty --in "$ENV_ID"' "$PROOF" >/dev/null ||
  fail "the proof does not run commands with cw run --in"
grep -F '"cw-cloud-$ENV_ID" "$@"' "$PROOF" >/dev/null ||
  fail "the proof does not reach the environment as cw-cloud-<id>"
# The key reaches cw through the environment, never an argument or a file.
if grep -nE -- '--api-key|API_KEY[^"]*"? *>' "$PROOF" >/dev/null; then
  fail "the proof passes the API key as an argument or writes it to a file"
fi

# The Pod the controller creates from the golden rendering, and its Sandbox.
jq '{
  metadata: {
    uid: "pod-uid",
    labels: .spec.podTemplate.metadata.labels,
    annotations: .spec.podTemplate.metadata.annotations
  },
  spec: (.spec.podTemplate.spec + {nodeName: "snp-node"})
}' "$GOLDEN" >"$work/pod.base.json"
jq '{spec: {podTemplate: .spec.podTemplate}}' "$GOLDEN" >"$work/sandbox.base.json"

run_check() { # CHECK ENV_ID POD_JQ SANDBOX_JQ -> exit status of the check
  local check="$1" environment="$2" pod_filter="$3" sandbox_filter="$4"
  jq "$pod_filter" "$work/pod.base.json" >"$work/pod.json"
  jq "$sandbox_filter" "$work/sandbox.base.json" >"$work/sandbox.json"
  (
    # shellcheck disable=SC1090
    source <(sed '$d' "$PROOF")
    # Read by the sourced checks.
    # shellcheck disable=SC2034
    TMPDIR_PROOF="$work"
    # shellcheck disable=SC2034
    ENV_ID="$environment"
    "$check"
  )
}

accepts() {
  run_check "$1" "${2:-$ENVIRONMENT}" "${3:-.}" "${4:-.}" || fail "$1 refused the reviewed rendering${5:+: $5}"
}

refuses() {
  if run_check "$1" "${2:-$ENVIRONMENT}" "${3:-.}" "${4:-.}"; then
    fail "$1 accepted ${5:-a drift}"
  fi
}

for check in pod_runs_confidential pod_is_identity_free \
  pod_mounts_no_config_map_and_keeps_state_in_memory pod_carries_measured_anchors \
  init_data_pins_the_anchors sandbox_carries_the_pods_init_data; do
  accepts "$check"
done

refuses pod_runs_confidential "$ENVIRONMENT" '.spec.runtimeClassName = "commodity"' . "the commodity runtime"
refuses pod_is_identity_free "$ENVIRONMENT" \
  '.spec.containers[0].env += [{name: "CODEWIRE_DAEMON_AUTH_TOKEN", value: "synthetic"}]' . "a daemon token"
refuses pod_is_identity_free "$ENVIRONMENT" '.spec.automountServiceAccountToken = true' . "an API token"
refuses pod_is_identity_free "$ENVIRONMENT" \
  '(.spec.containers[] | select(.name == "dind") | .volumeMounts) += [{name: "workspace-binding-identity", mountPath: "/x"}]' \
  . "the binding token in DinD"
refuses pod_mounts_no_config_map_and_keeps_state_in_memory "$ENVIRONMENT" \
  '.spec.volumes += [{name: "roots", configMap: {name: "codewire-orchestration-internal-roots"}}]' . "a roots ConfigMap"
refuses pod_mounts_no_config_map_and_keeps_state_in_memory "$ENVIRONMENT" \
  '(.spec.volumes[] | select(.name == "codewire-run")) = {name: "codewire-run", emptyDir: {}}' . "a disk-backed run directory"
refuses pod_carries_measured_anchors "$OTHER" . . "another environment"
refuses pod_carries_measured_anchors "$ENVIRONMENT" \
  '.spec.containers[0].env += [{name: "CODEWIRE_MEASURED_ENVIRONMENT_ID", value: "'"$OTHER"'"}]' . "a second measured environment"
refuses pod_carries_measured_anchors "$ENVIRONMENT" \
  '.spec.containers[0].env |= map(select(.name != "CODEWIRE_MEASURED_BINDING_ROOTS"))' . "missing measured roots"
refuses pod_carries_measured_anchors "$ENVIRONMENT" \
  '(.spec.containers[0].env[] | select(.name == "CODEWIRE_WORKSPACE_BINDING_URL") | .value) = "http://plaintext:8087"' \
  . "a plaintext binding URL"
refuses init_data_pins_the_anchors "$OTHER" . . "init-data for another environment"
refuses init_data_pins_the_anchors "$ENVIRONMENT" \
  '(.spec.containers[0].env[] | select(.name == "CODEWIRE_MEASURED_BINDING_ROOTS") | .value) = "-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n"' \
  . "roots the init-data does not pin"
refuses sandbox_carries_the_pods_init_data "$ENVIRONMENT" . \
  '.spec.podTemplate.metadata.annotations["io.katacontainers.config.hypervisor.cc_init_data"] = "c3RhbGU="' \
  "a Sandbox whose init-data differs from its Pod's"

printf 'confidential binding proof contract: OK\n'
