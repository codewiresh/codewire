#!/usr/bin/env bash
# Dev acceptance for confidential workspaces that bind like standard ones
# (Program #2238 B2c; design: private-docs designs/2026-10-07-confidential-binding-b2c.md).
#
# Creates one confidential environment on Dev's SEV-SNP node through the
# product CLI and proves, as a user sees it:
#   - it reaches running and its daemon answers;
#   - its Pod is identity-free, mounts no ConfigMap, keeps the daemon's state
#     in guest memory and carries the measured anchors exactly once;
#   - its measured init-data pins those anchors, names its environment as the
#     storage key, never carries a daemon token, and equals its Sandbox's;
#   - `cw setup ssh` then OpenSSH runs a command line and keeps its exit
#     status, scp round-trips over SFTP, over WebSocket and over the tailnet;
#   - the recorded host key is the one served, and any other key is refused;
#   - optionally, the credential relay serves a selected profile, and the
#     tailnet survives past one binding-token lifetime;
#   - a stop and start replaces the Pod, rotates its host key and binds again.
#
# Kubernetes access is read-only (get only). The run acts as the dedicated Dev
# smoke identity, whose organization a global admin has opted in to
# confidential environments. Run it under scripts/runtime/dev/with-dev-smoke-auth.sh,
# which loads the identity's API key from OpenBao into the environment; this
# script hands it to cw through the environment only. No credential, token or
# key material is printed, logged or kept beyond the run's private temporary
# directory, which is removed at exit.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
SNP_NODE_LABEL="${SNP_NODE_LABEL:-node.codewire.sh/confidential-snp=true}"
PROOF_IMAGE="${PROOF_IMAGE:-workspace}"
PROOF_CPU="${PROOF_CPU:-2}"
PROOF_MEMORY="${PROOF_MEMORY:-8GB}"
PROOF_DISK="${PROOF_DISK:-20GB}"
PROOF_TTL="${PROOF_TTL:-3h}"
# A confidential guest attests and opens its encrypted storage before its
# daemon binds: the tier's ready budget is 30 minutes.
PROOF_TIMEOUT_SECONDS="${PROOF_TIMEOUT_SECONDS:-1800}"
PROOF_SSH_TIMEOUT="${PROOF_SSH_TIMEOUT:-180}"
PROOF_TMP_PARENT="${PROOF_TMP_PARENT:-$ROOT/.tmp}"
CW_BIN="${CW_BIN:-}"
SMOKE_ORG_SLUG="codewire-dev-smoke"
CREDENTIAL_PROFILE=""
PRIVATE_REPO=""
HOLD_MINUTES=0
EXISTING_ENV_ID=""
KEEP=0
SKIP_STOP_START=0

INIT_DATA_ANNOTATION="io.katacontainers.config.hypervisor.cc_init_data"
MEASURED_ROOTS_ENV="CODEWIRE_MEASURED_BINDING_ROOTS"
MEASURED_ENVIRONMENT_ENV="CODEWIRE_MEASURED_ENVIRONMENT_ID"
BINDING_URL_ENV="CODEWIRE_WORKSPACE_BINDING_URL"

TMPDIR_PROOF=""
ENV_ID=""
CREATED=0
FAILURES=0
RESULTS=()

usage() {
  cat <<'USAGE'
Usage:
  scripts/runtime/confidential/prove-dev-confidential-binding.sh [options]

Prerequisites on Dev (outside this script):
  - a confidential storage class and the active confidential SNP profile;
  - the smoke organization opted in to confidential environments on its
    admin Organizations page (Confidential environments);
  - a human OpenBao session, so with-dev-smoke-auth.sh can load the smoke
    identity;
  - read-only kubectl access to the Dev cluster (KUBE_CONTEXT).

Options:
  --existing-env ID           Prove an existing confidential environment
                              instead of creating one (implies --keep)
  --credential-profile NAME   Create with this credential profile and prove
                              the relay with --private-repo
  --private-repo URL          A repository only the profile can read; proven
                              with `git ls-remote` over SSH in the workspace
  --hold-minutes N            Wait N minutes, then prove tailnet SSH again
                              (use 15 to outlast one binding-token lifetime)
  --skip-stop-start           Skip the stop and start journey
  --cw-bin PATH               Prebuilt cw binary (default: build one)
  --keep                      Keep the environment
  -h, --help                  Show this help

Run it as the smoke identity:
  scripts/runtime/dev/with-dev-smoke-auth.sh -- \
    scripts/runtime/confidential/prove-dev-confidential-binding.sh [options]

Environment:
  CODEWIRE_DEV_SMOKE_API_KEY          Set by with-dev-smoke-auth.sh; required.
                                      It must own exactly the
                                      codewire-dev-smoke organization.
  CODEWIRE_SERVER_URL   Defaults to https://codewire-dev.sh
  KUBECONFIG            Read-only access to the Dev cluster
  KUBE_CONTEXT          Defaults to codewire-dev
USAGE
}

log() { printf '[confidential-binding] %s\n' "$*" >&2; }
die() { printf '[confidential-binding] ERROR: %s\n' "$*" >&2; exit 1; }

pass() {
  RESULTS+=("PASS $*")
  log "PASS $*"
}

fail() {
  RESULTS+=("FAIL $*")
  FAILURES=$((FAILURES + 1))
  log "FAIL $*"
}

check() {
  local label="$1"
  shift
  if "$@"; then pass "$label"; else fail "$label"; fi
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

seconds_now() { date +%s; }

kubectl_ro() {
  [[ "$1" == get ]] || die "read-only kubectl refused verb $1"
  kubectl --context "$KUBE_CONTEXT" "$@"
}

cw() { timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" "$@"; }

cleanup() {
  if [[ "$CREATED" == 1 && "$KEEP" == 0 && -n "$ENV_ID" ]]; then
    cw rm --yes "$ENV_ID" >/dev/null 2>&1 || log "cleanup: could not remove $ENV_ID"
  fi
  if [[ -n "$TMPDIR_PROOF" && -d "$TMPDIR_PROOF" ]]; then
    rm -rf -- "$TMPDIR_PROOF"
  fi
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --existing-env) EXISTING_ENV_ID="${2:?}"; KEEP=1; shift 2 ;;
      --credential-profile) CREDENTIAL_PROFILE="${2:?}"; shift 2 ;;
      --private-repo) PRIVATE_REPO="${2:?}"; shift 2 ;;
      --hold-minutes) HOLD_MINUTES="${2:?}"; shift 2 ;;
      --skip-stop-start) SKIP_STOP_START=1; shift ;;
      --cw-bin) CW_BIN="${2:?}"; shift 2 ;;
      --keep) KEEP=1; shift ;;
      -h | --help) usage; exit 0 ;;
      *) usage >&2; die "unknown argument: $1" ;;
    esac
  done
  [[ "$HOLD_MINUTES" =~ ^[0-9]+$ ]] || die "--hold-minutes takes a whole number"
  if [[ -n "$PRIVATE_REPO" && -z "$CREDENTIAL_PROFILE" ]]; then
    die "--private-repo needs --credential-profile"
  fi
  if [[ -n "$EXISTING_ENV_ID" && ! "$EXISTING_ENV_ID" =~ ^[0-9a-f-]{36}$ ]]; then
    die "--existing-env takes an environment UUID"
  fi
}

build_cw() {
  if [[ -n "$CW_BIN" ]]; then
    [[ -x "$CW_BIN" ]] || die "--cw-bin is not executable: $CW_BIN"
    return
  fi
  log "building cw"
  (cd "$ROOT" && cargo build -q -p codewire-cli-bin --bin cw) || die "cw build failed"
  CW_BIN="$(cd "$ROOT" && cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')/debug/cw"
  [[ -x "$CW_BIN" ]] || die "built cw not found at $CW_BIN"
}

# Act as the smoke identity: its key reaches cw through the environment only,
# and a private cw config directory keeps any saved login out of the run.
use_smoke_identity() {
  [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] ||
    die "CODEWIRE_DEV_SMOKE_API_KEY is not set; run under scripts/runtime/dev/with-dev-smoke-auth.sh"
  export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
  export CW_CONFIG_DIR="$TMPDIR_PROOF/cw-config"
  mkdir -p "$CW_CONFIG_DIR"
  # The CLI's whoami asks the OAuth userinfo endpoint, which accepts only OAuth
  # access tokens, never an API key. Verify the key the way the commodity
  # smoke does: it owns exactly the dedicated smoke organization.
  local orgs="$TMPDIR_PROOF/organizations.json"
  cw org list --output json >"$orgs" 2>/dev/null ||
    die "the smoke identity cannot sign in to $CODEWIRE_SERVER_URL"
  jq -e --arg slug "$SMOKE_ORG_SLUG" '
    type == "array" and length == 1 and .[0].slug == $slug and .[0].role == "owner"
  ' "$orgs" >/dev/null || die "the API key does not own exactly the $SMOKE_ORG_SLUG organization"
}

# --------------------------------------------------------------- lifecycle

env_state() {
  local out="$TMPDIR_PROOF/env-info.out"
  cw info "$ENV_ID" >"$out" 2>&1 || return 1
  awk '$1 == "State:" {print $2; exit}' "$out"
}

wait_for_state() {
  local want="$1" deadline state
  deadline=$(( $(seconds_now) + PROOF_TIMEOUT_SECONDS ))
  while (( $(seconds_now) < deadline )); do
    state="$(env_state || true)"
    [[ "$state" == "$want" ]] && return 0
    if [[ "$state" == error ]]; then
      log "environment $ENV_ID entered error while waiting for $want"
      return 1
    fi
    sleep 10
  done
  log "environment $ENV_ID did not reach $want within ${PROOF_TIMEOUT_SECONDS}s"
  return 1
}

create_env() {
  local name out started finished args
  name="b2c-proof-$(date +%s)"
  out="$TMPDIR_PROOF/create.out"
  args=(create --image "$PROOF_IMAGE" --name "$name" --cpu "$PROOF_CPU"
    --memory "$PROOF_MEMORY" --disk "$PROOF_DISK" --isolation confidential
    --ttl "$PROOF_TTL" --no-network --no-wait --yes --output json)
  if [[ -n "$CREDENTIAL_PROFILE" ]]; then
    args+=(--profile "$CREDENTIAL_PROFILE")
  else
    args+=(--no-profile)
  fi
  started="$(seconds_now)"
  if ! cw "${args[@]}" >"$out" 2>&1; then
    sed 's/[[:cntrl:]]//g' "$out" >&2
    die "confidential create was refused"
  fi
  ENV_ID="$(jq -r '.id // empty' "$out" 2>/dev/null || true)"
  [[ "$ENV_ID" =~ ^[0-9a-f-]{36}$ ]] || die "could not read the created environment ID"
  CREATED=1
  pass "confidential create accepted ($ENV_ID)"
  if wait_for_state running; then
    finished="$(seconds_now)"
    pass "confidential environment running $((finished - started))s after the create request"
  else
    die "confidential environment never reached running"
  fi
}

# -------------------------------------------------------------- Kubernetes

sandbox_name() {
  kubectl_ro get sandboxclaim -n "$SANDBOX_NAMESPACE" "sandbox-$ENV_ID" -o json |
    jq -r '.status.sandbox.name // ""'
}

sandbox_json() {
  local sandbox
  sandbox="$(sandbox_name)"
  [[ -n "$sandbox" ]] || return 1
  kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json
}

pod_json() {
  local sandbox pod
  sandbox="$(sandbox_name)"
  [[ -n "$sandbox" ]] || return 1
  pod="$(kubectl_ro get sandbox -n "$SANDBOX_NAMESPACE" "$sandbox" -o json |
    jq -r --arg sandbox "$sandbox" '.metadata.annotations["agents.x-k8s.io/pod-name"] // $sandbox')"
  kubectl_ro get pod -n "$SANDBOX_NAMESPACE" "$pod" -o json
}

capture_pod() {
  pod_json >"$TMPDIR_PROOF/pod.json" || die "could not read the workspace Pod"
  sandbox_json >"$TMPDIR_PROOF/sandbox.json" || die "could not read the Sandbox"
}

pod_on_snp_node() {
  local node
  node="$(jq -r '.spec.nodeName // ""' "$TMPDIR_PROOF/pod.json")"
  [[ -n "$node" ]] || return 1
  kubectl_ro get nodes -l "$SNP_NODE_LABEL" -o name | grep -qx "node/$node"
}

pod_runs_confidential() {
  jq -e '.spec.runtimeClassName == "confidential"
    and .metadata.labels["codewire.sh/isolation-tier"] == "confidential"' \
    "$TMPDIR_PROOF/pod.json" >/dev/null
}

pod_is_identity_free() {
  jq -e '
    (.spec.containers[] | select(.name == "workspace")) as $w
    | ([$w.env[]?.name]) as $names
    | ($names | index("CODEWIRE_DAEMON_AUTH_TOKEN") | not)
    and ($names | index("CODEWIRE_ENVIRONMENT_ID") | not)
    and ($names | index("CODEWIRE_ENVIRONMENT_OPERATION_GENERATION") | not)
    and ($names | index("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS") | not)
    and ([$w.env[]? | select(.name == "CODEWIRE_POD_UID") | .valueFrom.fieldRef.fieldPath]
         == ["metadata.uid"])
    and ([.spec.volumes[] | select(.name == "workspace-binding-identity")
          | .projected.sources[0].serviceAccountToken.audience]
         == ["codewire.internal.workspace-binding.v1"])
    and ([.spec.containers[] | select(.name != "workspace")
          | (.volumeMounts // [])[] | select(.name == "workspace-binding-identity")]
         | length == 0)
    and (.spec.automountServiceAccountToken == false)
  ' "$TMPDIR_PROOF/pod.json" >/dev/null
}

pod_mounts_no_config_map_and_keeps_state_in_memory() {
  jq -e '
    ([.spec.volumes[] | select(has("configMap"))] | length == 0)
    and ([.spec.volumes[] | select(.name == "codewire-run") | .emptyDir.medium] == ["Memory"])
  ' "$TMPDIR_PROOF/pod.json" >/dev/null
}

pod_carries_measured_anchors() {
  jq -e --arg id "$ENV_ID" --arg roots "$MEASURED_ROOTS_ENV" \
    --arg measured "$MEASURED_ENVIRONMENT_ENV" --arg url "$BINDING_URL_ENV" '
    (.spec.containers[] | select(.name == "workspace") | .env) as $env
    | ([$env[] | select(.name == $measured) | .value] == [$id])
    and ([$env[] | select(.name == $roots) | .value
          | test("-----BEGIN CERTIFICATE-----")] == [true])
    and ([$env[] | select(.name == $url) | .value
          | test("^https://[a-z0-9.-]+:8087$")] == [true])
    and ([.spec.containers[] | select(.name != "workspace") | (.env // [])[]
          | select(.name == $roots or .name == $measured)] | length == 0)
  ' "$TMPDIR_PROOF/pod.json" >/dev/null
}

decoded_init_data() { # FILE -> init-data TOML on stdout
  jq -er --arg key "$INIT_DATA_ANNOTATION" '.metadata.annotations[$key]' "$1" |
    base64 -d | gzip -dc
}

init_data_pins_the_anchors() {
  local init="$TMPDIR_PROOF/init-data.toml" name value
  decoded_init_data "$TMPDIR_PROOF/pod.json" >"$init" || return 1
  grep -Fq "\"codewire_workspace_storage_key_id\" = \"$ENV_ID\"" "$init" || return 1
  if grep -Fq "CODEWIRE_DAEMON_AUTH_TOKEN" "$init"; then return 1; fi
  for name in "$BINDING_URL_ENV" "$MEASURED_ROOTS_ENV" "$MEASURED_ENVIRONMENT_ENV"; do
    value="$(jq -c --arg name "$name" \
      '.spec.containers[] | select(.name == "workspace") | .env[] | select(.name == $name) | .value' \
      "$TMPDIR_PROOF/pod.json")"
    grep -Fq "\"name\": \"$name\"" "$init" || return 1
    grep -Fq "\"value\": $value" "$init" || return 1
  done
}

sandbox_carries_the_pods_init_data() {
  local pod_init sandbox_init
  pod_init="$(jq -r --arg key "$INIT_DATA_ANNOTATION" '.metadata.annotations[$key] // ""' \
    "$TMPDIR_PROOF/pod.json")"
  sandbox_init="$(jq -r --arg key "$INIT_DATA_ANNOTATION" \
    '.spec.podTemplate.metadata.annotations[$key] // ""' "$TMPDIR_PROOF/sandbox.json")"
  [[ -n "$pod_init" && "$pod_init" == "$sandbox_init" ]]
}

# ------------------------------------------------------------------ access

daemon_answers() {
  timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$ENV_ID" -- true \
    >/dev/null 2>&1
}

guest_sees_its_measured_environment() {
  local seen
  # The workspace shell expands it, not this one.
  # shellcheck disable=SC2016
  seen="$(timeout 180 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" run --no-tty --in "$ENV_ID" -- \
    sh -c 'printf %s "${CODEWIRE_MEASURED_ENVIRONMENT_ID:-}"' 2>/dev/null)" || return 1
  [[ "$seen" == "$ENV_ID" ]]
}

ssh_config() {
  local config="$TMPDIR_PROOF/ssh_config"
  if [[ ! -s "$config" ]]; then
    "$CW_BIN" --server "$CODEWIRE_SERVER_URL" setup ssh --ssh-config-file "$config" >/dev/null ||
      die "cw setup ssh could not write the managed SSH block"
  fi
  printf '%s\n' "$config"
}

user_ssh() { # TRANSPORT ARGS...
  local transport="$1" config
  shift
  config="$(ssh_config)"
  env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" CW_SSH_TRANSPORT="$transport" \
    timeout "$PROOF_SSH_TIMEOUT" ssh -F "$config" -T -o BatchMode=yes -o ConnectTimeout=120 \
    "cw-cloud-$ENV_ID" "$@"
}

user_scp() { # TRANSPORT ARGS...
  local transport="$1" config
  shift
  config="$(ssh_config)"
  env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL" CW_SSH_TRANSPORT="$transport" \
    timeout "$PROOF_SSH_TIMEOUT" scp -F "$config" -o BatchMode=yes -o ConnectTimeout=120 "$@"
}

ssh_runs_a_command_line() { # TRANSPORT
  local output status=0
  output="$(user_ssh "$1" 'printf a && printf b | tr b B; exit 7' 2>"$TMPDIR_PROOF/ssh-$1.err" </dev/null)" ||
    status=$?
  if [[ "$output" == aB && "$status" == 7 ]]; then return 0; fi
  log "ssh over $1: output '$output', exit $status; $(sed 's/[[:cntrl:]]//g' "$TMPDIR_PROOF/ssh-$1.err" | tail -n 2 | tr '\n' ' ')"
  return 1
}

scp_round_trips() { # TRANSPORT
  local up="$TMPDIR_PROOF/scp-up-$1" down="$TMPDIR_PROOF/scp-down-$1"
  head -c 1048576 /dev/urandom >"$up"
  user_scp "$1" "$up" "cw-cloud-$ENV_ID:b2c-proof-$1.bin" </dev/null 2>/dev/null || return 1
  user_scp "$1" "cw-cloud-$ENV_ID:b2c-proof-$1.bin" "$down" </dev/null 2>/dev/null || return 1
  cmp -s "$up" "$down"
}

recorded_host_key() {
  timeout 60 "$CW_BIN" --server "$CODEWIRE_SERVER_URL" ssh known-hosts "cw-cloud-$ENV_ID" 2>/dev/null
}

# OpenSSH with a pinned known_hosts file in place of the block's
# KnownHostsCommand, otherwise the managed block's trust settings.
ssh_with_pinned_key() { # LABEL KNOWN_HOSTS
  local cw_command
  cw_command="$(printf '%q --server %q' "$CW_BIN" "$CODEWIRE_SERVER_URL")"
  env CW_SSH_TRANSPORT=websocket timeout "$PROOF_SSH_TIMEOUT" ssh -F /dev/null -T \
    -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
    -o PubkeyAuthentication=no -o StrictHostKeyChecking=yes \
    -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no \
    -o "UserKnownHostsFile=$2" -o ConnectTimeout=120 \
    -o "ProxyCommand=$cw_command --cloud shell --stdio %n" \
    "codewire@cw-cloud-$ENV_ID" true </dev/null >/dev/null 2>"$TMPDIR_PROOF/ssh-pinned-$1.err"
}

host_key_is_recorded_and_served() {
  local recorded pinned="$TMPDIR_PROOF/known_hosts.recorded"
  recorded="$(recorded_host_key)" || return 1
  [[ "$recorded" =~ ^cw-cloud-$ENV_ID\ ssh-ed25519\ [A-Za-z0-9+/]+=*$ ]] || return 1
  printf '%s\n' "$recorded" >"$pinned"
  ssh_with_pinned_key recorded "$pinned"
}

other_host_keys_are_refused() { # KNOWN_HOSTS-or-empty
  local pinned="${1:-}" forged="$TMPDIR_PROOF/forged-host-key"
  if [[ -z "$pinned" ]]; then
    rm -f "$forged" "$forged.pub"
    ssh-keygen -q -t ed25519 -N '' -C '' -f "$forged" >/dev/null
    pinned="$TMPDIR_PROOF/known_hosts.forged"
    printf 'cw-%s %s\n' "$ENV_ID" "$(awk '{print $1, $2}' "$forged.pub")" >"$pinned"
  fi
  if ssh_with_pinned_key forged "$pinned"; then return 1; fi
  grep -Eq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' \
    "$TMPDIR_PROOF/ssh-pinned-forged.err"
}

relay_reads_the_private_repository() {
  user_ssh websocket "git ls-remote --exit-code $(printf '%q' "$PRIVATE_REPO") HEAD" \
    </dev/null >/dev/null 2>&1
}

# ---------------------------------------------------------------- journeys

prove_runtime() {
  capture_pod
  check "Pod runs the confidential runtime" pod_runs_confidential
  check "Pod is scheduled on an SEV-SNP node" pod_on_snp_node
  check "Pod is identity-free: binding token only, no daemon token" pod_is_identity_free
  check "Pod mounts no ConfigMap and keeps the daemon's state in guest memory" \
    pod_mounts_no_config_map_and_keeps_state_in_memory
  check "workspace carries each measured anchor exactly once" pod_carries_measured_anchors
  check "measured init-data pins the anchors and names the environment as the storage key" \
    init_data_pins_the_anchors
  check "the Sandbox carries exactly the Pod's measured init-data" \
    sandbox_carries_the_pods_init_data
  check "the bound daemon answers" daemon_answers
  check "the guest sees its measured environment" guest_sees_its_measured_environment
}

prove_access() {
  local transport
  check "the recorded host key is the one served" host_key_is_recorded_and_served
  check "a host key other than the recorded one is refused" other_host_keys_are_refused
  for transport in websocket tailnet; do
    check "ssh over $transport runs a command line and keeps its exit status" \
      ssh_runs_a_command_line "$transport"
    check "scp over $transport round-trips 1 MiB" scp_round_trips "$transport"
  done
  if [[ -n "$PRIVATE_REPO" ]]; then
    check "the credential relay serves the selected profile" relay_reads_the_private_repository
  fi
}

prove_hold() {
  (( HOLD_MINUTES > 0 )) || return 0
  log "holding ${HOLD_MINUTES} minutes so the binding token and peer token renew"
  sleep $(( HOLD_MINUTES * 60 ))
  check "after ${HOLD_MINUTES} minutes the daemon still answers" daemon_answers
  check "after ${HOLD_MINUTES} minutes ssh over the tailnet still works" \
    ssh_runs_a_command_line tailnet
}

prove_stop_start() {
  local before_uid after_uid before_key
  [[ "$SKIP_STOP_START" == 0 ]] || return 0
  before_uid="$(jq -r '.metadata.uid' "$TMPDIR_PROOF/pod.json")"
  before_key="$TMPDIR_PROOF/known_hosts.previous"
  recorded_host_key >"$before_key" || true
  log "stopping and starting $ENV_ID"
  cw stop "$ENV_ID" >/dev/null || { fail "stop accepted"; return; }
  if ! wait_for_state stopped; then fail "environment stopped"; return; fi
  cw start "$ENV_ID" >/dev/null || { fail "start accepted"; return; }
  if ! wait_for_state running; then fail "environment running again"; return; fi
  pass "a confidential stop and start reaches running"
  capture_pod
  after_uid="$(jq -r '.metadata.uid' "$TMPDIR_PROOF/pod.json")"
  check "start replaced the Pod" test "$before_uid" != "$after_uid"
  check "the restarted Pod is identity-free" pod_is_identity_free
  check "the restarted Pod's measured init-data pins the anchors" init_data_pins_the_anchors
  check "the Sandbox carries exactly the restarted Pod's init-data" \
    sandbox_carries_the_pods_init_data
  check "the restarted daemon serves its recorded host key" host_key_is_recorded_and_served
  if [[ -s "$before_key" ]]; then
    check "the previous Pod's host key is refused" other_host_keys_are_refused "$before_key"
  fi
  check "ssh over websocket works after the restart" ssh_runs_a_command_line websocket
}

main() {
  parse_args "$@"
  for command in jq kubectl ssh scp ssh-keygen base64 gzip; do require_cmd "$command"; done
  mkdir -p "$PROOF_TMP_PARENT"
  TMPDIR_PROOF="$(mktemp -d "$PROOF_TMP_PARENT/confidential-binding.XXXXXX")"
  trap cleanup EXIT
  build_cw
  use_smoke_identity
  kubectl_ro get nodes -l "$SNP_NODE_LABEL" -o name | grep -q . ||
    die "no node is labelled $SNP_NODE_LABEL"

  if [[ -n "$EXISTING_ENV_ID" ]]; then
    ENV_ID="$EXISTING_ENV_ID"
    wait_for_state running || die "environment $ENV_ID is not running"
  else
    create_env
  fi
  prove_runtime
  prove_access
  prove_hold
  prove_stop_start

  printf '%s\n' "${RESULTS[@]}"
  if (( FAILURES > 0 )); then
    die "$FAILURES check(s) failed"
  fi
  log "confidential binding proven on $ENV_ID"
}

main "$@"
