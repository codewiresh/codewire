#!/usr/bin/env bash
# Dev proof that a sandbox whose VM dies recovers by itself, and that cw stop and
# cw start tell the truth meanwhile (#3851). It uses throwaway sandboxes of the
# synthetic smoke account and removes them on exit.
#
#   scripts/runtime/dev/with-dev-smoke-auth.sh -- \
#     scripts/runtime/dev/prove-dev-vm-death-recovery.sh [--rounds LIST] [--young-tries N]
#
# Rounds (default: established,young):
#   established  the VM dies after the sandbox has been up past the crash-recovery
#                minimum; it must run again within ESTABLISHED_BOUND_SECONDS
#   young        the VM dies straight after create, which normally waits for the
#                stuck-state sweep; within YOUNG_BOUND_SECONDS it must run again. If
#                it shows `error` first, cw stop must refuse, and cw start must work
#                or refuse only because recovery has already moved it on. A round that
#                recovers before `error` is seen is retried (--young-tries, default 3),
#                then reported as SKIP: the commands were not exercised
#
# How a VM dies: no Pod here has host access (owner, 2026-11-02, #3718), and the guest
# kernel has no /proc/sysrq-trigger. So DinD sets the guest's vm.panic_on_oom=2 and the
# workspace exhausts its memory; kernel.panic=1 then ends the VM. That panics whichever
# kernel it reaches, so it runs only after proving the Pod is a Kata guest whose kernel
# isn't the node's. On runc it would panic the node.
#
# A death is proven by a new guest boot_id and Pod UID, never by the sandbox answering:
# a sandbox that never died answers too.
#
# Exit 0 passed (SKIPs are printed), 1 a check failed, 2 could not run.
#
# Environment: CODEWIRE_DEV_SMOKE_API_KEY (from with-dev-smoke-auth.sh), CW_BIN (default
# cw), PROOF_CPU and PROOF_MEMORY (default one 4 GiB pool shape, which fills fastest).
# KUBE_CONTEXT is the codewire-dev context, or what scripts/kube-access gives for
# the Dev cluster (it exports INFRA_KUBE_ENVIRONMENT=dev), which is how an agent
# session runs this:
#
#   scripts/kube-access --mode agent <dev-cluster> -- \
#     scripts/runtime/dev/with-dev-smoke-auth.sh -- \
#     scripts/runtime/dev/prove-dev-vm-death-recovery.sh
set -euo pipefail
umask 077

CODEWIRE_SERVER_URL="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
SANDBOX_NAMESPACE="${SANDBOX_NAMESPACE:-dev-sandboxes}"
KUBE_CONTEXT="${KUBE_CONTEXT:-codewire-dev}"
CW_BIN="${CW_BIN:-cw}"
PROOF_CPU="${PROOF_CPU:-1000m}"
PROOF_MEMORY="${PROOF_MEMORY:-4096}"
ROUNDS=(established young)
YOUNG_TRIES=3
# Past CRASH_RECOVERY_MIN_RUNNING (60 s) in worker/loops.rs.
readonly ESTABLISHED_SETTLE_SECONDS=75
# Measured on Dev on 2026-11-03: 19 and 20 s from the containers ending to `running`.
readonly ESTABLISHED_BOUND_SECONDS=60
# The sweep's 300 s window and 30 s tick, one start, and the time to notice. Measured: 336 s.
readonly YOUNG_BOUND_SECONDS=420
readonly ROUND_TIMEOUT_SECONDS=480
readonly POLL_SECONDS=2
readonly HOG='import itertools; a = [b"\1" * (1 << 26) for _ in itertools.count()]'

CONFIG_DIR=""
CREATED=()
HOG_PID=""
FAILURES=0
SKIPS=0

log() { printf '[vm-death] %s\n' "$*" >&2; }
die() { printf '[vm-death] ERROR: %s\n' "$*" >&2; exit 2; }
pass() { log "PASS $*"; }
fail() { FAILURES=$((FAILURES + 1)); log "FAIL $*"; }
skip() { SKIPS=$((SKIPS + 1)); log "SKIP $*"; }
usage() { sed -n '2,37p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

now() { date +%s; }
nap() { sleep "$1"; }
k() { timeout 30 kubectl --context "$KUBE_CONTEXT" "$@" </dev/null; }
cw_cli() {
  CW_CONFIG_DIR="$CONFIG_DIR" CODEWIRE_API_KEY="${CODEWIRE_DEV_SMOKE_API_KEY:-}" \
    timeout 120 "$CW_BIN" --cloud --server "$CODEWIRE_SERVER_URL" "$@" </dev/null
}

# One failed read while a VM dies isn't a result: both of these report nothing and the poll goes on.
sandbox_state() { cw_cli info "$1" --output json 2>/dev/null | jq -r '.state // empty' || true; }
pod_json() {
  k -n "$SANDBOX_NAMESPACE" get pods -l "codewire.sh/environment-id=$1" -o json 2>/dev/null |
    jq -c '.items[0] // empty' || true
}
guest() { # POD COMMAND...; empty when the guest doesn't answer.
  local pod="$1"
  shift
  k -n "$SANDBOX_NAMESPACE" exec "$pod" -c dind -- "$@" 2>/dev/null || true
}
boot_id() { guest "$1" cat /proc/sys/kernel/random/boot_id; }
start_hog() {
  # Longer than k's limit: this exec only ends when the guest does.
  timeout 180 kubectl --context "$KUBE_CONTEXT" -n "$SANDBOX_NAMESPACE" exec "$1" -c workspace -- \
    python3 -c "$HOG" </dev/null >/dev/null 2>&1 &
  HOG_PID=$!
}
# When the guest's containers ended, in seconds; empty until they have.
containers_ended_at() {
  local ended
  ended="$(jq -r '[.status.containerStatuses[]?.state.terminated.finishedAt // empty] | first // empty' <<<"$1")"
  [[ -n "$ended" ]] && date -d "$ended" +%s
  return 0
}

# Fails closed: anything it can't read means no.
require_kata_guest() { # POD_JSON
  local pod class handler node guest_kernel node_kernel
  pod="$(jq -r '.metadata.name // empty' <<<"$1")"
  class="$(jq -r '.spec.runtimeClassName // empty' <<<"$1")"
  node="$(jq -r '.spec.nodeName // empty' <<<"$1")"
  [[ -n "$pod" && -n "$class" && -n "$node" ]] || { log "refusing: the Pod has no runtime class or node"; return 1; }
  handler="$(k get runtimeclass "$class" -o jsonpath='{.handler}' 2>/dev/null || true)"
  [[ "$handler" == *kata* ]] || { log "refusing: handler '$handler' is not Kata"; return 1; }
  guest_kernel="$(guest "$pod" uname -r)"
  node_kernel="$(k get node "$node" -o jsonpath='{.status.nodeInfo.kernelVersion}' 2>/dev/null || true)"
  [[ -n "$guest_kernel" && -n "$node_kernel" && "$guest_kernel" != "$node_kernel" ]] ||
    { log "refusing: guest kernel '$guest_kernel' is not proven apart from node kernel '$node_kernel'"; return 1; }
}

# cw stop and cw start in `error`: each either works or says something true.
commands_in_error() { # LABEL NAME
  local label="$1" name="$2" output state
  if output="$(cw_cli stop "$name" 2>&1)"; then
    fail "$label: cw stop accepted a sandbox in error"
  elif [[ "$output" == *'must be running'* ]]; then
    pass "$label: cw stop refuses error and says it must be running"
  else
    fail "$label: cw stop's refusal doesn't say why: ${output:0:200}"
  fi
  if output="$(cw_cli start "$name" 2>&1)"; then
    pass "$label: cw start accepted error"
    return 0
  fi
  state="$(sandbox_state "$name")"
  if [[ "$output" == *'must be stopped, pending, or errored'* && "$state" != error && "$state" != stopped && "$state" != pending ]]; then
    pass "$label: recovery got there first, and cw start's refusal is true (state $state)"
  else
    fail "$label: cw start refused in state '$state': ${output:0:200}"
  fi
}

# Returns 0 when the round proved or failed something; 3 when it recovered too fast to
# see `error`, for a young round to retry.
vm_death_round() { # LABEL SETTLE_SECONDS BOUND_SECONDS TRY_COMMANDS
  local label="$1" settle="$2" bound="$3" try_commands="$4"
  local name id pod_object pod uid boot0 armed hog_started deadline current new_uid
  local state="" object="" boot="" ended="" tried=0 recovered_at=""

  name="proof-vmdeath-$label-$(now)"
  CREATED+=("$name")
  cw_cli create --no-file --image workspace --name "$name" --cpu "$PROOF_CPU" --memory "$PROOF_MEMORY" \
    --isolation standard --ttl 30m --no-network --yes >/dev/null 2>&1 || { fail "$label: create failed"; return 0; }
  id="$(cw_cli info "$name" --output json 2>/dev/null | jq -r '.id // empty' || true)"
  pod_object="$(pod_json "$id")"
  [[ -n "$id" && -n "$pod_object" ]] || { fail "$label: no Pod for the sandbox"; return 0; }
  require_kata_guest "$pod_object" || { fail "$label: not a proven Kata guest; killed nothing"; return 0; }
  pod="$(jq -r '.metadata.name' <<<"$pod_object")"
  uid="$(jq -r '.metadata.uid' <<<"$pod_object")"
  boot0="$(boot_id "$pod")"
  [[ -n "$boot0" ]] || { fail "$label: can't read the guest's boot_id"; return 0; }
  # shellcheck disable=SC2016 # Expanded in the sandbox.
  cw_cli run --no-tty --in "$name" -- sh -c 'echo before-death >"$HOME/.vm-death-proof-marker"; sync' >/dev/null 2>&1 ||
    { fail "$label: can't write the marker file"; return 0; }

  nap "$settle"
  armed="$(guest "$pod" sh -c 'echo 2 >/proc/sys/vm/panic_on_oom; cat /proc/sys/vm/panic_on_oom')"
  [[ "$armed" == 2 ]] || { fail "$label: could not arm the guest's panic"; return 0; }
  start_hog "$pod"
  hog_started="$(now)"
  log "$label: exhausting the memory of $pod"

  deadline=$(( hog_started + ROUND_TIMEOUT_SECONDS ))
  while (( $(now) < deadline )); do
    state="$(sandbox_state "$name")"
    object="$(pod_json "$id")"
    if [[ -z "$ended" && "$(jq -r '.metadata.uid // empty' <<<"$object")" == "$uid" ]]; then
      ended="$(containers_ended_at "$object")"
    fi
    if [[ "$state" == error && "$tried" == 0 && "$try_commands" == 1 ]]; then
      tried=1
      commands_in_error "$label" "$name"
    fi
    if [[ "$state" == running ]]; then
      current="$(jq -r '.metadata.name // empty' <<<"$object")"
      boot="$([[ -z "$current" ]] || boot_id "$current")"
      if [[ -n "$boot" && "$boot" != "$boot0" ]] && cw_cli run --no-tty --in "$name" -- true >/dev/null 2>&1; then
        recovered_at="$(now)"
        break
      fi
    fi
    nap "$POLL_SECONDS"
  done

  if [[ -z "$recovered_at" ]]; then
    if [[ -z "$ended" && ( -z "$boot" || "$boot" == "$boot0" ) && "$state" == running ]]; then
      fail "$label: the VM never died, so this proved nothing (boot_id still $boot0)"
    else
      fail "$label: not running on a new VM within ${ROUND_TIMEOUT_SECONDS}s (state ${state:-unknown})"
    fi
    return 0
  fi

  new_uid="$(jq -r '.metadata.uid // empty' <<<"$object")"
  if [[ -n "$new_uid" && "$new_uid" != "$uid" ]]; then
    pass "$label: a new Pod and a new guest boot_id"
  else
    fail "$label: a new boot_id but the same Pod UID $uid"
  fi
  # The containers' end is the death's latest sign. If it was never seen, the hog's
  # start is earlier still, so this can only overstate the time.
  local took=$(( recovered_at - ${ended:-$hog_started} ))
  if (( took <= bound )); then
    pass "$label: running ${took}s after the VM died (bound ${bound}s)"
  else
    fail "$label: running ${took}s after the VM died (bound ${bound}s)"
  fi
  # shellcheck disable=SC2016 # Expanded in the sandbox.
  if [[ "$(cw_cli run --no-tty --in "$name" -- sh -c 'cat "$HOME/.vm-death-proof-marker"' 2>/dev/null | tail -1 || true)" == before-death ]]; then
    pass "$label: the file written before the death is still there"
  else
    fail "$label: the file written before the death is gone"
  fi
  if [[ "$try_commands" == 1 && "$tried" == 0 ]]; then
    return 3
  fi
  return 0
}

young_rounds() {
  local try rc
  for (( try = 1; try <= YOUNG_TRIES; try++ )); do
    rc=0
    vm_death_round "young$try" 0 "$YOUNG_BOUND_SECONDS" 1 || rc=$?
    [[ "$rc" == 3 ]] || return 0
    log "young$try: recovered before error was seen"
  done
  skip "cw stop and cw start in error: no try of $YOUNG_TRIES showed error"
}

cleanup() {
  local name
  if [[ -n "$HOG_PID" ]]; then
    kill "$HOG_PID" 2>/dev/null || true
    wait "$HOG_PID" 2>/dev/null || true
  fi
  for name in "${CREATED[@]}"; do
    cw_cli rm --yes "$name" >/dev/null 2>&1 || log "could not remove $name; remove it by hand"
  done
  [[ -z "$CONFIG_DIR" ]] || rm -rf "$CONFIG_DIR"
}

parse_args() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --rounds) IFS=, read -ra ROUNDS <<<"${2:?}"; shift 2 ;;
      --young-tries) YOUNG_TRIES="${2:?}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  local round
  for round in "${ROUNDS[@]}"; do
    case "$round" in established|young) ;; *) die "unknown round: $round" ;; esac
  done
  [[ "$YOUNG_TRIES" =~ ^[1-9]$ ]] || die '--young-tries must be 1-9'
  [[ "$CODEWIRE_SERVER_URL" == https://codewire-dev.sh ]] || die 'this proof runs only against Dev'
  [[ "$KUBE_CONTEXT" == codewire-dev ||
    ("${INFRA_KUBE_ENVIRONMENT:-}" == dev && -n "${KUBECONFIG:-}" && "${INFRA_TRANSIENT_KUBE_AUTH:-}" == 1) ]] ||
    die "this proof runs only against Dev: the codewire-dev context, or through scripts/kube-access for the Dev cluster"
  [[ -n "${CODEWIRE_DEV_SMOKE_API_KEY:-}" ]] || die 'CODEWIRE_DEV_SMOKE_API_KEY is required'
  case "$-" in *x*) die 'shell tracing is enabled; it would print the key' ;; esac
}

main() {
  parse_args "$@"
  local round
  CONFIG_DIR="$(mktemp -d)"
  trap cleanup EXIT
  for round in "${ROUNDS[@]}"; do
    case "$round" in
      established) vm_death_round established "$ESTABLISHED_SETTLE_SECONDS" "$ESTABLISHED_BOUND_SECONDS" 0 ;;
      young) young_rounds ;;
    esac
  done
  log "$FAILURES failed, $SKIPS skipped"
  (( FAILURES == 0 )) || exit 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
