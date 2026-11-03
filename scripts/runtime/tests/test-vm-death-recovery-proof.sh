#!/usr/bin/env bash
# Offline contract for the Dev VM-death proof (#3851): it panics nothing it hasn't
# proven is a Kata guest, a sandbox that never died can't pass, and cw stop and
# cw start are held to what they say. The cluster and cw are shell functions, driven by
# a fake clock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROOF="$ROOT/scripts/runtime/dev/prove-dev-vm-death-recovery.sh"

die_test() { printf 'test-vm-death-recovery-proof: %s\n' "$*" >&2; exit 1; }

refuses() {
  local expected="$1" output
  shift
  if output="$(env -u CODEWIRE_DEV_SMOKE_API_KEY "$@" 2>&1)"; then
    die_test "accepted: $*"
  fi
  [[ "$output" == *"$expected"* ]] || die_test "unexpected refusal for $*: $output"
}

bash -n "$PROOF"
"$PROOF" --help | grep -q 'prove-dev-vm-death-recovery.sh' || die_test '--help does not describe the proof'
"$PROOF" --help | grep -q 'scripts/kube-access --mode agent' || die_test '--help does not show the agent command'
refuses 'only against Dev' env CODEWIRE_SERVER_URL=https://codewire.sh CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF"
refuses 'only against Dev' env KUBE_CONTEXT=codewire-prod CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF"
# The Dev cluster's name counts only through kube-access, which renders its KUBECONFIG.
refuses 'only against Dev' env -u KUBECONFIG -u INFRA_TRANSIENT_KUBE_AUTH KUBE_CONTEXT=cw-dev-hz-eu-1 CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF"
refuses 'only against Dev' env KUBECONFIG=/nonexistent INFRA_TRANSIENT_KUBE_AUTH=1 KUBE_CONTEXT=codewire-prod CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF"
refuses 'CODEWIRE_DEV_SMOKE_API_KEY is required' env KUBECONFIG=/nonexistent INFRA_TRANSIENT_KUBE_AUTH=1 KUBE_CONTEXT=cw-dev-hz-eu-1 "$PROOF"
refuses 'CODEWIRE_DEV_SMOKE_API_KEY is required' "$PROOF"
refuses 'unknown round' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --rounds established,nonsense
refuses '--young-tries must be' env CODEWIRE_DEV_SMOKE_API_KEY=x "$PROOF" --young-tries 0
refuses 'shell tracing is enabled' env CODEWIRE_DEV_SMOKE_API_KEY=x bash -x "$PROOF"
# sysrq does nothing on the guest, so a proof using it would never kill anything.
if grep -nE '^[^#]*sysrq-trigger' "$PROOF"; then
  die_test 'the proof kills through sysrq, which the guest kernel lacks'
fi
grep -qF 'cw_cli create --no-file --image' "$PROOF" || die_test 'the proof create reads a codewire.yaml'

# shellcheck disable=SC1090
source "$PROOF"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TRACE="$WORK/trace"
LOG="$WORK/log"
readonly NEVER=999999999999

NOW=1000
now() { printf '%s\n' "$NOW"; }
nap() { NOW=$(( NOW + $1 )); }
trace() { printf '%s\n' "$*" >>"$TRACE"; }
traced() { grep -qx -- "$1" "$TRACE" 2>/dev/null; }
count() { grep -cx -- "$1" "$TRACE" 2>/dev/null || true; }

# The scenario, as seconds after the hog starts.
scenario() {
  : >"$TRACE"
  : >"$LOG"
  NOW=1000
  FAILURES=0
  SKIPS=0
  CREATED=()
  HANDLER=kata-clh GUEST_KERNEL=7.2.15 NODE_KERNEL=6.18.58-talos ARMED=2
  DIES_AFTER=20 ERROR_AFTER=$NEVER RUNNING_AFTER=40 SAME_UID=0 MARKER_KEPT=1
  STOP_RC=1 STOP_OUTPUT='environment must be running to stop'
  START_RC=0 START_OUTPUT=''
  AFTER_START_STATE=''
  INFO_FAILS=0
}
HOG_FILE="$WORK/hog-at"

after() { (( NOW >= $(cat "$HOG_FILE" 2>/dev/null || echo "$NEVER") + $1 )); }

cw_cli() {
  case "$1" in
    create) trace create; return 0 ;;
    rm) trace "rm $3"; return 0 ;;
    stop) trace stop; printf '%s' "$STOP_OUTPUT"; return "$STOP_RC" ;;
    start) trace start; printf '%s' "$START_OUTPUT"; return "$START_RC" ;;
    run)
      # shellcheck disable=SC2016 # The proof's literal command.
      case "$*" in
        *'cat "$HOME/.vm-death-proof-marker"'*) (( MARKER_KEPT == 1 )) && echo before-death; return 0 ;;
      esac
      return 0
      ;;
    info)
      (( INFO_FAILS == 0 )) || ! after 25 || return 1
      local state=running
      if traced start && [[ -n "$AFTER_START_STATE" ]]; then state="$AFTER_START_STATE"
      elif after "$RUNNING_AFTER"; then state=running
      elif after "$ERROR_AFTER"; then state=error
      elif after "$DIES_AFTER"; then state=starting
      fi
      printf '{"id":"env-1","state":"%s"}\n' "$state"
      ;;
  esac
}
k() {
  case "$*" in
    'get runtimeclass'*) printf '%s' "$HANDLER" ;;
    'get node'*) printf '%s' "$NODE_KERNEL" ;;
    *) die_test "unexpected kubectl: $*" ;;
  esac
}
guest() {
  shift
  case "$1" in
    uname) printf '%s' "$GUEST_KERNEL" ;;
    sh) trace armed; printf '%s' "$ARMED" ;;
    *) die_test "unexpected guest command: $*" ;;
  esac
}
boot_id() {
  if after "$RUNNING_AFTER"; then echo boot-new
  elif after "$DIES_AFTER"; then echo ''
  else echo boot-old
  fi
}
start_hog() { trace hog; printf '%s' "$NOW" >"$HOG_FILE"; }
pod_json() {
  local uid=old ended=''
  if after "$RUNNING_AFTER"; then
    (( SAME_UID == 1 )) || uid=new
  elif after "$DIES_AFTER"; then
    ended="$(date -u -d "@$(( $(cat "$HOG_FILE") + DIES_AFTER ))" +%FT%TZ)"
  fi
  jq -nc --arg uid "$uid" --arg ended "$ended" '{
    metadata: {name: "pod-1", uid: $uid},
    spec: {runtimeClassName: "commodity", nodeName: "node-1"},
    status: {containerStatuses: [{state: (if $ended == "" then {running: {}} else {terminated: {finishedAt: $ended}} end)}]}
  }'
}

established() { rm -f "$HOG_FILE"; vm_death_round established 75 60 0 2>>"$LOG" || true; }
young() { rm -f "$HOG_FILE"; vm_death_round young 0 420 1 2>>"$LOG" || ROUND_RC=$?; }
logged() { grep -qF -- "$1" "$LOG" || die_test "$2: the log lacks '$1': $(cat "$LOG")"; }
expect() { # FAILURES SKIPS NAME
  [[ "$FAILURES" == "$1" && "$SKIPS" == "$2" ]] ||
    die_test "$3: $FAILURES failed and $SKIPS skipped, wanted $1 and $2: $(cat "$LOG")"
}
killed_nothing() {
  if traced armed || traced hog; then die_test "$1: armed or killed a guest it had not proven: $(cat "$TRACE")"; fi
}

# A VM that dies and comes back fast passes, with the time from the containers' end.
scenario
established
expect 0 0 'a recovery'
traced armed || die_test 'a recovery: never armed the guest'
traced hog || die_test 'a recovery: never exhausted its memory'
logged 'a new Pod and a new guest boot_id' 'a recovery'
logged 'running 2' 'a recovery'
logged 'is still there' 'a recovery'

# Nothing is armed or killed unless the Pod is proven to be a Kata guest.
scenario; HANDLER=runc
established; expect 1 0 'runc'; killed_nothing runc
scenario; HANDLER=''
established; expect 1 0 'an unreadable handler'; killed_nothing 'an unreadable handler'
scenario; GUEST_KERNEL=6.18.58-talos
established; expect 1 0 'the node kernel'; killed_nothing 'the node kernel'
scenario; GUEST_KERNEL=''
established; expect 1 0 'an unreadable guest kernel'; killed_nothing 'an unreadable guest kernel'
scenario; NODE_KERNEL=''
established; expect 1 0 'an unreadable node kernel'; killed_nothing 'an unreadable node kernel'

# If the panic can't be armed, the memory isn't exhausted.
scenario; ARMED=0
established; expect 1 0 'an unarmed guest'
if traced hog; then die_test 'an unarmed guest: exhausted its memory anyway'; fi

# A sandbox that never died answers, and that must not pass (the first sysrq run).
scenario; DIES_AFTER=$NEVER; RUNNING_AFTER=$NEVER
established; expect 1 0 'no death'; logged 'the VM never died' 'no death'

# Too slow, the same Pod, or a lost file each fail.
scenario; DIES_AFTER=20; RUNNING_AFTER=200
established; expect 1 0 'too slow'; logged 'bound 60s' 'too slow'
scenario; SAME_UID=1
established; expect 1 0 'the same Pod'; logged 'the same Pod UID' 'the same Pod'
scenario; MARKER_KEPT=0
established; expect 1 0 'a lost file'; logged 'is gone' 'a lost file'
scenario; DIES_AFTER=20; RUNNING_AFTER=$NEVER
established; expect 1 0 'no recovery'; logged 'not running on a new VM' 'no recovery'

# One failed read during the death doesn't end the proof, with errexit on as in main.
scenario; INFO_FAILS=1; rm -f "$HOG_FILE"
( vm_death_round established 75 60 0 2>>"$LOG"; trace survived )
traced survived || die_test 'a failed read stopped the proof'

# In error, cw stop must refuse and say why, and cw start must work.
scenario; ERROR_AFTER=30; RUNNING_AFTER=340
ROUND_RC=0; young; expect 0 0 'commands in error'
[[ "$ROUND_RC" == 0 ]] || die_test 'commands in error: asked to retry'
traced stop || die_test 'commands in error: cw stop not run'
traced start || die_test 'commands in error: cw start not run'
[[ "$(count stop)" == 1 ]] || die_test 'commands in error: run more than once'
logged 'cw start accepted error' 'commands in error'
scenario; ERROR_AFTER=30; RUNNING_AFTER=340; STOP_RC=0
young; expect 1 0 'cw stop accepted error'
scenario; ERROR_AFTER=30; RUNNING_AFTER=340; STOP_OUTPUT='internal error'
young; expect 1 0 "cw stop's refusal says why"
# It stays in error here, so the round also fails to recover.
scenario; ERROR_AFTER=30; RUNNING_AFTER=340; START_RC=1; START_OUTPUT='start environment: environment must be stopped, pending, or errored to start'; AFTER_START_STATE=error
young; expect 2 0 'cw start refused the state it accepts'
logged 'cw start refused in state' 'cw start refused the state it accepts'
scenario; ERROR_AFTER=30; RUNNING_AFTER=340; START_RC=1; START_OUTPUT='start environment: environment must be stopped, pending, or errored to start'; AFTER_START_STATE=starting
young
logged "cw start's refusal is true (state starting)" 'recovery got there first'

# A recovery too quick to show error retries, and ends as a SKIP, never a pass.
scenario
# shellcheck disable=SC2034 # The sourced proof reads it.
YOUNG_TRIES=3
rm -f "$HOG_FILE"
young_rounds 2>>"$LOG"
expect 0 1 'error never seen'
[[ "$(count create)" == 3 ]] || die_test "error never seen: $(count create) creates, wanted 3"
logged 'no try of 3 showed error' 'error never seen'
if traced stop || traced start; then die_test 'error never seen: ran the commands'; fi

# Every sandbox created is removed.
scenario
# shellcheck disable=SC2034 # The sourced proof reads them.
CREATED=(one two) CONFIG_DIR='' HOG_PID=''
cleanup
traced 'rm one' || die_test 'cleanup left a sandbox'
traced 'rm two' || die_test 'cleanup left a sandbox'

printf 'vm death recovery proof contract: OK\n'
