#!/usr/bin/env bash
# The local VM credentials smoke, Part A (#5220): real cw binaries on a Linux
# host with KVM, driven through public commands only, in the isolation of
# scripts/ci/verify/lib/local-smoke-isolation.sh. Each step is a sub-feature of
# docs/journeys/local-vm-credentials-smoke.md and reports failures under its
# journey ID with cw's own words. The credentials are an SSH key cw generates
# into the smoke's private keyring and two made-up API keys; nothing contacts
# a provider.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

die() {
  printf 'smoke-local-credentials: %s\n' "$*" >&2
  exit 1
}

# shellcheck source=scripts/ci/verify/lib/local-smoke-isolation.sh
source "$ROOT/scripts/ci/verify/lib/local-smoke-isolation.sh"

usage() {
  cat <<'USAGE' >&2
usage: smoke-local-credentials.sh --cw ABSOLUTE_PATH [--cw-sha256 HEX]
                                  [--runtime-from DIR] --scratch DIR
                                  [--previous-cw ABSOLUTE_PATH
                                   [--previous-cw-sha256 HEX]]

Runs the journey steps that need only the cw under test:
  smoke-provider-unresolved
  smoke-profile-after-create
  smoke-attach-restart
  smoke-proxy-down
smoke-proxy-down needs HTTPS from the guest to releases.codewire.sh.
With --previous-cw, a released cw before the candidate, it runs only
smoke-upgrade's authority-left-running case (#5238) instead: the previous
release's credential service is left running, then the candidate gives a VM
a profile.
--cw-sha256 checks a downloaded release before it runs. --runtime-from
installs the local VM runtime from a release directory (for a cw built from
source, which pins none); without it, the first create downloads the runtime
this cw pins. --scratch is an existing directory for the smoke's private
roots, removed after.
USAGE
}

CW=''
CW_SHA256=''
PREVIOUS_CW=''
PREVIOUS_CW_SHA256=''
RUNTIME_FROM=''
SCRATCH=''
SMOKE_DIR=''
LOG=''
VMS=()
# The fingerprint of the SSH key smoke-profile-after-create generates.
GENERATED_FINGERPRINT=''

# Remove the smoke's VMs and private root whatever happened. The root holds
# the private keyring and cw's credential store, the generated private key
# among them, so only the log, which holds none, is kept from a failed run.
cleanup() {
  local status=$? vm kept
  for vm in "${VMS[@]}"; do
    smoke_cw "$CW" rm --local "$vm" --yes >>"$LOG" 2>&1 || true
  done
  smoke_isolation_end || status=1
  if [[ "$status" -ne 0 && -f "$LOG" ]]; then
    kept="$(mktemp "$SCRATCH/smoke-local-credentials.XXXXXX.log")"
    chmod 0600 "$kept"
    cat -- "$LOG" >"$kept"
    echo "smoke-local-credentials: its log is $kept" >&2
  fi
  [[ -z "$SMOKE_DIR" ]] || rm -rf -- "$SMOKE_DIR"
  exit "$status"
}

# Fail STEP with REASON and the last lines cw printed, which name its stage.
step_fail() {
  printf '::error::%s: %s\n' "$1" "$2" >&2
  tail -n 15 "$LOG" >&2 || true
  exit 1
}

# Run cw in the smoke for STEP, logging its output; fail the step on error.
step_cw() {
  local step="$1"
  shift
  printf '$ cw %s\n' "$*" >>"$LOG"
  smoke_cw "$CW" "$@" >>"$LOG" 2>&1 || step_fail "$step" "cw $* failed"
}

# The state `cw ls --local --output json` reports for VM, or nothing.
vm_state() {
  smoke_cw "$CW" ls --local --output json 2>>"$LOG" |
    python3 -c '
import json, sys
name = sys.argv[1]
for entry in json.load(sys.stdin):
    if entry.get("name") == name:
        print(entry.get("state") or entry.get("status") or "")
' "$1"
}

# Fail STEP unless the agent in VM lists FINGERPRINT. ssh-add -l's own output
# is read, not the log, which already holds the fingerprint from generate.
agent_holds() {
  local step="$1" vm="$2" fingerprint="$3" keys
  printf '$ cw exec --in %s -- ssh-add -l\n' "$vm" >>"$LOG"
  keys="$(smoke_cw "$CW" exec --in "$vm" -- ssh-add -l 2>>"$LOG")" ||
    step_fail "$step" "ssh-add -l failed in $vm"
  printf '%s\n' "$keys" >>"$LOG"
  grep -qF "$fingerprint" <<<"$keys" || step_fail "$step" "the guest's agent does not hold $fingerprint"
}

# What `cw ls --local --output json` gives as VM's error: its cause while it
# is in `error`, else nothing.
vm_error() {
  smoke_cw "$CW" ls --local --output json 2>>"$LOG" |
    python3 -c '
import json, sys
name = sys.argv[1]
for entry in json.load(sys.stdin):
    if entry.get("name") == name:
        print(entry.get("error") or "")
' "$1"
}

# A VM made with no credentials is given a credential profile; its managed
# restart must bring it back running with the key in its agent.
step_profile_after_create() {
  local step=smoke-profile-after-create name=smoke-n key=smoke-n-key fingerprint state
  VMS+=("$name")
  step_cw "$step" create --local --name "$name" --no-file --no-profile --yes
  step_cw "$step" exec --in "$name" -- true
  step_cw "$step" credentials --local generate ssh --name "$key"
  fingerprint="$(grep -o 'SHA256:[A-Za-z0-9+/]*' "$LOG" | tail -n 1)"
  [[ -n "$fingerprint" ]] || step_fail "$step" 'the generated key printed no fingerprint'
  GENERATED_FINGERPRINT="$fingerprint"
  step_cw "$step" credentials --local --profile "$name" set ssh "$key"
  step_cw "$step" update --local "$name" --profile "local:$name" --yes
  state="$(vm_state "$name")"
  [[ "$state" == running ]] || step_fail "$step" "after the update the VM is ${state:-missing}, not running"
  agent_holds "$step" "$name" "$fingerprint"
  printf 'ok %s\n' "$step"
}

# Attach through a terminal as a person does: wait for cw's detach hint, type
# TEXT, wait until MARKER is printed, then detach with Ctrl-B d. Prints what
# the terminal showed; fails unless the marker came and cw said it detached.
# argv: TEXT MARKER CW_ARGS...
# shellcheck disable=SC2016 # Python, not shell.
PTY_ATTACH='
import os, pty, re, select, sys, time
text, marker, command = sys.argv[1].encode(), sys.argv[2].encode(), sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(command[0], command)
out, typed, detaching = b"", False, False
deadline = time.time() + float(os.environ.get("SMOKE_ATTACH_SECONDS", "90"))
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.25)
    if ready:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    if not typed and b"Detach: Ctrl-B" in out:
        os.write(fd, text + b"\r")
        typed = True
    if typed and not detaching and marker in out:
        os.write(fd, b"\x02")
        time.sleep(0.3)
        os.write(fd, b"d")
        detaching = True
else:
    os.kill(pid, 9)
_, status = os.waitpid(pid, 0)
shown = re.sub(r"\x1b\[[0-9;?<>]*[A-Za-z]|\x1b[()>=][A-Z0-9]?|\r", "", out.decode("utf-8", "replace"))
print(shown)
if os.waitstatus_to_exitcode(status) != 0 or marker not in out or b"Detached from" not in out:
    sys.exit(1)
'

# Attach to SESSION in VM for STEP, where the session signs with the profile's
# key through its agent; fail unless that attach ran it and detached.
attach_and_sign() {
  local step="$1" vm="$2" session="$3" a="$RANDOM" b="$RANDOM" marker
  # The marker is the sum, which only a live shell prints: replayed output
  # from before a restart holds another one.
  marker="signed-$((a + b))"
  printf '$ cw --local attach %s --session %s\n' "$vm" "$session" >>"$LOG"
  smoke_cw /usr/bin/python3 -I -c "$PTY_ATTACH" \
    "ssh-add -l; ssh-add -L >/tmp/smoke-agent.pub && echo smoke | ssh-keygen -Y sign -n smoke -f /tmp/smoke-agent.pub >/dev/null && echo signed-\$(($a + $b))" \
    "$marker" "$CW" --local attach "$vm" --session "$session" >>"$LOG" 2>&1 ||
    step_fail "$step" "attaching to $vm/$session did not sign with the profile's key and detach"
}

# A session attached and detached in a VM with a profile; after `cw stop` and
# `cw start`, a session in the restarted VM is attached and signs with the
# profile's key through its agent.
step_attach_restart() {
  local step=smoke-attach-restart name=smoke-a key=smoke-n-key fingerprint state
  VMS+=("$name")
  fingerprint="$GENERATED_FINGERPRINT"
  [[ -n "$fingerprint" ]] || step_fail "$step" 'smoke-profile-after-create recorded no generated key'
  step_cw "$step" credentials --local --profile "$name" set ssh "$key"
  step_cw "$step" create --local --name "$name" --no-file --profile "local:$name" --yes
  step_cw "$step" run --in "$name" --name before --detach --tty -- bash
  attach_and_sign "$step" "$name" before
  step_cw "$step" stop --local "$name"
  step_cw "$step" start --local "$name"
  state="$(vm_state "$name")"
  [[ "$state" == running ]] || step_fail "$step" "after the restart the VM is ${state:-missing}, not running"
  step_cw "$step" ls --local "$name"
  step_cw "$step" run --in "$name" --name after --detach --tty -- bash
  local mark
  mark="$(wc -l <"$LOG")"
  attach_and_sign "$step" "$name" after
  log_since "$mark" | grep -qF "$fingerprint" ||
    step_fail "$step" "the restarted VM's agent does not hold $fingerprint"
  printf 'ok %s\n' "$step"
}

# The lines cw has logged since line FROM of the smoke's log.
log_since() {
  tail -n "+$(($1 + 1))" "$LOG"
}

# Wait up to SECONDS for the credential service's broker log to hold a
# `broker_ready` line, after its first SKIP of them, whose `unresolved=` is
# VALUE. The spec names that line as the record of what a broker serves
# (docs/dev/SECRETS-AND-CREDENTIALS.md, "What is recorded").
broker_ready_with() {
  local value="$1" skip="$2" seconds="$3" log="$SMOKE_HOME/.codewire/credentials-v1/logs/brokers.log"
  for ((waited = 0; waited < seconds; waited += 2)); do
    if grep -F ' event=broker_ready ' "$log" 2>/dev/null | tail -n "+$((skip + 1))" |
      sed -n 's/.* unresolved=//p' | grep -qxF -- "$value"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# One request on each provider's route from inside VM, as an agent's client
# makes it: `ROUTE STATUS BODY` a line.
provider_requests() {
  # shellcheck disable=SC2016 # the guest's shell expands these
  step_cw "$1" exec --in "$2" -- sh -c '
    for route in "anthropic $ANTHROPIC_BASE_URL/v1/models" "openai $OPENAI_BASE_URL/models"; do
      set -- $route
      printf "%s %s " "$1" "$(curl -sS -m 30 -o /tmp/smoke-body -w "%{http_code}" "$2")"
      head -c 200 /tmp/smoke-body | tr "\n" " "; echo
    done'
}

# A made-up API key in PROVIDER's shape, on stdout with no newline. It carries
# its own randomness and opens nothing.
made_up_key() {
  local prefix length
  case "$1" in
    anthropic) prefix=sk-ant-api03- length=95 ;;
    openai) prefix=sk-proj- length=48 ;;
    *) die "no made-up key for $1" ;;
  esac
  printf '%s%s' "$prefix" "$(head -c 128 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | head -c "$length")"
}

# A VM whose credential profile names two providers is created while the
# credential service can look neither up: the create succeeds, each
# provider's requests are refused in words, a stop and start works, and once
# the names resolve a broker serves both again with no restart (#5286).
step_provider_unresolved() {
  local step=smoke-provider-unresolved name=smoke-u unanswered="$SMOKE_DIR/resolv.conf" from ready
  local unresolved=api.anthropic.com/api.openai.com
  VMS+=("$name")
  # Nothing listens there, so a lookup gets no answer. The credential service
  # starts with the first credential command and keeps this resolver; cw
  # itself, and the VM's image pull, keep the host's.
  printf 'nameserver 127.255.255.254\n' >"$unanswered"
  SMOKE_RESOLVER="$unanswered"
  for provider in anthropic openai; do
    made_up_key "$provider" |
      step_cw "$step" credentials --local add "$provider" --name "$name-$provider"
    step_cw "$step" credentials --local --profile "$name" set "$provider" "$name-$provider"
  done
  # shellcheck disable=SC2034 # smoke_cw reads it
  SMOKE_RESOLVER=''
  step_cw "$step" create --local --name "$name" --no-file --no-network --profile "local:$name" --yes
  broker_ready_with - 0 1 && step_fail "$step" \
    'the cw under test resolved both providers without the resolver it was given (a cw built against the system C library may not read resolv.conf); this step needs the static cw a release ships'
  broker_ready_with "$unresolved" 0 10 ||
    step_fail "$step" "the first broker did not come up with unresolved=$unresolved"
  from="$(wc -l <"$LOG")"
  provider_requests "$step" "$name"
  for provider in Anthropic OpenAI; do
    log_since "$from" | grep -qF " 502 Codewire: $provider couldn't be reached; try again." ||
      step_fail "$step" "$provider's route did not answer 502 in Codewire's words"
  done
  step_cw "$step" stop --local "$name"
  step_cw "$step" start --local "$name"
  ready="$(grep -cF ' event=broker_ready ' "$SMOKE_HOME/.codewire/credentials-v1/logs/brokers.log")"
  [[ "$(vm_state "$name")" == running ]] || step_fail "$step" 'the VM did not start again'
  # The names resolve again: the same file, rewritten in place.
  cat /etc/resolv.conf >"$unanswered"
  broker_ready_with - "$ready" 120 ||
    step_fail "$step" 'no broker served both providers within two minutes of their names resolving (a host firewall must answer the broker)'
  printf 'ok %s\n' "$step"
}

# What the guest probes: Codewire's own release channel, as the native smoke's
# network qualification does.
readonly PROBE_URL='https://releases.codewire.sh/cw/v1/channels/stable.json'

# The scope's processes that are the cw under test running ROLE, and for an
# environment's helper, ENVIRONMENT_ID's: one PID a line.
role_pids() {
  role_pids_of "$CW" "$@"
}

# The same, for processes BINARY started.
role_pids_of() {
  local binary="$1" role="$2" environment_id="${3:-}" pid
  local -a argv
  while read -r pid; do
    argv=()
    mapfile -d '' -t argv 2>/dev/null <"$SMOKE_PROC_ROOT/$pid/cmdline" || continue
    [[ ${#argv[@]} -ge 2 && "${argv[1]}" == "$role" ]] || continue
    [[ "$(readlink -f -- "${argv[0]}")" == "$(readlink -f -- "$binary")" ]] || continue
    [[ -z "$environment_id" || ( "${argv[2]:-}" == --environment-id && "${argv[3]:-}" == "$environment_id" ) ]] ||
      continue
    printf '%s\n' "$pid"
  done < <(smoke_scope_pids)
}

# SIGKILL the one process role_pids finds for ROLE (and ENVIRONMENT_ID), and
# print `PID EPOCH`, the host's time just before the signal. The signal goes
# through a pidfd opened after the PID was matched, and only once that same
# process is seen still in the smoke's scope with the argv it was matched by,
# so a reused PID fails the step instead of being killed.
kill_role() {
  local step="$1" role="$2" environment_id="${3:-}" pid argv at
  pid="$(role_pids "$role" "$environment_id")"
  [[ -n "$pid" && "$pid" != *$'\n'* ]] ||
    step_fail "$step" "expected exactly one $role, found: ${pid:-none}"
  argv="$(od -An -tx1 -v <"$SMOKE_PROC_ROOT/$pid/cmdline" | tr -d ' \n')" ||
    step_fail "$step" "$role $pid ended before it could be killed"
  at="$(python3 -I -c '
import os, signal, sys, time
proc, pid, argv = sys.argv[1], int(sys.argv[2]), sys.argv[3]
fd = os.pidfd_open(pid)
with open(f"{proc}/self/cgroup") as mine, open(f"{proc}/{pid}/cgroup") as its:
    same_scope = mine.read() == its.read()
with open(f"{proc}/{pid}/cmdline", "rb") as source:
    same_argv = source.read().hex() == argv
if not (same_scope and same_argv):
    sys.exit("not the process that was matched")
at = time.time()
signal.pidfd_send_signal(fd, signal.SIGKILL)
print(f"{at:.6f}")
' "$SMOKE_PROC_ROOT" "$pid" "$argv")" || step_fail "$step" "$role $pid could not be killed as matched"
  printf '$ kill -KILL %s (%s) at %s\n' "$pid" "$role" "$at" >>"$LOG"
  printf '%s %s\n' "$pid" "$at"
}

# The guest's probe lines, `START NAMED DIRECT AGENT`: the guest's wall-clock
# start, the HTTP code of the request by name through the proxy and of the
# request straight to an address (000 for no answer), and `ssh-add -l`'s
# status, read from FILE in the shared workspace. OFFSET is the guest clock's
# lead on the host's (guest_offset), so START - OFFSET is host time, as
# KILLED is. Checks pass or fail on them:
# - agent_mended FILE KILLED OFFSET: some probe after KILLED reached the
#   agent, and none more than five seconds after it failed;
# - egress_closed FILE KILLED OFFSET: at least five probes started from a
#   second after KILLED, and neither request of any of them got an answer.
agent_mended() {
  awk -v killed="$2" -v offset="$3" '
    $1 - offset > killed && $4 == 0 { served = 1 }
    $1 - offset > killed + 5 && $4 != 0 { late = 1 }
    END { exit !(served && !late) }' "$1"
}
egress_closed() {
  awk -v killed="$2" -v offset="$3" '
    $1 - offset >= killed + 1 { after++; if ($2 != "000" || $3 != "000") answered = 1 }
    END { exit !(after >= 5 && !answered) }' "$1"
}

# How far the guest's clock leads the host's: `OFFSET HALF_WIDTH` from
# SAMPLES lines of `HOST_BEFORE GUEST HOST_AFTER`, by the narrowest sample,
# since the guest read its clock somewhere between the host's two readings.
narrowest_offset() {
  awk '
    { width = ($3 - $1) / 2
      if (NR == 1 || width < best) { best = width; offset = $2 - ($1 + $3) / 2 } }
    END { if (NR == 0) exit 1; printf "%.6f %.6f\n", offset, best }'
}

# The guest clock's offset for VM, measured five times through `cw exec`;
# fails STEP unless the narrowest measurement is within half a second.
guest_offset() {
  local step="$1" vm="$2" before guest after
  for _ in 1 2 3 4 5; do
    before="$(date +%s.%N)"
    guest="$(smoke_cw "$CW" exec --in "$vm" -- date +%s.%N 2>>"$LOG")" ||
      step_fail "$step" "cw exec date failed in $vm"
    after="$(date +%s.%N)"
    printf '%s %s %s\n' "$before" "$guest" "$after"
  done | narrowest_offset | {
    read -r offset width
    printf '$ guest clock offset %s, within %s s\n' "$offset" "$width" >>"$LOG"
    awk -v width="$width" 'BEGIN { exit !(width <= 0.5) }' ||
      step_fail "$step" "the guest's clock offset is known only to within $width s"
    printf '%s\n' "$offset"
  }
}

# Wait up to SECONDS for FILE to hold COUNT lines that pass AWK_CONDITION.
wait_for_probes() {
  local file="$1" condition="$2" count="$3" seconds="$4" waited
  for ((waited = 0; waited < seconds; waited++)); do
    [[ "$(awk "$condition" "$file" 2>/dev/null | wc -l)" -ge "$count" ]] && return 0
    sleep 1
  done
  return 1
}

# With a VM running, its credential broker is killed and then its egress
# broker. A credential broker is replaced by the credential service, and the
# agent answers again within seconds with no restart
# (docs/dev/SECRETS-AND-CREDENTIALS.md, "It mends by itself"). An egress
# broker is not: from a second after the kill nothing the guest sends gets an
# answer, the VM turns `error` and says why, and `cw start` restores it.
step_proxy_down() {
  local step=smoke-proxy-down name=smoke-p key=smoke-n-key vm probes stop id killed pid replaced
  local refusal
  local address offset
  # The earlier steps' VMs are stopped, so this VM's helpers are the only ones.
  for vm in "${VMS[@]}"; do
    step_cw "$step" stop --local "$vm"
  done
  VMS+=("$name")
  probes="$SMOKE_WORKSPACE/proxy-down.probes"
  stop="$SMOKE_WORKSPACE/proxy-down.stop"
  step_cw "$step" credentials --local --profile "$name" set ssh "$key"
  step_cw "$step" create --local --name "$name" --no-file --profile "local:$name" --yes
  id="$(smoke_cw "$CW" ls --local --output json 2>>"$LOG" | python3 -c '
import json, sys
print(next(entry["id"] for entry in json.load(sys.stdin) if entry.get("name") == sys.argv[1]))
' "$name")" || step_fail "$step" "cw ls names no $name"
  # The same host straight by its address, with no name to look up: any HTTP
  # answer on port 80 is a connection that got out.
  address="$(getent ahostsv4 "$(sed -E 's|^https://([^/]+)/.*|\1|' <<<"$PROBE_URL")" | awk 'NR == 1 { print $1 }')"
  [[ -n "$address" ]] || step_fail "$step" "the host cannot resolve $PROBE_URL's name"
  # Four probes a second at most, for at most five minutes, until the stop file.
  # shellcheck disable=SC2016 # the guest's shell expands these
  step_cw "$step" run --in "$name" --name probes --detach -- sh -c '
    count=0
    while [ ! -e "$2" ] && [ "$count" -lt 1200 ]; do
      started="$(date +%s.%N)"
      named="$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 3 "$3" 2>/dev/null)"
      direct="$(curl -sS -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 3 "http://$4/" 2>/dev/null)"
      ssh-add -l >/dev/null 2>&1
      printf "%s %s %s %s\n" "$started" "${named:-000}" "${direct:-000}" "$?" >>"$1"
      count=$((count + 1))
      sleep 0.25
    done' probes "/workspace/workspace/${probes##*/}" "/workspace/workspace/${stop##*/}" "$PROBE_URL" "$address"
  # shellcheck disable=SC2016 # an awk condition
  wait_for_probes "$probes" '$2 == "200" && $3 != "000" && $4 == 0' 3 60 ||
    step_fail "$step" "the guest's probes never reached $PROBE_URL, $address and the agent before any kill"
  offset="$(guest_offset "$step" "$name")" || exit 1

  read -r pid killed < <(kill_role "$step" __local-credential-broker)
  sleep 10
  replaced="$(role_pids __local-credential-broker)"
  [[ -n "$replaced" && "$replaced" != "$pid" ]] ||
    step_fail "$step" 'no other credential broker serves after the kill'
  agent_mended "$probes" "$killed" "$offset" ||
    step_fail "$step" "the guest's agent did not answer again within five seconds of the credential broker's kill"

  read -r pid killed < <(kill_role "$step" __native-egress-broker "$id")
  wait_for_probes "$probes" "\$1 - $offset >= $killed + 1" 5 60 ||
    step_fail "$step" 'the guest made no probes after the egress broker was killed'
  egress_closed "$probes" "$killed" "$offset" ||
    step_fail "$step" 'a guest request got an answer a second or more after the egress broker was killed'
  [[ "$(vm_state "$name")" == error ]] ||
    step_fail "$step" 'the VM did not turn error when its egress broker was killed'
  # The VM says why, and what to do about it (#5359).
  [[ "$(vm_error "$name")" == egress_broker_exit ]] ||
    step_fail "$step" 'cw ls --output json does not give egress_broker_exit as the error of the VM'
  refusal="$(smoke_cw "$CW" exec --in "$name" -- true 2>&1)" &&
    step_fail "$step" 'cw exec ran in a VM whose egress broker was killed'
  printf '$ cw exec --in %s -- true\n%s\n' "$name" "$refusal" >>"$LOG"
  if ! grep -qF "the VM's network broker stopped, so nothing can leave the VM" <<<"$refusal" ||
    ! grep -qF "cw --local start $name" <<<"$refusal"; then
    step_fail "$step" 'cw exec did not say that the network broker stopped and how to start the VM again'
  fi
  : >"$stop"
  cat -- "$probes" >>"$LOG"

  step_cw "$step" start --local "$name"
  step_cw "$step" exec --in "$name" -- curl -sS -o /dev/null -w 'egress %{http_code}\n' --max-time 10 "$PROBE_URL"
  tail -n 1 "$LOG" | grep -qx 'egress 200' ||
    step_fail "$step" "cw start did not restore the guest's HTTPS"
  [[ -z "$(vm_error "$name")" ]] ||
    step_fail "$step" 'the started VM still shows an error in cw ls --output json'
  printf 'ok %s\n' "$step"
}

# smoke-upgrade, an authority left running (#5238): the previous release's
# credential service keeps running after an update, and the candidate's first
# start that needs credentials must replace it and come up with the key, never
# fail deep in the guest start as egress_broker_exited.
step_upgrade_authority_left() {
  local step=smoke-upgrade name=smoke-u key=smoke-u-key fingerprint state
  printf '$ previous cw credentials --local list\n' >>"$LOG"
  smoke_cw "$PREVIOUS_CW" credentials --local list >>"$LOG" 2>&1 ||
    step_fail "$step" 'the previous release did not start its credential service'
  [[ -n "$(role_pids_of "$PREVIOUS_CW" __local-credential-authority)" ]] ||
    step_fail "$step" "the previous release's credential service is not running"
  VMS+=("$name")
  step_cw "$step" create --local --name "$name" --no-file --no-profile --yes
  step_cw "$step" credentials --local generate ssh --name "$key"
  fingerprint="$(grep -o 'SHA256:[A-Za-z0-9+/]*' "$LOG" | tail -n 1)"
  [[ -n "$fingerprint" ]] || step_fail "$step" 'the generated key printed no fingerprint'
  step_cw "$step" credentials --local --profile "$name" set ssh "$key"
  step_cw "$step" update --local "$name" --profile "local:$name" --yes
  state="$(vm_state "$name")"
  [[ "$state" == running ]] || step_fail "$step" "after the update the VM is ${state:-missing}, not running"
  agent_holds "$step" "$name" "$fingerprint"
  [[ -z "$(role_pids_of "$PREVIOUS_CW" __local-credential-authority)" ]] ||
    step_fail "$step" "the previous release's credential service still runs"
  printf 'ok %s\n' "$step"
}

main() {
  local -a arguments=("$@")
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cw) [[ $# -ge 2 && -z "$CW" ]] || { usage; exit 2; }; CW="$2"; shift 2 ;;
      --cw-sha256) [[ $# -ge 2 && -z "$CW_SHA256" ]] || { usage; exit 2; }; CW_SHA256="$2"; shift 2 ;;
      --runtime-from) [[ $# -ge 2 && -z "$RUNTIME_FROM" ]] || { usage; exit 2; }; RUNTIME_FROM="$2"; shift 2 ;;
      --scratch) [[ $# -ge 2 && -z "$SCRATCH" ]] || { usage; exit 2; }; SCRATCH="$2"; shift 2 ;;
      --previous-cw) [[ $# -ge 2 && -z "$PREVIOUS_CW" ]] || { usage; exit 2; }; PREVIOUS_CW="$2"; shift 2 ;;
      --previous-cw-sha256)
        [[ $# -ge 2 && -z "$PREVIOUS_CW_SHA256" ]] || { usage; exit 2; }
        PREVIOUS_CW_SHA256="$2"
        shift 2
        ;;
      -h | --help) usage; exit 0 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ "$CW" == /* && -f "$CW" && -x "$CW" ]] || die '--cw must be an absolute path to an executable cw'
  [[ "$SCRATCH" == /* && -d "$SCRATCH" && ! -L "$SCRATCH" ]] || die '--scratch must be an existing absolute directory'
  [[ -z "$RUNTIME_FROM" || ( "$RUNTIME_FROM" == /* && -d "$RUNTIME_FROM" ) ]] ||
    die '--runtime-from must be an existing absolute directory'
  [[ -z "$CW_SHA256" ]] || smoke_require_sha256 "$CW" "$CW_SHA256"
  [[ -z "$PREVIOUS_CW" || ( "$PREVIOUS_CW" == /* && -f "$PREVIOUS_CW" && -x "$PREVIOUS_CW" ) ]] ||
    die '--previous-cw must be an absolute path to an executable cw'
  [[ -n "$PREVIOUS_CW" || -z "$PREVIOUS_CW_SHA256" ]] || die '--previous-cw-sha256 needs --previous-cw'
  [[ -z "$PREVIOUS_CW_SHA256" ]] || smoke_require_sha256 "$PREVIOUS_CW" "$PREVIOUS_CW_SHA256"

  smoke_run_in_scope lcreds -- "$0" "${arguments[@]}"
  SMOKE_DIR="$(mktemp -d "$SCRATCH/smoke-local-credentials.XXXXXX")"
  LOG="$SMOKE_DIR/cw.log"
  trap cleanup EXIT
  smoke_isolation_begin "$SMOKE_DIR"
  if [[ -n "$RUNTIME_FROM" ]]; then
    step_cw setup setup --local --from "$RUNTIME_FROM"
  fi
  if [[ -n "$PREVIOUS_CW" ]]; then
    step_upgrade_authority_left
    return
  fi
  # First: it decides the resolver the credential service starts with.
  step_provider_unresolved
  step_profile_after_create
  step_attach_restart
  step_proxy_down
}

# Sourced by its tests, run otherwise.
[[ "${BASH_SOURCE[0]}" != "$0" ]] || main "$@"
