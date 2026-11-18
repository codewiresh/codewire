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

Runs the journey steps that need only the cw under test:
  smoke-provider-unresolved
  smoke-profile-after-create
  smoke-attach-restart
--cw-sha256 checks a downloaded release before it runs. --runtime-from
installs the local VM runtime from a release directory (for a cw built from
source, which pins none); without it, the first create downloads the runtime
this cw pins. --scratch is an existing directory for the smoke's private
roots, removed after.
USAGE
}

CW=''
CW_SHA256=''
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
  step_cw "$step" exec --in "$name" -- ssh-add -l
  grep -qF "$fingerprint" "$LOG" || step_fail "$step" "the guest's agent does not hold $fingerprint"
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

main() {
  local -a arguments=("$@")
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cw) [[ $# -ge 2 && -z "$CW" ]] || { usage; exit 2; }; CW="$2"; shift 2 ;;
      --cw-sha256) [[ $# -ge 2 && -z "$CW_SHA256" ]] || { usage; exit 2; }; CW_SHA256="$2"; shift 2 ;;
      --runtime-from) [[ $# -ge 2 && -z "$RUNTIME_FROM" ]] || { usage; exit 2; }; RUNTIME_FROM="$2"; shift 2 ;;
      --scratch) [[ $# -ge 2 && -z "$SCRATCH" ]] || { usage; exit 2; }; SCRATCH="$2"; shift 2 ;;
      -h | --help) usage; exit 0 ;;
      *) usage; exit 2 ;;
    esac
  done
  [[ "$CW" == /* && -f "$CW" && -x "$CW" ]] || die '--cw must be an absolute path to an executable cw'
  [[ "$SCRATCH" == /* && -d "$SCRATCH" && ! -L "$SCRATCH" ]] || die '--scratch must be an existing absolute directory'
  [[ -z "$RUNTIME_FROM" || ( "$RUNTIME_FROM" == /* && -d "$RUNTIME_FROM" ) ]] ||
    die '--runtime-from must be an existing absolute directory'
  [[ -z "$CW_SHA256" ]] || smoke_require_sha256 "$CW" "$CW_SHA256"

  smoke_run_in_scope lcreds -- "$0" "${arguments[@]}"
  SMOKE_DIR="$(mktemp -d "$SCRATCH/smoke-local-credentials.XXXXXX")"
  LOG="$SMOKE_DIR/cw.log"
  trap cleanup EXIT
  smoke_isolation_begin "$SMOKE_DIR"
  if [[ -n "$RUNTIME_FROM" ]]; then
    step_cw setup setup --local --from "$RUNTIME_FROM"
  fi
  # First: it decides the resolver the credential service starts with.
  step_provider_unresolved
  step_profile_after_create
  step_attach_restart
}

# Sourced by its tests, run otherwise.
[[ "${BASH_SOURCE[0]}" != "$0" ]] || main "$@"
