#!/usr/bin/env bash
# The local VM credentials smoke, Part A (#5220): real cw binaries on a Linux
# host with KVM, driven through public commands only, in the isolation of
# scripts/ci/verify/lib/local-smoke-isolation.sh. Each step is a sub-feature of
# docs/journeys/local-vm-credentials-smoke.md and reports failures under its
# journey ID with cw's own words. The only credential is an SSH key cw
# generates into the smoke's private keyring; nothing contacts a provider.
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
  smoke-profile-after-create
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
  step_cw "$step" credentials --local --profile "$name" set ssh "$key"
  step_cw "$step" update --local "$name" --profile "local:$name" --yes
  state="$(vm_state "$name")"
  [[ "$state" == running ]] || step_fail "$step" "after the update the VM is ${state:-missing}, not running"
  step_cw "$step" exec --in "$name" -- ssh-add -l
  grep -qF "$fingerprint" "$LOG" || step_fail "$step" "the guest's agent does not hold $fingerprint"
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
  step_profile_after_create
}

# Sourced by its tests, run otherwise.
[[ "${BASH_SOURCE[0]}" != "$0" ]] || main "$@"
