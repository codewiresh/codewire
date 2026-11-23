#!/usr/bin/env bash
# Make sure Dev acceptance's continuity Sandbox exists and runs (#6095).
#
# Dev acceptance reads this Sandbox's Pod before and after each delivery; a
# delivery that replaces it fails acceptance. It is a plain Sandbox in the
# smoke identity's organization, with no credential profile: the smoke key is
# organization-scoped and cannot make account-global credentials or
# profiles. It is still bound (Pod-scope), so the running bootstrap check
# covers it. It never stops when idle.
#
# Usage, inside deploy's acceptance container or by hand on Dev:
#   scripts/runtime/dev/with-dev-smoke-auth.sh -- \
#     scripts/runtime/dev/ensure-continuity-sandbox.sh NAME
#
# NAME comes from deploy's settings/dev.env, the one home of the name. Inputs:
# CODEWIRE_DEV_SMOKE_API_KEY (never printed), CODEWIRE_SERVER_URL (Dev only),
# CW_BIN (default cw) and TMPDIR.
#
# It creates or starts the Sandbox only when needed and never deletes,
# replaces or changes anything. A same-named Sandbox in another shape is
# refused. It prints one line: `[pod-continuity] ensure
# created|started|present`, or `[pod-continuity] ensure refused reason=REASON`
# or `[pod-continuity] ensure failed step=STEP`, with no names or IDs.
set -euo pipefail

readonly DEV_SERVER_URL=https://codewire-dev.sh

say() { printf '[pod-continuity] ensure %s\n' "$1"; }
refuse() { say "refused reason=$1"; exit 1; }
failed() { say "failed step=$1"; exit 1; }

[[ $# -eq 1 ]] || { printf 'usage: ensure-continuity-sandbox.sh NAME\n' >&2; exit 2; }
readonly name="$1"
[[ "$name" =~ ^[a-z][a-z0-9-]{0,47}$ ]] || refuse name
[[ "${CODEWIRE_SERVER_URL:-}" == "$DEV_SERVER_URL" ]] || refuse server
[[ "${CODEWIRE_DEV_SMOKE_API_KEY:-}" =~ ^cw_[0-9a-f]{64}$ ]] || refuse api-key
readonly cw="${CW_BIN:-cw}"
for command in jq timeout mktemp; do
  command -v "$command" >/dev/null 2>&1 || failed tools
done

umask 077
work="$(mktemp -d "${TMPDIR:-/tmp}/continuity-sandbox.XXXXXX")" || failed tools
trap 'rm -rf -- "$work"' EXIT
# Only this key signs cw in: no saved login, no local VM state.
export CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY"
unset CODEWIRE_DEV_SMOKE_API_KEY
export CW_CONFIG_DIR="$work/cw-config" CODEWIRE_NATIVE_STATE_ROOT="$work/native-v1"
mkdir -m 0700 "$CW_CONFIG_DIR"

# run STEP OUT ARG...: one bounded cw call; its output stays in this folder.
run() {
  local step="$1" out="$2"
  shift 2
  timeout 120 "$cw" "$@" </dev/null >"$out" 2>"$work/$step.err" || failed "$step"
}

# named FILE OUT: the one object named NAME in the JSON array FILE, written to
# OUT, which stays empty when there is none. Several, or no array, refuse.
named() {
  jq -c --arg name "$name" '
    if type != "array" then error("not an array") else . end |
    [.[] | select(.name == $name)] |
    if length > 1 then error("ambiguous") elif length == 1 then .[0] else empty end
  ' "$1" >"$2" 2>/dev/null
}

uuid='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

# The running Sandbox, never stopped for being idle. --no-profile: the
# account's default profile is account-global, out of this key's reach.
run list-sandboxes "$work/sandboxes.json" --cloud ls --output json
named "$work/sandboxes.json" "$work/sandbox.json" || refuse sandbox-list
if [[ ! -s "$work/sandbox.json" ]]; then
  run create-sandbox "$work/created.json" --cloud create --no-file --no-profile \
    --name "$name" --image workspace \
    --cpu 2000m --memory 4096 --disk 10 --idle-stop off --no-network \
    --no-wait --yes --output json
  jq -e --arg uuid "$uuid" '.id | type == "string" and test($uuid)' "$work/created.json" \
    >/dev/null 2>&1 || failed create-sandbox
  say created
  exit 0
fi
# The list entry has no idle stop or TTL; info has both.
run info-sandbox "$work/info.json" --cloud info "$name" --output json
jq -e --arg id "$(jq -r '.id' "$work/sandbox.json")" '
  .id == $id and .type == "sandbox" and .idle_stop_seconds == 0 and .ttl_seconds == null
' "$work/info.json" >/dev/null 2>&1 || refuse sandbox
case "$(jq -r '.state' "$work/info.json")" in
  stopped)
    run start-sandbox "$work/started.out" --cloud start "$name" --output json
    say started
    ;;
  running | pending | pending_build | building | creating | starting | pulling_snapshot | restoring | resizing)
    say present
    ;;
  *) refuse sandbox-state ;;
esac
