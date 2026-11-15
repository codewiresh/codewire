#!/usr/bin/env bash
# Record the README's two walks and render each as an animated SVG:
#
# - the platform walk ("Five minutes on the platform"), on Dev as the e2e
#   account (infra docs/test-identities.md, "Dev browser acceptance"), into
#   docs/assets/readme-walkthrough.svg. The account signs in through
#   `cw login`'s device sign-in, approved with its password and second factor
#   from OpenBao, as scripts/runtime/dev/invitations-journey.sh approves the
#   invitee's. No secret value is printed or written outside a private folder.
# - with --local, the local VM walk ("On your own machine"), in a VM on this
#   machine with its own state root, into docs/assets/readme-walkthrough-local.svg.
#
# Everything a walk creates is removed afterwards, except the e2e account's
# credential profile `me`: the first profile becomes the account's default,
# and a default can't be deleted (#3550). It is left with no identity in it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SERVER="https://codewire-dev.sh"
readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly IDENTITY_PATH="apps/codewire/dev/ci-browser-auth"
readonly IDENTITY_EMAIL="e2e@codewire.sh"
CW_BIN="${CW_BIN:-cw}"
MODE=platform
OUTPUT=""
KEEP_TRANSCRIPT=""
WORK=""
LOGIN_PID=""
SIGNED_IN=false
LOCAL_VM=false

usage() {
  cat <<'USAGE'
Usage:
  scripts/docs/record-readme-walkthrough.sh [--local] [--output FILE] [--transcript FILE]

Without --local, signs in to Dev as the e2e account, runs the README's
platform walk (sign in, an SSH key in a credential profile, a personal secret,
a sandbox that uses both, a server opened through a preview URL, stop and
remove), cleans up, signs out, and writes docs/assets/readme-walkthrough.svg.

With --local, runs the README's local VM walk (install the runtime, a VM with
a project folder mounted, a server opened on 127.0.0.1, remove) with a state
root of its own, and writes docs/assets/readme-walkthrough-local.svg. It
downloads the VM runtime and the workspace image under TMPDIR, and needs KVM
and a free port 3000.

--output FILE writes the recording there instead. --transcript FILE also
keeps the run's raw transcript, so scripts/docs/render-terminal-svg.py can
render it again without another run; it holds the run's unredacted output, so
keep it out of the repository. CW_BIN names the cw to record; the default is
the cw on PATH.
USAGE
}

log() { printf '[readme-recording] %s\n' "$*" >&2; }
die() { printf '[readme-recording] FAIL: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local) MODE=local; shift ;;
    --output) [[ $# -ge 2 ]] || die '--output needs a file'; OUTPUT="$2"; shift 2 ;;
    --transcript) [[ $# -ge 2 ]] || die '--transcript needs a file'; KEEP_TRANSCRIPT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
for tool in jq curl python3 "$CW_BIN"; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
if [[ -z "$OUTPUT" ]]; then
  OUTPUT="$ROOT/docs/assets/readme-walkthrough.svg"
  [[ "$MODE" == platform ]] || OUTPUT="$ROOT/docs/assets/readme-walkthrough-local.svg"
fi

cw_as() {
  HOME="$WORK/home" PATH="$WORK/bin:$PATH" CODEWIRE_NATIVE_STATE_ROOT="$WORK/local-state" \
    CODEWIRE_SERVER_URL="$SERVER" NO_COLOR=1 "$CW_BIN" "$@"
}

# The account's web session, which approves cw login's device code.
web() { curl -sS --max-time 30 -c "$WORK/cookies" -b "$WORK/cookies" -H "Origin: $SERVER" "$@"; }

# Signs the web session out and confirms Dev no longer knows it. Sign-out
# always answers 200, so the check asks for the session with the old cookie.
end_web_session() {
  [[ -s "$WORK/cookies" ]] || return 0
  cp -- "$WORK/cookies" "$WORK/cookies.before"
  web -o /dev/null -X POST "$SERVER/api/auth/sign-out" || true
  local session
  session="$(curl -sS --max-time 30 -b "$WORK/cookies.before" "$SERVER/api/auth/get-session" || true)"
  shred -u -- "$WORK/cookies" "$WORK/cookies.before"
  [[ "$session" == null ]]
}

# A backstop after `cw --local rm`, for what a failed walk leaves running. It
# stops only processes started with this run's own state root, so it never
# touches another session's VMs.
stop_local_processes() {
  local pid marker="CODEWIRE_NATIVE_STATE_ROOT=$WORK/local-state"
  local -a pids=()
  for pid in $(pgrep -u "$(id -u)" .); do
    { tr '\0' '\n' <"/proc/$pid/environ"; } 2>/dev/null | grep -qxF "$marker" && pids+=("$pid")
  done
  [[ ${#pids[@]} -gt 0 ]] || return 0
  log "stopping this run's local VM processes: ${pids[*]}"
  kill -TERM "${pids[@]}" 2>/dev/null || true
  for _ in $(seq 1 30); do
    kill -0 "${pids[@]}" 2>/dev/null || return 0
    sleep 1
  done
  log "still running after 30 s: ${pids[*]}"
}

cleanup() {
  local status=$?
  [[ -z "$LOGIN_PID" ]] || kill "$LOGIN_PID" 2>/dev/null || true
  [[ -z "$WORK" ]] || end_web_session || log 'the web session was not confirmed signed out; it expires on its own'
  # A failed walk keeps its transcript, so the failing step's output can be read.
  if [[ "$status" != 0 && -n "$KEEP_TRANSCRIPT" && -s "${TRANSCRIPT:-}" ]]; then
    cp -- "$TRANSCRIPT" "$KEEP_TRANSCRIPT" && log "the transcript so far is in $KEEP_TRANSCRIPT"
  fi
  if [[ "$SIGNED_IN" == true ]]; then
    cw_as rm hello --yes >/dev/null 2>&1 || true
    cw_as credentials --cloud --profile me unset ssh >/dev/null 2>&1 || true
    cw_as credentials --cloud revoke my-key >/dev/null 2>&1 || true
    cw_as credentials --cloud delete my-key --yes >/dev/null 2>&1 || true
    cw_as secrets --cloud --user delete GREETING >/dev/null 2>&1 || true
    cw_as logout >/dev/null 2>&1 || log 'cw logout failed; the sign-in expires on its own'
  fi
  if [[ "$LOCAL_VM" == true ]]; then
    cw_as --local rm hello --yes >/dev/null 2>&1 || true
    stop_local_processes
  fi
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    # Every file but the local VM's state, which holds no sign-in and is large.
    find "$WORK" -path "$WORK/local-state" -prune -o -type f -exec shred -u {} + 2>/dev/null || true
    chmod -R u+w "$WORK" 2>/dev/null || true
    rm -rf -- "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cw-readme-recording.XXXXXX")"
chmod 0700 "$WORK"
mkdir -m 0700 "$WORK/home" "$WORK/bin" "$WORK/bao"
# The project folder sits in the walk's HOME, so cw shows it as ~/hello.
PROJECT="$WORK/home/hello"
mkdir -m 0700 "$PROJECT"
# cw login opens a browser; nothing here should.
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/xdg-open"
chmod 0700 "$WORK/bin/xdg-open"

# Each step's command and its output, with the time each line arrived.
TRANSCRIPT="$WORK/transcript.jsonl"
: >"$TRANSCRIPT"
step() {
  local shown="$1"; shift
  log "$shown"
  python3 -I -c 'import json, sys, time; print(json.dumps({"t": time.time(), "cmd": sys.argv[1]}))' \
    "$shown" >>"$TRANSCRIPT"
  ( cd "$PROJECT" && "$@" 2>&1 ) | python3 -I -u -c '
import json, sys, time
for line in sys.stdin:
    print(json.dumps({"t": time.time(), "out": line.rstrip("\n")}), flush=True)
' >>"$TRANSCRIPT"
}

render() {
  [[ -z "$KEEP_TRANSCRIPT" ]] || cp -- "$TRANSCRIPT" "$KEEP_TRANSCRIPT"
  python3 -I "$ROOT/scripts/docs/render-terminal-svg.py" "$@" "$TRANSCRIPT" "$OUTPUT"
  log "wrote $OUTPUT"
}

sign_in() {
  # The account's sign-in, read once through the workstation access client.
  # shellcheck source=scripts/runtime/dev/openbao-access-token.sh
  source "$ROOT/scripts/runtime/dev/openbao-access-token.sh"
  openbao_access_admit || die 'the workstation access client is not available'
  openbao_access_acquire "$WORK/bao" || die 'no OpenBao token from the access client'
  openbao_access_kv_get "$WORK/bao" "$OPENBAO_ADDR" "$IDENTITY_PATH" "$WORK/identity.json" "$WORK/bao.err" ||
    die "cannot read $IDENTITY_PATH"
  openbao_access_revoke "$WORK/bao" "$OPENBAO_ADDR" || die 'the OpenBao token was not confirmed revoked'
  jq -e --arg email "$IDENTITY_EMAIL" \
    '.data.data | .email == $email and (.password | type == "string") and (.totpSecret | type == "string")' \
    "$WORK/identity.json" >/dev/null || die "$IDENTITY_PATH is not the e2e account's sign-in"
  jq '{email: .data.data.email, password: .data.data.password}' "$WORK/identity.json" >"$WORK/sign-in.json"
  jq -r '.data.data.totpSecret' "$WORK/identity.json" >"$WORK/totp-secret"
  shred -u -- "$WORK/identity.json"

  # Device sign-in: cw login waits for its code, which the account's own
  # password and second-factor session approves.
  step 'cw login' cw_as login </dev/null &
  LOGIN_PID=$!
  local code="" status csrf i login_status=0
  for _ in $(seq 1 30); do
    code="$(jq -r 'select(.out) | .out' "$TRANSCRIPT" | sed -n 's/^Your code: //p' | tr -d -- '-[:space:]')"
    [[ -z "$code" ]] || break
    sleep 1
  done
  [[ "$code" =~ ^[A-Z0-9]{8}$ ]] || die 'cw login printed no device code'
  status="$(web -o "$WORK/sign-in.out" -w '%{http_code}' -H 'Content-Type: application/json' \
    --data "@$WORK/sign-in.json" "$SERVER/api/auth/sign-in")"
  shred -u -- "$WORK/sign-in.json"
  [[ "$status" == 200 ]] || die "the sign-in answered HTTP $status"
  jq -e '.twoFactorRequired == true and (.twoFactorToken | type == "string")' "$WORK/sign-in.out" >/dev/null ||
    die 'the sign-in asked for no second factor'
  python3 -I - "$WORK/totp-secret" "$WORK/sign-in.out" >"$WORK/two-factor.json" <<'PY'
import base64, hashlib, hmac, json, struct, sys, time
secret = open(sys.argv[1]).read().strip().upper()
key = base64.b32decode(secret + "=" * (-len(secret) % 8))
digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
offset = digest[-1] & 15
code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
token = json.load(open(sys.argv[2]))["twoFactorToken"]
json.dump({"code": f"{code:06d}", "token": token}, sys.stdout)
PY
  shred -u -- "$WORK/totp-secret" "$WORK/sign-in.out"
  status="$(web -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    --data "@$WORK/two-factor.json" "$SERVER/api/auth/two-factor/validate")"
  shred -u -- "$WORK/two-factor.json"
  [[ "$status" == 200 ]] || die "the second factor answered HTTP $status"
  web -o "$WORK/device.html" "$SERVER/device?user_code=$code"
  csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$WORK/device.html" | head -1)"
  [[ -n "$csrf" ]] || die 'the device page had no form'
  local -a form=(--data-urlencode "_csrf=$csrf")
  for i in 1 2 3 4 5 6 7 8; do form+=(--data-urlencode "user_code_$i=${code:i-1:1}"); done
  web -o /dev/null "${form[@]}" "$SERVER/device/_actions/approve"
  shred -u -- "$WORK/device.html"
  end_web_session || die 'the web session was not confirmed signed out'
  wait "$LOGIN_PID" || login_status=$?
  LOGIN_PID=""
  [[ "$login_status" == 0 ]] || die "cw login exited $login_status"
  SIGNED_IN=true
  cw_as whoami | grep -qF "($IDENTITY_EMAIL)" || die "cw is not signed in as $IDENTITY_EMAIL"
  log "signed in as $IDENTITY_EMAIL"
}

platform_walk() {
  sign_in
  # The walk's names must be free, so the recording shows a first run.
  cw_as ls 2>&1 | grep -qE '^[[:space:]]*›?[[:space:]]*hello[[:space:]]' && die 'an environment named hello exists'
  cw_as credentials --cloud list 2>&1 | grep -qF '"my-key"' && die 'a credential named my-key exists'
  cw_as secrets --cloud --user list 2>&1 | grep -qE '^GREETING[[:space:]]' && die 'a personal secret GREETING exists'

  step 'cw credentials --cloud generate ssh --name my-key' \
    cw_as credentials --cloud generate ssh --name my-key
  step 'cw credentials --cloud --profile me set ssh my-key' \
    cw_as credentials --cloud --profile me set ssh my-key
  set_greeting() { echo hello | cw_as secrets --cloud --user set GREETING; }
  step 'echo hello | cw secrets --cloud --user set GREETING' set_greeting
  step 'cw create --name hello --image workspace --user-secrets platform --yes' \
    cw_as create --name hello --image workspace --user-secrets platform --yes
  # shellcheck disable=SC2016 # $GREETING expands inside the sandbox.
  step "cw exec --in hello -- sh -c 'echo \"\$GREETING\"'" \
    cw_as exec --in hello -- sh -c 'echo "$GREETING"'
  step 'cw run --in hello --name web --detach -- python3 -m http.server 3000' \
    cw_as run --in hello --name web --detach -- python3 -m http.server 3000
  step 'cw ports hello --publish 3000 --label web' \
    cw_as ports hello --publish 3000 --label web
  step 'cw stop hello' cw_as stop hello
  step 'cw rm hello --yes' cw_as rm hello --yes

  # The Dev preview domain stays out of the public tree.
  local preview_domain
  preview_domain="$(jq -r 'select(.out) | .out' "$TRANSCRIPT" |
    sed -n 's#.*URL: https://[^.]*\.\([^/[:space:]]*\).*#\1#p' | head -1)"
  [[ -n "$preview_domain" ]] || die 'cw ports printed no preview URL'
  # So are the account's IDs: its organization, its credential and its profile.
  local uuid='[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}'
  local organization credential profile
  organization="$(jq -r 'select(.out) | .out' "$TRANSCRIPT" | sed -n 's/.*organization "\([0-9a-f]\{32\}\)".*/\1/p' | head -1)"
  credential="$(jq -r 'select(.out) | .out' "$TRANSCRIPT" | sed -n "s/^\\($uuid\\) .*\"my-key\".*/\\1/p" | head -1)"
  profile="$(jq -r 'select(.out) | .out' "$TRANSCRIPT" | sed -n "s/^\\($uuid\\)[[:space:]].*platform:user\\/me.*/\\1/p" | head -1)"
  [[ -n "$organization" && -n "$credential" && -n "$profile" ]] || die 'the walk printed no organization, credential or profile ID'
  render --replace "$preview_domain={preview domain}" --replace "$organization={org id}" \
    --replace "$credential={credential id}" --replace "$profile={profile id}" \
    --title 'cw: five minutes on the platform'
  ! grep -qE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32}' "$OUTPUT" ||
    die "$OUTPUT still shows an ID"
}

local_walk() {
  [[ -r /dev/kvm && -w /dev/kvm ]] || die 'a local VM needs read and write access to /dev/kvm'
  [[ -z "$(ss -Hltn '( sport = :3000 )')" ]] || die 'port 3000 is in use on this machine'
  mkdir -m 0700 "$WORK/local-state"
  printf '<h1>Hello from a VM</h1>\n' >"$PROJECT/index.html"
  LOCAL_VM=true

  step 'cw setup --local' cw_as setup --local
  step 'cw create --local --name hello --path . --yes' \
    cw_as create --local --name hello --path . --yes
  step 'cw run --in hello --name web --detach -- python3 -m http.server 3000' \
    cw_as run --in hello --name web --detach -- python3 -m http.server 3000
  step 'cw ports hello --publish 3000' cw_as ports hello --publish 3000
  # The server takes a moment to start. Wait for it unrecorded, so the
  # recording shows one curl, as a reader running the walk by hand would.
  local _
  for _ in $(seq 1 10); do curl -sf --max-time 5 -o /dev/null http://127.0.0.1:3000/ && break; sleep 1; done
  step 'curl http://127.0.0.1:3000/' curl -sS --max-time 5 http://127.0.0.1:3000/
  step 'cw rm hello --yes' cw_as rm hello --yes
  grep -qF '"out": "<h1>Hello from a VM</h1>"' "$TRANSCRIPT" || die 'the server in the VM did not answer'
  render --title 'cw: a VM on your own machine'
}

if [[ "$MODE" == platform ]]; then platform_walk; else local_walk; fi
