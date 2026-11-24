#!/usr/bin/env bash
# Run one command signed in to Dev as the synthetic personal-walk identity
# (provision-dev-personal-walk-user.sh, #6074), through a fresh `cw login` in
# a private cw config folder on tmpfs. The device code is approved here with a
# password session, as invitations-journey.sh approves the invitee's. The
# command then acts with that cw sign-in, an account credential, so it can add
# personal credentials and profiles, which no API key may do.
#
# Dev only, synthetic only. A real provider key on this account is an
# incident: revoke it at the provider and delete it here by id.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly DEV_ORIGIN="https://codewire-dev.sh"
readonly SERVER="${CODEWIRE_SERVER_URL:-$DEV_ORIGIN}"
readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly OPENBAO_PATH="apps/codewire/dev/ci-personal-walk"
readonly WALK_EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
# cw's OAuth client (crates/codewire-client/src/auth.rs), a public client: the
# token itself is the exact id the server revokes and introspects by.
readonly CLI_CLIENT_ID="codewire-cli"
CW_BIN="${CW_BIN:-$ROOT/target/debug/cw}"

WORK=""
PRIVATE=""
CONFIG=""
LOGIN_PID=""
SIGNED_IN=false
# Browser sessions for a walk that drives the dashboard (--browser-sessions):
# each sign-in's cookie jar, kept to sign it out, and the storage-state file
# COMMAND gets.
BROWSER_SESSIONS=0
BROWSER_JARS=()
BROWSER_STATES=()

usage() {
  cat <<'USAGE'
Usage:
  CW_BIN=/path/to/cw scripts/runtime/dev/with-dev-personal-walk.sh [--document-stdin] [--browser-sessions N] [--] COMMAND [ARGS...]

The flags may come in either order, each at most once.

Dev only. Runs COMMAND signed in to https://codewire-dev.sh as the synthetic
personal-walk identity (success+codewire-dev-personal-walk@simulator.amazonses.com),
whose password is in the OpenBao document apps/codewire/dev/ci-personal-walk
(provision-dev-personal-walk-user.sh creates and rotates it).

  - The document is read once with a short-lived token from the workstation
    access client, which is revoked before anything else runs. With
    --document-stdin it is instead OpenBao's KV read response for that path,
    on stdin, as a CI step that read it with its own role pipes it (#6302):
    no bao and no access client, the same shape check, and COMMAND gets no
    stdin.
  - A fresh cw config folder is made under $XDG_RUNTIME_DIR (tmpfs, 0700).
    `cw login` signs in there by device sign-in, and this script approves the
    code with a password session read from a 0600 file that is removed
    straight after. The password is never on argv, in an environment or in
    output, and the browser session is signed out once the code is approved.
  - COMMAND runs with CW_CONFIG_DIR naming that folder, CODEWIRE_SERVER_URL,
    CW_BIN and EXPECTED_PERSONAL_WALK_USER_EMAIL set, and none of the caller's
    cw or OpenBao environment.
  - With --browser-sessions N (exactly 1 or 2), it also makes N password
    sessions for a browser, before the document is removed, and checks that
    each is this identity's before skipping its second-factor setup. Each
    session's cookie goes into a Playwright storage-state file, 0600 in the
    private folder, and COMMAND gets the paths in
    PERSONAL_WALK_BROWSER_STORAGE_STATES, separated by colons. The browser
    never sees the password. COMMAND may overwrite a file with its context's
    final state and keeps no other copy: no trace, screenshot or saved
    session. Each session's id, never its token, is logged when it is made.
  - Afterwards, whether COMMAND passed or not, `cw logout` runs, and the
    server is asked whether each token of the walk's CLI sign-in is still
    active. One that is gets revoked by its exact token, and the run fails if
    any stays active. Every browser session token the helper made or finds in
    the storage-state files is signed out, and the run fails if the server
    still knows one or a file can't be read. The folder is then removed.

Synthetic only: give this account synthetic, canary-marked provider
credentials, never a real one. A real provider key found on it is an
incident: revoke it at the provider and delete it here by id.
USAGE
}

log() { printf '[personal-walk-auth] %s\n' "$*" >&2; }
die() { printf '[personal-walk-auth] ERROR: %s\n' "$*" >&2; exit 1; }

secure_remove() {
  [[ "$#" -gt 0 ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u -- "$@" 2>/dev/null && return 0
  fi
  rm -f -- "$@" 2>/dev/null
}

# introspect FILE HINT: whether the token in FILE is active, from the server.
introspect() {
  local answer
  answer="$(curl -sS --max-time 30 \
    --data-urlencode "client_id=$CLI_CLIENT_ID" --data-urlencode "token_type_hint=$2" \
    --data-urlencode "token@$1" "$SERVER/api/oauth/introspect")" || return 2
  jq -er 'if .active == true then "active" elif .active == false then "inactive"
    else error("no active field") end' <<<"$answer" 2>/dev/null || return 2
}

# revoke_token FILE HINT: revoke the token in FILE by itself (RFC 7009).
revoke_token() {
  local status
  status="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' \
    --data-urlencode "client_id=$CLI_CLIENT_ID" --data-urlencode "token_type_hint=$2" \
    --data-urlencode "token@$1" "$SERVER/api/oauth/revoke")" || return 1
  [[ "$status" == 200 ]]
}

# snapshot_grant NAME: keep the sign-in's current token pair, so that it can
# be checked on the server after `cw logout`, which deletes the local copy.
snapshot_grant() {
  [[ -f "$CONFIG/credentials.json" ]] || return 0
  jq -e '(.access_token | type == "string" and length > 0) and
    (.refresh_token | type == "string" and length > 0)' "$CONFIG/credentials.json" >/dev/null ||
    return 1
  jq -j '.access_token' "$CONFIG/credentials.json" >"$PRIVATE/$1.access"
  jq -j '.refresh_token' "$CONFIG/credentials.json" >"$PRIVATE/$1.refresh"
}

# end_sign_in: log out, then confirm on the server that no token of the
# walk's CLI sign-in is still active, revoking any that is by its exact token.
end_sign_in() {
  local status=0 logout=not_needed file hint state revoked=0
  if [[ -n "$LOGIN_PID" ]]; then
    kill "$LOGIN_PID" 2>/dev/null || true
    wait "$LOGIN_PID" 2>/dev/null || true
    LOGIN_PID=""
  fi
  if [[ -s "$PRIVATE/cookies" ]]; then
    curl -sS --max-time 30 -o /dev/null -b "$PRIVATE/cookies" -H "Origin: $SERVER" \
      -X POST "$SERVER/api/auth/sign-out" || log 'signing the approval session out failed'
  fi
  if [[ -f "$CONFIG/credentials.json" ]]; then
    snapshot_grant final || { log 'the saved cw sign-in has an unexpected shape'; status=1; }
    if timeout --kill-after=5s 60s "$CW_BIN" --server "$SERVER" logout \
        </dev/null >"$PRIVATE/logout.out" 2>&1; then
      logout=confirmed
    else
      logout=unconfirmed
      log 'cw logout did not confirm that the server ended the sign-in'
    fi
  fi
  # The server revokes a token only by the token itself and lists no CLI
  # grants, so a token from a refresh between login and logout could never be
  # checked. CLI access tokens last 720 hours and a walk takes minutes, so a
  # changed access token means an unexpected refresh: fail, and let the
  # provisioner's rotation revoke every CLI token of the account by id.
  if [[ -s "$PRIVATE/login.access" && -s "$PRIVATE/final.access" ]] &&
      ! cmp -s "$PRIVATE/login.access" "$PRIVATE/final.access"; then
    log 'the CLI sign-in refreshed during the walk; rotate the identity with provision-dev-personal-walk-user.sh to revoke every CLI token'
    status=1
  fi
  for file in "$PRIVATE"/login.access "$PRIVATE"/login.refresh \
      "$PRIVATE"/final.access "$PRIVATE"/final.refresh; do
    [[ -s "$file" ]] || continue
    case "$file" in *.access) hint=access_token ;; *) hint=refresh_token ;; esac
    state="$(introspect "$file" "$hint")" || { log "the server did not answer for a $hint"; status=1; continue; }
    if [[ "$state" == active ]]; then
      if revoke_token "$file" "$hint" && state="$(introspect "$file" "$hint")" &&
          [[ "$state" == inactive ]]; then
        revoked=$((revoked + 1))
      else
        log "a $hint of the walk's CLI sign-in is still active on the server"
        status=1
      fi
    fi
  done
  if [[ "$SIGNED_IN" == true ]]; then
    if [[ "$status" == 0 ]]; then
      log "PASS cli_sign_in_ended=true logout=$logout revoked_by_token=$revoked secret_values_printed=false"
    else
      log "FAIL cli_sign_in_ended=false logout=$logout; check the account's CLI sign-ins"
    fi
  fi
  return "$status"
}

# session_lines FILE: the cookie line of every Dev session token in a
# Playwright storage state, one per line, as a curl cookie jar reads it.
session_lines() {
  jq -er --arg host "${SERVER#https://}" '
    (.cookies | if type == "array" then . else error("no cookies") end)[]
    | select(.name == "codewire.session_token" and (.domain == $host or .domain == "." + $host))
    | (.value | if type == "string" and test("^[^\\t\\n\\r ;]+$") then . else error("bad value") end)
    | "\($host)\tFALSE\t/\tTRUE\t0\tcodewire.session_token\t\(.)"
  ' "$1"
}

# jar_lines FILE: the same lines from a curl cookie jar.
jar_lines() {
  jq -Rr --arg host "${SERVER#https://}" '
    split("\t")
    | select(length == 7 and (.[0] == $host or .[0] == "#HttpOnly_" + $host)
      and .[5] == "codewire.session_token" and (.[6] | test("^[^\\t\\n\\r ;]+$")))
    | "\($host)\tFALSE\t/\tTRUE\t0\tcodewire.session_token\t\(.[6])"
  ' <"$1"
}

# browser_session I: one more password session, for the browser. The password
# goes from the 0600 document to curl through a pipe, as the approval
# session's does, and the cookie stays in files: no token is on argv or in
# an environment.
browser_session() {
  local jar="$PRIVATE/browser-$1.jar" state="$WORK/browser/state-$1.json" status session id
  status="$(jq '{email: .data.data.userEmail, password: .data.data.password}' "$DOCUMENT" |
    curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -c "$jar" \
      -H 'Content-Type: application/json' --data @- "$SERVER/api/auth/sign-in")" || status=unreachable
  # Kept at once, so that a session this function gives up on is still
  # signed out.
  [[ ! -e "$jar" ]] || BROWSER_JARS+=("$jar")
  [[ "$status" == 200 ]] || die "browser session $1: the password sign-in answered HTTP $status"
  session="$(curl -sS --max-time 30 -b "$jar" "$SERVER/api/auth/get-session")" ||
    die "browser session $1: cannot confirm whose it is"
  # Second-factor setup is skipped only for this synthetic identity.
  id="$(jq -er --arg email "$WALK_EMAIL" \
    'select(.user.email == $email) | .session.id | select(type == "string" and length > 0)' \
    <<<"$session" 2>/dev/null)" || die "browser session $1 is not the personal-walk identity's"
  log "browser session $1: id $id"
  status="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -b "$jar" -c "$jar" \
    -H 'Content-Type: application/json' -H "Origin: $SERVER" --data '{}' \
    "$SERVER/api/auth/two-factor/skip-setup")" || status=unreachable
  [[ "$status" == 200 ]] || die "browser session $1: skipping second-factor setup answered HTTP $status"
  jq -Rn --arg host "${SERVER#https://}" '{cookies: [inputs | split("\t")
      | select(length == 7 and (.[0] == $host or .[0] == "#HttpOnly_" + $host)
        and .[5] == "codewire.session_token")
      | {name: .[5], value: .[6], domain: $host, path: "/",
         expires: (if .[4] == "0" then -1 else (.[4] | tonumber) end),
         httpOnly: true, secure: true, sameSite: "Lax"}], origins: []}
    | if (.cookies | length) == 1 then . else error("not one session cookie") end' \
    <"$jar" >"$state" 2>/dev/null || die "browser session $1: the sign-in set no single session cookie"
  BROWSER_STATES+=("$state")
  session_lines "$state" >/dev/null 2>&1 || die "browser session $1: its storage state can't be read"
}

# end_browser_sessions: sign out every session token the helper made or finds
# in the storage-state files, each from a 0600 cookie jar, and fail if the
# server still knows one or a file can't be read.
end_browser_sessions() {
  local status=0 state file line n=0 ended=0 session id
  [[ "$BROWSER_SESSIONS" -gt 0 ]] || return 0
  : >"$PRIVATE/browser-tokens"
  for file in "${BROWSER_JARS[@]}"; do
    jar_lines "$file" >>"$PRIVATE/browser-tokens" 2>/dev/null ||
      { log "a browser cookie jar can't be read"; status=1; }
  done
  for state in "${BROWSER_STATES[@]}"; do
    [[ -e "$state" ]] || continue
    session_lines "$state" >>"$PRIVATE/browser-tokens" 2>/dev/null ||
      { log "a browser storage-state file can't be read: $(basename "$state")"; status=1; }
  done
  sort -u -o "$PRIVATE/browser-tokens" "$PRIVATE/browser-tokens"
  while IFS= read -r line; do
    n=$((n + 1))
    file="$PRIVATE/sign-out-$n.jar"
    printf '%s\n' "$line" >"$file"
    curl -sS --max-time 30 -o /dev/null -b "$file" -H "Origin: $SERVER" \
      -X POST "$SERVER/api/auth/sign-out" || true
    if session="$(curl -sS --max-time 30 -b "$file" "$SERVER/api/auth/get-session")" &&
        [[ "$session" == null ]]; then
      ended=$((ended + 1))
    else
      id="$(jq -r '.session.id // "unknown"' <<<"$session" 2>/dev/null)" || id=unknown
      log "browser session $id is still signed in; revoke it by id"
      status=1
    fi
  done <"$PRIVATE/browser-tokens"
  if [[ "$status" == 0 ]]; then
    log "PASS browser_sessions_ended=$ended secret_values_printed=false"
  else
    log "FAIL browser_sessions_ended=$ended; check the account's sessions"
  fi
  return "$status"
}

remove_work() {
  local status=0
  [[ -n "$WORK" && -d "$WORK" ]] || return 0
  while IFS= read -r -d '' file; do secure_remove "$file" || status=1; done \
    < <(find "$WORK" -type f -print0)
  rm -rf -- "$WORK" || status=1
  [[ ! -e "$WORK" ]] || status=1
  WORK=""
  return "$status"
}

finish() {
  local status="$1"
  trap - EXIT HUP INT TERM
  if [[ -n "$PRIVATE" && -d "$PRIVATE" ]]; then
    if [[ "$DOCUMENT_STDIN" == false ]]; then
      openbao_access_cleanup "$PRIVATE/bao" "$OPENBAO_ADDR" 2>/dev/null || status=$((status ? status : 1))
    fi
    end_sign_in || status=$((status ? status : 1))
    end_browser_sessions || status=$((status ? status : 1))
  fi
  remove_work || { log 'the private folder was not removed'; status=$((status ? status : 1)); }
  exit "$status"
}

case "${1:-}" in -h|--help) usage; exit 0 ;; esac
case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
DOCUMENT_STDIN=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --document-stdin)
      [[ "$DOCUMENT_STDIN" == false ]] || die '--document-stdin is given twice'
      DOCUMENT_STDIN=true
      shift ;;
    --browser-sessions)
      [[ "$BROWSER_SESSIONS" == 0 ]] || die '--browser-sessions is given twice'
      [[ "${2:-}" =~ ^[12]$ ]] || die '--browser-sessions takes 1 or 2'
      BROWSER_SESSIONS="$2"
      shift 2 ;;
    *) break ;;
  esac
done
[[ "${1:-}" != '--' ]] || shift
[[ "$#" -gt 0 ]] || die 'name the command to run; see --help'
[[ "$SERVER" == "$DEV_ORIGIN" ]] ||
  die "this identity exists only on Dev; refusing server $SERVER"
required=(cmp curl find grep head jq mktemp rm sed shred stat timeout wc)
[[ "$DOCUMENT_STDIN" == true ]] || required+=(bao)
for command in "${required[@]}"; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ -x "$CW_BIN" ]] || die "Codewire CLI is unavailable: $CW_BIN (set CW_BIN)"
[[ "${XDG_RUNTIME_DIR:-}" == /* && -d "$XDG_RUNTIME_DIR" && ! -L "$XDG_RUNTIME_DIR" &&
  "$(stat -c '%a:%u' "$XDG_RUNTIME_DIR")" == "700:$(id -u)" ]] ||
  die 'XDG_RUNTIME_DIR must be your own 0700 runtime directory'
case "$(stat -f -c %T "$XDG_RUNTIME_DIR")" in
  tmpfs|ramfs) ;;
  *) die 'XDG_RUNTIME_DIR is not on tmpfs; the sign-in must never reach a disk' ;;
esac
if [[ "$DOCUMENT_STDIN" == false ]]; then
  # shellcheck source=scripts/runtime/dev/openbao-access-token.sh
  source "$ROOT/scripts/runtime/dev/openbao-access-token.sh"
  openbao_access_admit || die 'the workstation access client is not available'
  [[ "${BAO_ADDR:-$OPENBAO_ADDR}" == "$OPENBAO_ADDR" ]] ||
    die 'BAO_ADDR must be the canonical OpenBao Tailnet endpoint'
fi
ulimit -c 0 || die 'cannot disable core dumps'

umask 077
trap 'finish $?' EXIT
trap 'exit 130' HUP INT TERM
WORK="$(mktemp -d "$XDG_RUNTIME_DIR/codewire-personal-walk.XXXXXX")"
chmod 0700 "$WORK"
PRIVATE="$WORK/private"
CONFIG="$WORK/cw-config"
mkdir -m 0700 "$PRIVATE" "$PRIVATE/bao" "$CONFIG" "$WORK/bin" "$WORK/browser"
# cw opens the device page with xdg-open; this script approves the code
# itself, so the workstation's browser must never open.
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/xdg-open"
chmod 0700 "$WORK/bin/xdg-open"
DOCUMENT="$PRIVATE/document.json"

if [[ "$DOCUMENT_STDIN" == true ]]; then
  # The document as the CI step read it, on stdin, never more than a page.
  head -c 4096 >"$DOCUMENT"
else
  # The document, read once; the token is revoked before anything else runs.
  openbao_access_acquire "$PRIVATE/bao" || die 'no OpenBao token from the access client'
  if ! openbao_access_kv_get "$PRIVATE/bao" "$OPENBAO_ADDR" "$OPENBAO_PATH" "$DOCUMENT" \
      "$PRIVATE/bao.err"; then
    if grep -Eqi 'permission denied|status code: 403|code 403' "$PRIVATE/bao.err"; then
      die "the access client token lacks the exact Dev path $OPENBAO_PATH"
    elif grep -q '^No value found at ' "$PRIVATE/bao.err"; then
      die "$OPENBAO_PATH does not exist; run provision-dev-personal-walk-user.sh --create-document"
    fi
    die "failed to read $OPENBAO_PATH; output suppressed"
  fi
  openbao_access_revoke "$PRIVATE/bao" "$OPENBAO_ADDR" ||
    die 'the OpenBao token was not confirmed revoked; nothing runs'
fi
[[ "$(stat -c '%a' "$DOCUMENT")" == 600 ]] || die 'the document file is not 0600'
jq -e --arg email "$WALK_EMAIL" '
  (.data.metadata.version | type == "number" and . > 0) and
  (.data.data | type == "object" and keys == ["password", "userEmail"]) and
  (.data.data.password | type == "string" and test("^[A-Za-z0-9_-]{43}$")) and
  .data.data.userEmail == $email
' "$DOCUMENT" >/dev/null 2>&1 || {
  secure_remove "$DOCUMENT"
  die "$OPENBAO_PATH has an unexpected shape"
}

# Nothing from here on reads OpenBao, and nothing the caller set for its own
# cw or OpenBao reaches cw or the command.
for name in "${!BAO_@}"; do unset "$name"; done
unset VAULT_TOKEN VAULT_ADDR CODEWIRE_ACCESS_CLIENT CODEWIRE_OPENBAO_ADDR CODEWIRE_API_KEY \
  CODEWIRE_DEV_SMOKE_API_KEY EXPECTED_CODEWIRE_SMOKE_USER_EMAIL CODEWIRE_ORG \
  CW_HOST_DATA_DIR CW_LOCAL_MESH_STATE_DIR CW_MESH_DATA_DIR CODEWIRE_DAEMON_AUTH_TOKEN \
  CODEWIRE_MESH_AUTH_TOKEN CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN
# The local VM state root lies in the private folder and never exists, so cw
# never reaches the caller's local VMs or starts their supervisor (#3793).
export CW_CONFIG_DIR="$CONFIG"
export CODEWIRE_NATIVE_STATE_ROOT="$WORK/no-local-vm-state"
export PATH="$WORK/bin:$PATH"

log "server: $SERVER; identity: $WALK_EMAIL; cw: $("$CW_BIN" version 2>&1 | head -1)"
# The file exists before cw starts: a background job opens its redirect after
# the fork, and reading a missing file below would end this script.
: >"$PRIVATE/login.out"
"$CW_BIN" --server "$SERVER" login </dev/null >"$PRIVATE/login.out" 2>&1 &
LOGIN_PID=$!
code=""
for _ in $(seq 1 30); do
  code="$(sed -n 's/^Your code: //p' "$PRIVATE/login.out" | tr -d -- '-[:space:]')"
  [[ -z "$code" ]] || break
  sleep 1
done
[[ "$code" =~ ^[A-Z0-9]{8}$ ]] || die 'cw login printed no device code'

# The password goes from the 0600 document to curl through a pipe, and the
# document is removed straight after.
status="$(jq '{email: .data.data.userEmail, password: .data.data.password}' "$DOCUMENT" |
  curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -c "$PRIVATE/cookies" \
    -b "$PRIVATE/cookies" -H 'Content-Type: application/json' --data @- \
    "$SERVER/api/auth/sign-in")" || status=unreachable
[[ "$status" == 200 ]] || die "the password sign-in answered HTTP $status"
for i in $(seq 1 "$BROWSER_SESSIONS"); do browser_session "$i"; done
secure_remove "$DOCUMENT"
[[ ! -e "$DOCUMENT" ]] || die 'the password file was not removed'
curl -sS --max-time 30 -o /dev/null -c "$PRIVATE/cookies" -b "$PRIVATE/cookies" \
  -H 'Content-Type: application/json' -H "Origin: $SERVER" --data '{}' \
  "$SERVER/api/auth/two-factor/skip-setup"
curl -sS --max-time 30 -o "$PRIVATE/device.html" -c "$PRIVATE/cookies" -b "$PRIVATE/cookies" \
  "$SERVER/device?user_code=$code"
csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$PRIVATE/device.html" | head -1)"
[[ -n "$csrf" ]] || die 'the device page had no form'
form=(--data-urlencode "_csrf=$csrf")
for i in 1 2 3 4 5 6 7 8; do form+=(--data-urlencode "user_code_$i=${code:i-1:1}"); done
curl -sS --max-time 30 -o "$PRIVATE/approved.html" -c "$PRIVATE/cookies" -b "$PRIVATE/cookies" \
  -H "Origin: $SERVER" "${form[@]}" "$SERVER/device/_actions/approve"

login_status=0
for _ in $(seq 1 60); do
  kill -0 "$LOGIN_PID" 2>/dev/null || break
  sleep 1
done
kill -0 "$LOGIN_PID" 2>/dev/null && die 'cw login did not finish within a minute of the approval'
wait "$LOGIN_PID" || login_status=$?
LOGIN_PID=""
[[ "$login_status" == 0 ]] || die "cw login exited $login_status"
SIGNED_IN=true
snapshot_grant login || die 'cw login saved a sign-in of an unexpected shape'

# The approval session's work is done: sign it out and see that it is gone.
curl -sS --max-time 30 -o /dev/null -b "$PRIVATE/cookies" -H "Origin: $SERVER" \
  -X POST "$SERVER/api/auth/sign-out" || die 'signing the approval session out failed'
session="$(curl -sS --max-time 30 -b "$PRIVATE/cookies" "$SERVER/api/auth/get-session")" ||
  die 'cannot confirm that the approval session ended'
[[ "$session" == null ]] || die 'the approval session is still signed in'
secure_remove "$PRIVATE/cookies"

whoami="$("$CW_BIN" --server "$SERVER" whoami --output json 2>/dev/null |
  jq -r '.email // empty' 2>/dev/null)" || true
[[ "$whoami" == "$WALK_EMAIL" ]] || die 'cw is not signed in as the personal-walk identity'
log "signed in as $WALK_EMAIL in a private cw config folder"

if [[ "$BROWSER_SESSIONS" -gt 0 ]]; then
  PERSONAL_WALK_BROWSER_STORAGE_STATES="$(IFS=:; printf '%s' "${BROWSER_STATES[*]}")"
  export PERSONAL_WALK_BROWSER_STORAGE_STATES
fi
child_status=0
if [[ "$DOCUMENT_STDIN" == true ]]; then
  # stdin carried the document; the command gets none of it.
  CODEWIRE_SERVER_URL="$SERVER" CW_BIN="$CW_BIN" EXPECTED_PERSONAL_WALK_USER_EMAIL="$WALK_EMAIL" \
    "$@" </dev/null || child_status=$?
else
  CODEWIRE_SERVER_URL="$SERVER" CW_BIN="$CW_BIN" EXPECTED_PERSONAL_WALK_USER_EMAIL="$WALK_EMAIL" \
    "$@" || child_status=$?
fi
[[ "$child_status" == 0 ]] || log "the command exited $child_status"
exit "$child_status"
