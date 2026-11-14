#!/usr/bin/env bash
# Walk the invite, accept and remove steps of docs/journeys/invitations.md on
# Dev with two synthetic identities and no person: the Dev smoke identity
# (organization codewire-dev-smoke) invites the synthetic invitee
# (provision-dev-invitee-user.sh), the invitee signs in through `cw login`'s
# device sign-in and accepts, the inviter removes it, and its `cw org list`
# shows it is gone. Every invitation the walk made is revoked at the end.
#
# The invitee's password is read from OpenBao into this process's private
# folder and never printed; the smoke key stays inside the smoke wrapper.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly SERVER="${CODEWIRE_SERVER_URL:-https://codewire-dev.sh}"
readonly OPENBAO_ADDR="${CODEWIRE_OPENBAO_ADDR:-https://openbao.example.invalid}"
readonly INVITEE_PATH="apps/codewire/dev/ci-invitee"
readonly ORG_SLUG="codewire-dev-smoke"
readonly SMOKE_AUTH="$ROOT/scripts/runtime/dev/with-dev-smoke-auth.sh"
CW_BIN="${CW_BIN:-$ROOT/target/debug/cw}"
WORK=""
LOGIN_PID=""

log() { printf '[invitations-journey] %s\n' "$*" >&2; }
die() { printf '[invitations-journey] FAIL: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage:
  CW_BIN=/path/to/cw scripts/runtime/dev/invitations-journey.sh

Runs invite-send, invite-accept and invite-remove of docs/journeys/invitations.md
on Dev as the smoke identity (inviter) and the synthetic invitee, prints each
command with what it showed, and revokes every invitation it made. Needs the
workstation OpenBao access client, as the smoke wrapper does.
USAGE
}

cleanup() {
  [[ -z "$LOGIN_PID" ]] || kill "$LOGIN_PID" 2>/dev/null || true
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    find "$WORK" -type f -exec shred -u -- {} + 2>/dev/null || true
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

case "${1:-}" in -h|--help) usage; exit 0 ;; "") ;; *) die "unknown option: $1" ;; esac
case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
for command in curl jq shred; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ -x "$CW_BIN" ]] || die "Codewire CLI is unavailable: $CW_BIN (set CW_BIN)"

umask 077
WORK="$(mktemp -d "${TMPDIR:-/tmp}/codewire-invitations-journey.XXXXXX")"
mkdir -m 0700 "$WORK/bin" "$WORK/inviter" "$WORK/invitee"
# cw opens the device page with xdg-open; this walk approves it itself, so the
# workstation's browser must never open.
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/xdg-open"
chmod 0700 "$WORK/bin/xdg-open"

# The invitee's document, read once through the same access client the smoke
# wrapper uses.
# shellcheck source=scripts/runtime/dev/openbao-access-token.sh
source "$ROOT/scripts/runtime/dev/openbao-access-token.sh"
openbao_access_admit || die 'the workstation access client is not available'
mkdir -m 0700 "$WORK/bao"
openbao_access_acquire "$WORK/bao" || die 'no OpenBao token from the access client'
openbao_access_kv_get "$WORK/bao" "$OPENBAO_ADDR" "$INVITEE_PATH" "$WORK/invitee.json" "$WORK/bao.err" ||
  die "cannot read $INVITEE_PATH; run provision-dev-invitee-user.sh first"
openbao_access_revoke "$WORK/bao" "$OPENBAO_ADDR" || die 'the OpenBao token was not confirmed revoked'
jq -e '.data.data | keys == ["password", "userEmail"]' "$WORK/invitee.json" >/dev/null ||
  die "$INVITEE_PATH has an unexpected shape"
INVITEE_EMAIL="$(jq -r '.data.data.userEmail' "$WORK/invitee.json")"
jq -n --slurpfile doc "$WORK/invitee.json" \
  '{email: $doc[0].data.data.userEmail, password: $doc[0].data.data.password}' >"$WORK/sign-in.json"
shred -u -- "$WORK/invitee.json"

redact() { sed -E 's#(accept-invite\?token=)[^[:space:]]+#\1<redacted>#g'; }

# One command as the inviter, inside the smoke wrapper, printed with its output.
inviter() {
  printf '\n$ cw %s   # inviter\n' "$*"
  # shellcheck disable=SC2016 # The child shell expands the key the wrapper loaded.
  "$SMOKE_AUTH" -- env HOME="$WORK/inviter" CW="$CW_BIN" bash -c \
    'CODEWIRE_API_KEY="$CODEWIRE_DEV_SMOKE_API_KEY" exec "$CW" --server "$0" "$@"' \
    "$SERVER" "$@" 2> >(grep -v '^\[runtime-smoke-auth\]' >&2) | redact
}

# One OrganizationService call as the inviter (no `cw` command revokes, #4508).
inviter_api() {
  # shellcheck disable=SC2016 # The child shell expands the key the wrapper loaded.
  "$SMOKE_AUTH" -- env METHOD="$1" BODY="$2" SERVER="$SERVER" bash -c '
    curl -sS --max-time 30 -X POST -H "Content-Type: application/json" \
      -H @<(printf "Authorization: Bearer %s\n" "$CODEWIRE_DEV_SMOKE_API_KEY") \
      --data "$BODY" "$SERVER/codewire.v1.OrganizationService/$METHOD"' \
    2> >(grep -v '^\[runtime-smoke-auth\]' >&2)
}

# One command as the invitee, with its own HOME and no local VM state.
invitee() {
  printf '\n$ cw %s   # invitee\n' "$*"
  HOME="$WORK/invitee" PATH="$WORK/bin:$PATH" CODEWIRE_NATIVE_STATE_ROOT="$WORK/no-local-vm-state" \
    "$CW_BIN" --server "$SERVER" "$@"
}

revoke_walk_invitations() {
  local org_id ids id
  org_id="$(inviter org list --output json | sed -n '/^\[/,$p' |
    jq -r --arg slug "$ORG_SLUG" '.[] | select(.slug == $slug) | .id')" || return 1
  ids="$(inviter_api ListInvitations "{\"orgId\":\"$org_id\"}" | jq -r --arg email "$INVITEE_EMAIL" \
    '.invitations // [] | .[] | select(.email == $email and .status == "INVITATION_STATUS_PENDING") | .id')"
  for id in $ids; do
    inviter_api RevokeInvitation "{\"orgId\":\"$org_id\",\"invitationId\":\"$id\"}" >/dev/null
    log "revoked pending invitation $id"
  done
}

log "cw: $("$CW_BIN" version 2>&1 | head -1); server: $SERVER; invitee: $INVITEE_EMAIL"

# A walk that stopped part-way may have left the invitee pending or joined.
revoke_walk_invitations
inviter org member rm "$INVITEE_EMAIL" --org "$ORG_SLUG" --yes >/dev/null 2>&1 || true

# invite-send
out="$(inviter org invite "$INVITEE_EMAIL" --role member --org "$ORG_SLUG" 2>&1)"; printf '%s\n' "$out"
grep -q "^Invitation email sent to $INVITEE_EMAIL" <<<"$out" || die 'invite-send: no "Invitation email sent" line'
out="$(inviter org invite "$INVITEE_EMAIL" --role member --org "$ORG_SLUG" 2>&1 || true)"; printf '%s\n' "$out"
grep -q 'a pending invitation already exists for this email' <<<"$out" || die 'invite-send: the duplicate was not refused'

# invite-accept: the invitee signs in through device sign-in, approving the
# code itself with a password session that skips second-factor setup.
printf '\n$ cw login   # invitee\n'
HOME="$WORK/invitee" PATH="$WORK/bin:$PATH" CODEWIRE_NATIVE_STATE_ROOT="$WORK/no-local-vm-state" \
  "$CW_BIN" --server "$SERVER" login </dev/null >"$WORK/login.out" 2>&1 &
LOGIN_PID=$!
code=""
for _ in $(seq 1 30); do
  code="$(sed -n 's/^Your code: //p' "$WORK/login.out" | tr -d -- '-[:space:]')"
  [[ -z "$code" ]] || break
  sleep 1
done
[[ "$code" =~ ^[A-Z0-9]{8}$ ]] || die 'invite-accept: cw login printed no device code'
status="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code}' -c "$WORK/cookies" -b "$WORK/cookies" \
  -H 'Content-Type: application/json' --data "@$WORK/sign-in.json" "$SERVER/api/auth/sign-in")"
[[ "$status" == 200 ]] || die "invite-accept: the invitee's sign-in answered HTTP $status"
curl -sS --max-time 30 -o /dev/null -c "$WORK/cookies" -b "$WORK/cookies" -H 'Content-Type: application/json' \
  -H "Origin: $SERVER" --data '{}' "$SERVER/api/auth/two-factor/skip-setup"
curl -sS --max-time 30 -o "$WORK/device.html" -c "$WORK/cookies" -b "$WORK/cookies" "$SERVER/device?user_code=$code"
csrf="$(sed -n 's/.*name="_csrf" value="\([^"]*\)".*/\1/p' "$WORK/device.html" | head -1)"
[[ -n "$csrf" ]] || die 'invite-accept: the device page had no form'
form=(--data-urlencode "_csrf=$csrf")
for i in 1 2 3 4 5 6 7 8; do form+=(--data-urlencode "user_code_$i=${code:i-1:1}"); done
curl -sS --max-time 30 -o "$WORK/approved.html" -c "$WORK/cookies" -b "$WORK/cookies" \
  -H "Origin: $SERVER" "${form[@]}" "$SERVER/device/_actions/approve"
# An invitee has no organization yet; cw login succeeds for it and points to
# its invitations (#4530).
login_status=0
wait "$LOGIN_PID" || login_status=$?
LOGIN_PID=""
grep -v '^Your code:' "$WORK/login.out"
[[ "$login_status" == 0 ]] || die "invite-accept: cw login exited $login_status"
grep -qF "You're not in an organization yet; create one with \`cw org create NAME\`, or accept an invitation with \`cw org invitations\`." "$WORK/login.out" ||
  die 'invite-accept: cw login did not point to cw org invitations'
invitee whoami
invitee org invitations
out="$(invitee org accept "$ORG_SLUG" 2>&1)"; printf '%s\n' "$out"
grep -q "^Joined .* ($ORG_SLUG) as member\.$" <<<"$out" || die 'invite-accept: cw org accept did not join'

# invite-remove
out="$(inviter org members --org "$ORG_SLUG")"; printf '%s\n' "$out"
grep -qF "$INVITEE_EMAIL" <<<"$out" || die 'invite-remove: the invitee is not listed as a member'
out="$(inviter org member rm "$INVITEE_EMAIL" --org "$ORG_SLUG" --yes 2>&1)"; printf '%s\n' "$out"
grep -q "^Removed $INVITEE_EMAIL from " <<<"$out" || die 'invite-remove: cw org member rm did not remove'
out="$(inviter org members --org "$ORG_SLUG")"; printf '%s\n' "$out"
! grep -qF "$INVITEE_EMAIL" <<<"$out" || die 'invite-remove: the invitee is still listed'
out="$(invitee org list 2>&1 || true)"; printf '%s\n' "$out"
! grep -q "$ORG_SLUG" <<<"$out" || die "invite-remove: the invitee still sees $ORG_SLUG"

revoke_walk_invitations
invitee logout >/dev/null 2>&1 || true
curl -sS --max-time 30 -o /dev/null -b "$WORK/cookies" -H "Origin: $SERVER" -X POST "$SERVER/api/auth/sign-out" || true
log 'PASS invite-send invite-accept invite-remove; secret_values_printed=false'
