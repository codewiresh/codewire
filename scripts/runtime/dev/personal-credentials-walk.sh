#!/usr/bin/env bash
# The done-when walk of #6074 on Dev, as the synthetic personal-walk identity:
# add a synthetic Anthropic API key, select it in a personal profile, create a
# Sandbox with that profile, and delete all three by their exact ids at the
# end, even when a step fails. Run it under with-dev-personal-walk.sh, which
# signs cw in. With --sweep it only reports what the account holds that is
# older than a day, or of unknown age, and deletes nothing.
#
# Dev only, synthetic only. A real provider key on this account is an
# incident: revoke it at the provider and delete it here by id.
set -euo pipefail

readonly DEV_ORIGIN="https://codewire-dev.sh"
readonly WALK_EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
readonly WALK="personal-walk"
# The account's default profile. A user's first profile becomes its default,
# and a default can't be deleted (#3550), so the account keeps this one,
# empty, and each walk's own profile is never the default.
readonly ANCHOR_PROFILE="personal-walk-default"
readonly NAME_PATTERN='^personal-walk-([0-9]{8})t([0-9]{6})z-[0-9a-f]{6}$'
readonly UUID_PATTERN='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

MODE=walk
CREDENTIAL_ID=""
PROFILE_ID=""
SANDBOX_ID=""
ANCHOR_HOLDS_CREDENTIAL=false
WALK_STARTED=false

usage() {
  cat <<'USAGE'
Usage:
  CW_BIN=/path/to/cw scripts/runtime/dev/with-dev-personal-walk.sh -- \
    scripts/runtime/dev/personal-credentials-walk.sh [--sweep]

Dev only, synthetic only. As the synthetic personal-walk identity:

  1. adds a synthetic Anthropic API key, `sk-ant-api03-CWCANARY-PERSONAL-WALK-`
     followed by the run id, which can't authenticate and marks any place it
     turns up;
  2. selects it in a new personal profile;
  3. creates a Sandbox with that profile (30 minute TTL, no network);
  4. deletes the Sandbox, the profile and the credential by their exact ids,
     even when an earlier step failed, and checks that none of them is left.

Every name is personal-walk-RUN_ID, where RUN_ID is the UTC start time and a
random suffix, so two walks never touch each other's objects. The first walk
on a new account also leaves the empty default profile personal-walk-default,
because a default profile can't be deleted.

--sweep lists the account's credentials, profiles and Sandboxes that are older
than a day, or whose age is unknown because no walk named them, and deletes
nothing.

A real provider key on this account is an incident: revoke it at the provider
and delete it here by id (cw credentials --cloud delete id:UUID --yes).
USAGE
}

log() { printf '[personal-credentials-walk] %s\n' "$*" >&2; }
die() { printf '[personal-credentials-walk] FAIL: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --sweep) MODE=sweep; shift ;;
  "") ;;
  *) die "unknown option: $1" ;;
esac
[[ "$#" == 0 ]] || die "unexpected argument: $1"
case "$-" in *x*) die 'shell tracing is enabled; rerun without set -x' ;; esac
readonly SERVER="${CODEWIRE_SERVER_URL:-}"
[[ "$SERVER" == "$DEV_ORIGIN" ]] ||
  die "run under with-dev-personal-walk.sh; this walk is Dev only (server: ${SERVER:-unset})"
[[ "${EXPECTED_PERSONAL_WALK_USER_EMAIL:-}" == "$WALK_EMAIL" && -n "${CW_CONFIG_DIR:-}" ]] ||
  die 'run under with-dev-personal-walk.sh, which signs cw in as the personal-walk identity'
[[ -x "${CW_BIN:-}" ]] || die 'CW_BIN is not an executable cw'
for command in date jq od sed sleep tr; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done

cw() { "$CW_BIN" --server "$SERVER" "$@"; }
# A command's JSON output: from its first line that opens an array or object.
json() { sed -n '/^[[{]/,$p'; }
first() { jq -c 'if type == "array" then .[0] // empty else . end'; }

whoami="$(cw whoami --output json | json | jq -r '.email // empty')" || true
[[ "$whoami" == "$WALK_EMAIL" ]] || die 'cw is not signed in as the personal-walk identity'

# --- the sweep: report only ---------------------------------------------------

# verdict NAME: stale (a walk name older than a day), recent, anchor, or
# unknown (no walk made it, so its age is not known here).
verdict() {
  local name="$1" now stamp
  if [[ "$name" == "$ANCHOR_PROFILE" ]]; then printf 'anchor'; return; fi
  if [[ "$name" =~ $NAME_PATTERN ]]; then
    stamp="$(date -u -d "${BASH_REMATCH[1]} ${BASH_REMATCH[2]:0:2}:${BASH_REMATCH[2]:2:2}:${BASH_REMATCH[2]:4:2}" +%s)" ||
      { printf 'unknown'; return; }
    now="$(date -u +%s)"
    if (( now - stamp > 86400 )); then printf 'stale'; else printf 'recent'; fi
    return
  fi
  printf 'unknown'
}

sweep() {
  local credentials profiles sandboxes kind id name verdict stale=0 unknown=0
  credentials="$(cw credentials --cloud list --output json | json)" || die 'cannot list credentials'
  profiles="$(cw credentials --cloud profiles list --output json | json)" || die 'cannot list profiles'
  sandboxes="$(cw --cloud ls --output json | json)" || die 'cannot list Sandboxes'
  while IFS=$'\t' read -r kind id name; do
    [[ -n "$kind" ]] || continue
    verdict="$(verdict "$name")"
    case "$verdict" in
      stale) stale=$((stale + 1)) ;;
      unknown) unknown=$((unknown + 1)) ;;
      anchor|recent) continue ;;
    esac
    printf 'SWEEP %s id=%s name=%s %s\n' "$kind" "$id" "$name" "$verdict"
  done < <(
    jq -r '.[] | ["credential", .id, .name] | @tsv' <<<"${credentials:-[]}"
    jq -r '.[] | ["profile", .id, .name] | @tsv' <<<"${profiles:-[]}"
    jq -r '.[] | ["sandbox", (.id // .environment_id), .name] | @tsv' <<<"${sandboxes:-[]}"
  )
  log "SWEEP stale=$stale unknown_age=$unknown deleted=0 (report only; delete each by its id)"
}

if [[ "$MODE" == sweep ]]; then
  sweep
  exit 0
fi

# --- the walk -------------------------------------------------------------------

RUN_ID="$(date -u +%Y%m%dt%H%M%Sz)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
readonly NAME="$WALK-$RUN_ID"
[[ "$NAME" =~ $NAME_PATTERN ]] || die 'the run id has an unexpected shape'
# Synthetic, never a key: Anthropic's API-key prefix, so the product treats it
# as one, then a canary marker and the run id, so it can't authenticate and
# any place it turns up names this run.
readonly CANARY="sk-ant-api03-CWCANARY-PERSONAL-WALK-$RUN_ID"

# The id of this run's credential, profile or Sandbox from a full listing: empty
# when it is not listed, and a failure when the listing itself failed.
credential_id() {
  cw credentials --cloud list --output json | json | jq -er --arg name "$NAME" '
    [.[] | select(.name == $name and .provider == "anthropic")]
    | if length == 1 then .[0].id elif length == 0 then "" else error("ambiguous") end'
}
profile_id() {
  cw credentials --cloud profiles list --output json | json | jq -er --arg name "$NAME" '
    [.[] | select(.name == $name)]
    | if length == 1 then .[0].id elif length == 0 then "" else error("ambiguous") end'
}
sandbox_id() {
  cw --cloud ls --output json | json | jq -er --arg name "$NAME" '
    [.[] | select(.name == $name)]
    | if length == 1 then (.[0].id // .[0].environment_id) elif length == 0 then ""
      else error("ambiguous") end'
}
sandbox_listed() {
  cw --cloud ls --output json 2>/dev/null | json |
    jq -e --arg id "$1" 'any(.[]; (.id // .environment_id) == $id)' >/dev/null
}

# Every object this run made is deleted by its id. One whose create may have
# landed without the walk learning its id is looked up by its exact name,
# which only this run uses, and then deleted by id.
cleanup() {
  local status=0 attempt
  [[ "$WALK_STARTED" == true ]] || return 0
  [[ -n "$SANDBOX_ID" ]] || SANDBOX_ID="$(sandbox_id)" || true
  if [[ -n "$SANDBOX_ID" ]]; then
    if cw --cloud rm "$SANDBOX_ID" --yes; then
      for attempt in $(seq 1 36); do
        sandbox_listed "$SANDBOX_ID" || break
        [[ "$attempt" != 36 ]] || { log "Sandbox $SANDBOX_ID is still listed after 3 minutes"; status=1; }
        sleep 5
      done
    else
      log "removing Sandbox $SANDBOX_ID failed"; status=1
    fi
  fi
  [[ -n "$PROFILE_ID" ]] || PROFILE_ID="$(profile_id)" || true
  if [[ -n "$PROFILE_ID" ]]; then
    # The profile stays bound until its Sandbox is gone.
    for attempt in $(seq 1 24); do
      cw credentials --cloud --profile "id:$PROFILE_ID" delete --yes && break
      [[ "$attempt" != 24 ]] || { log "deleting profile $PROFILE_ID failed for 2 minutes"; status=1; }
      sleep 5
    done
  fi
  if [[ "$ANCHOR_HOLDS_CREDENTIAL" == true ]]; then
    cw credentials --cloud --profile "$ANCHOR_PROFILE" unset anthropic ||
      { log "taking the credential out of $ANCHOR_PROFILE failed"; status=1; }
  fi
  [[ -n "$CREDENTIAL_ID" ]] || CREDENTIAL_ID="$(credential_id)" || true
  if [[ -n "$CREDENTIAL_ID" ]]; then
    cw credentials --cloud delete "id:$CREDENTIAL_ID" --yes ||
      { log "deleting credential $CREDENTIAL_ID failed"; status=1; }
  fi
  # Nothing this run made is left, by fresh listings that must succeed.
  local left kind
  for kind in sandbox profile credential; do
    if ! left="$("${kind}_id")"; then
      log "cannot list ${kind}s to confirm the cleanup"; status=1
    elif [[ -n "$left" ]]; then
      log "$kind $left named $NAME is still listed; delete it by its id"; status=1
    fi
  done
  log "cleanup sandbox=${SANDBOX_ID:-none} profile=${PROFILE_ID:-none} credential=${CREDENTIAL_ID:-none} $([[ "$status" == 0 ]] && printf 'deleted' || printf 'INCOMPLETE')"
  return "$status"
}

finish() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup || status=$((status ? status : 1))
  if [[ "$status" == 0 ]]; then
    log "PASS run=$RUN_ID credential_added profile_selected sandbox_created all_three_deleted_by_id"
  fi
  exit "$status"
}
trap 'finish $?' EXIT
trap 'exit 130' HUP INT TERM

log "run $RUN_ID as $WALK_EMAIL on $SERVER; canary marker CWCANARY-PERSONAL-WALK-$RUN_ID"
WALK_STARTED=true

printf '\n$ cw credentials --cloud add anthropic --name %s   # synthetic key on stdin\n' "$NAME"
printf '%s' "$CANARY" | cw credentials --cloud add anthropic --name "$NAME"
CREDENTIAL_ID="$(credential_id)" || true
[[ "$CREDENTIAL_ID" =~ $UUID_PATTERN ]] || die 'the added credential is not listed by its name'
log "created credential id=$CREDENTIAL_ID"

# A new account has no profile yet. Its first would become the default and
# could never be deleted, so the walk first makes the empty default.
profiles="$(cw credentials --cloud profiles list --output json | json)" || die 'cannot list profiles'
if [[ "$(jq 'length' <<<"$profiles")" == 0 ]]; then
  log "the account has no profile; making the empty default $ANCHOR_PROFILE"
  ANCHOR_HOLDS_CREDENTIAL=true
  cw credentials --cloud --profile "$ANCHOR_PROFILE" set anthropic "id:$CREDENTIAL_ID"
  cw credentials --cloud --profile "$ANCHOR_PROFILE" unset anthropic
  ANCHOR_HOLDS_CREDENTIAL=false
  profiles="$(cw credentials --cloud profiles list --output json | json)" || die 'cannot list profiles'
fi
jq -e 'any(.[]; .is_default == true)' <<<"$profiles" >/dev/null ||
  die 'the account has profiles but no default'

printf '\n$ cw credentials --cloud --profile %s set anthropic id:%s\n' "$NAME" "$CREDENTIAL_ID"
cw credentials --cloud --profile "$NAME" set anthropic "id:$CREDENTIAL_ID"
PROFILE_ID="$(profile_id)" || true
[[ "$PROFILE_ID" =~ $UUID_PATTERN ]] || die 'the new profile is not listed by its name'
log "created profile id=$PROFILE_ID"
profile="$(cw credentials --cloud --profile "id:$PROFILE_ID" get --output json | json | first)"
jq -e --arg credential "$CREDENTIAL_ID" '.entries.anthropic == $credential' <<<"$profile" >/dev/null ||
  die 'the profile does not select the credential'
jq -e '.is_default != true' <<<"$profile" >/dev/null ||
  die "the walk's profile became the default, which can't be deleted"

printf '\n$ cw --cloud create --name %s --no-file --ttl 30m --no-network --profile %s\n' "$NAME" "$NAME"
create_status=0
cw --cloud create --name "$NAME" --no-file --ttl 30m --no-network --profile "$NAME" || create_status=$?
SANDBOX_ID="$(sandbox_id)" || true
[[ -z "$SANDBOX_ID" ]] || log "created Sandbox id=$SANDBOX_ID"
[[ "$create_status" == 0 ]] || die "cw create exited $create_status"
[[ -n "$SANDBOX_ID" ]] || die 'the Sandbox is not listed by its name'
printf '\n$ cw --cloud info %s\n' "$SANDBOX_ID"
cw --cloud info "$SANDBOX_ID"
