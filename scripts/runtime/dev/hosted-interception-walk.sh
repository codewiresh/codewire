#!/usr/bin/env bash
# The swap, reselect and revoke walk of #6197 behind the hosted front door on
# Dev, as #6074's synthetic personal-walk identity. Run it under
# with-dev-personal-walk.sh, which signs cw in. With --sweep it only reports
# what the account holds under this walk's names that is older than a day,
# and deletes nothing.
#
# Dev only, synthetic only. A real provider key on this account is an
# incident: revoke it at the provider and delete it here by id. Output is
# shapes, counts, HTTP statuses, refusal codes, request ids, closed timing
# labels and object ids, never a key, a placeholder or any other header.
set -euo pipefail

readonly DEV_ORIGIN="https://codewire-dev.sh"
readonly PERSONAL_WALK_EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
# The Dev test account e2e, under cw-security's conditions for it (#6181): a
# caller signs it in from an isolated cw config folder on tmpfs.
readonly E2E_EMAIL="e2e@codewire.sh"
readonly WALK="hosted-walk"
# The account's default profile, which personal-credentials-walk.sh leaves:
# a default can't be deleted (#3550), so the walk's own profile never is one.
readonly ANCHOR_PROFILE="personal-walk-default"
readonly NAME_PATTERN='^hosted-walk-([0-9]{8})t([0-9]{6})z-[0-9a-f]{6}(-[ab])?$'
readonly UUID_PATTERN='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
# Profile edits alone never rebind an environment (SECRETS-AND-CREDENTIALS.md,
# environment sources); `cw update ENV --profile` moves a running Sandbox to
# the profile's current revision with a managed restart, and follows that
# restart to its end. The walk bounds it, and the wait for "running" after.
readonly UPDATE_TIMEOUT_S=900
readonly RUNNING_WINDOW_S=300
# After the restart the old placeholder is refused at once; a first request
# whose handshake is dropped (#6267) is retried within this window.
readonly RESELECT_WINDOW_S=70
readonly REVOKE_WINDOW_S=70

MODE=walk
A_ID="" B_ID="" PROFILE_ID="" SANDBOX_ID="" PROJECT="" WALK_STARTED=false
REQUEST_IDS=()
# What each request's timing line must show, from its HTTP answer: "swapped"
# (the provider's 401: cache hit or miss, one provider request) or "unsent"
# (a 403 refusal: cache bypass, no provider request).
declare -A REQUEST_EXPECT=()
FAILED=()

usage() {
  cat <<'USAGE'
Usage:
  CW_BIN=/path/to/cw scripts/runtime/dev/with-dev-personal-walk.sh -- \
    scripts/runtime/dev/hosted-interception-walk.sh [--sweep]

Dev only, synthetic only, with hosted interception on. As the synthetic
personal-walk identity:

  1. adds two synthetic Anthropic API keys, A and B (the provider prefix, a
     canary marker and the run id, so neither can authenticate), selects A in
     a new personal profile, and creates a Sandbox with that profile;
  2. swap: one request to https://api.anthropic.com/v1/messages through the
     front door with the Sandbox's ANTHROPIC_AUTH_TOKEN; the provider's 401
     means A was swapped in (a first request answered 000 is retried once
     after 2 s, #6267);
  3. reselect: the profile selects B, and `cw --cloud update SANDBOX
     --profile platform:id:PROFILE --yes` moves the Sandbox to that revision
     with a managed restart, since a profile edit alone never rebinds it.
     After the restart, A's old placeholder, kept value-blind in a 0600 file
     on the Sandbox's workspace volume, must get 403 selected_credential_only
     with nothing sent upstream, and a new process must get B's placeholder,
     which differs from A's and is swapped;
  4. revoke: B is revoked by its id, and B's placeholder must get 403
     credential_revoked with nothing sent upstream;
  5. deletes the Sandbox, the profile and both credentials by their exact
     ids, even when a step failed, and checks that none is left.

With HOSTED_WALK_AGENT=claude, each request is a real agent's: `claude -p`
in the Sandbox, with the placeholder under test as its ANTHROPIC_AUTH_TOKEN,
instead of curl. Claude Code shows no response headers, so the walk reads the
status and the refusal from what the agent prints: the provider's 401, or
the front door's 403 and the sentence that names its refusal. No request id
is printed in that mode.

Every request's codewire-request-id is printed. With
HOSTED_WALK_TIMING_LINES set to an executable, the walk runs it with the
walk's start time (RFC 3339) and reads the credential service's raw log
lines from its output, then prints the closed fields of each timing line for
exactly those request ids: cache "miss" or "hit" means a key was swapped in,
"bypass" that none was. Each line must agree with its request's answer: a
provider 401 swapped (one provider request), a 403 refusal unsent (none).

It runs as the personal-walk identity under with-dev-personal-walk.sh, or,
with HOSTED_WALK_IDENTITY=e2e, as the Dev test account e2e signed in from an
isolated cw config folder under XDG_RUNTIME_DIR (cw-security's conditions on
#6181). Either way it lists the account's credentials, profiles and Sandboxes
first, never makes or changes another account's default profile, and at the
end re-lists to show every first-listing entry unchanged and none of its own
objects left.

Every name is hosted-walk-RUN_ID (credentials hosted-walk-RUN_ID-a and -b),
where RUN_ID is the UTC start time and a random suffix. --sweep lists such
objects older than a day and deletes nothing.

A real provider key on this account is an incident: revoke it at the provider
and delete it here by id (cw credentials --cloud delete id:UUID --yes).
USAGE
}

log() { printf '[hosted-interception-walk] %s\n' "$*" >&2; }
die() { printf '[hosted-interception-walk] FAIL: %s\n' "$*" >&2; exit 1; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
fail_step() { FAILED+=("$1"); log "FAIL $1"; }

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
  die "this walk is Dev only (server: ${SERVER:-unset})"
[[ "${XDG_RUNTIME_DIR:-}" == /* && -d "$XDG_RUNTIME_DIR" ]] || die 'XDG_RUNTIME_DIR is unset'
readonly AGENT="${HOSTED_WALK_AGENT:-curl}"
[[ "$AGENT" == curl || "$AGENT" == claude ]] ||
  die "unknown HOSTED_WALK_AGENT: $AGENT (curl or claude)"
case "${HOSTED_WALK_IDENTITY:-personal-walk}" in
  personal-walk)
    WALK_EMAIL="$PERSONAL_WALK_EMAIL"
    [[ "${EXPECTED_PERSONAL_WALK_USER_EMAIL:-}" == "$WALK_EMAIL" && -n "${CW_CONFIG_DIR:-}" ]] ||
      die 'run under with-dev-personal-walk.sh, which signs cw in as the personal-walk identity' ;;
  e2e)
    WALK_EMAIL="$E2E_EMAIL"
    [[ "${CW_CONFIG_DIR:-}" == "$XDG_RUNTIME_DIR"/* ]] ||
      die 'as e2e, cw must be signed in from an isolated config folder under XDG_RUNTIME_DIR' ;;
  *) die "unknown HOSTED_WALK_IDENTITY: $HOSTED_WALK_IDENTITY (personal-walk or e2e)" ;;
esac
readonly WALK_EMAIL
[[ -x "${CW_BIN:-}" ]] || die 'CW_BIN is not an executable cw'
for command in date jq mktemp od sed sleep tr; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
if [[ -n "${HOSTED_WALK_TIMING_LINES:-}" ]]; then
  [[ -x "$HOSTED_WALK_TIMING_LINES" ]] || die 'HOSTED_WALK_TIMING_LINES is not an executable'
fi

cw() { "$CW_BIN" --server "$SERVER" "$@"; }
# A command's JSON output: from its first line that opens an array or object.
json() { sed -n '/^[[{]/,$p'; }
first() { jq -c 'if type == "array" then .[0] // empty else . end'; }

whoami="$(cw whoami --output json | json | jq -r '.email // empty')" || true
[[ "$whoami" == "$WALK_EMAIL" ]] || die "cw is not signed in as $WALK_EMAIL"

# --- the sweep: report only ---------------------------------------------------

sweep() {
  local now_s stamp kind id name stale=0
  now_s="$(date -u +%s)"
  while IFS=$'\t' read -r kind id name; do
    [[ -n "$kind" && "$name" =~ $NAME_PATTERN ]] || continue
    stamp="$(date -u -d "${BASH_REMATCH[1]} ${BASH_REMATCH[2]:0:2}:${BASH_REMATCH[2]:2:2}:${BASH_REMATCH[2]:4:2}" +%s)" ||
      continue
    (( now_s - stamp > 86400 )) || continue
    stale=$((stale + 1))
    printf 'SWEEP %s id=%s name=%s stale\n' "$kind" "$id" "$name"
  done < <(
    cw credentials --cloud list --output json | json | jq -r '.[] | ["credential", .id, .name] | @tsv'
    cw credentials --cloud profiles list --output json | json | jq -r '.[] | ["profile", .id, .name] | @tsv'
    cw --cloud ls --output json | json | jq -r '.[] | ["sandbox", (.id // .environment_id), .name] | @tsv'
  )
  log "SWEEP stale=$stale deleted=0 (report only; delete each by its id)"
}

if [[ "$MODE" == sweep ]]; then
  sweep
  exit 0
fi

# --- the walk -------------------------------------------------------------------

RUN_ID="$(date -u +%Y%m%dt%H%M%Sz)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
readonly NAME="$WALK-$RUN_ID"
[[ "$NAME" =~ $NAME_PATTERN ]] || die 'the run id has an unexpected shape'
START="$(now)"
readonly START
# Synthetic, never keys: Anthropic's API-key prefix, so the product treats
# each as one, then a canary marker, the run id and the key's letter, so
# neither can authenticate and any place one turns up names this run.
readonly CANARY_A="sk-ant-api03-CWCANARY-HOSTED-WALK-$RUN_ID-a"
readonly CANARY_B="sk-ant-api03-CWCANARY-HOSTED-WALK-$RUN_ID-b"

# The account's credentials, profiles and Sandboxes as kind, id, name and
# closed state, one per line, sorted: no value.
inventory() {
  {
    cw credentials --cloud list --output json | json |
      jq -r '.[] | ["credential", .id, .name, .provider, (.status // "-")] | @tsv'
    cw credentials --cloud profiles list --output json | json |
      jq -r '.[] | ["profile", .id, .name, (if .is_default == true then "default" else "-" end), (.revision // "-" | tostring)] | @tsv'
    cw --cloud ls --output json | json |
      jq -r '.[] | ["sandbox", (.id // .environment_id), .name, "-", "-"] | @tsv'
  } | LC_ALL=C sort
}

credential_id() { # SUFFIX: this run's credential NAME-SUFFIX, empty when not listed
  cw credentials --cloud list --output json | json | jq -er --arg name "$NAME-$1" '
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
profile_revision() {
  cw credentials --cloud --profile "id:$PROFILE_ID" get --output json | json | first |
    jq -r '.revision // "unknown"'
}

# The credential service's timing line for each of the walk's request ids,
# closed fields only, from the caller's log reader.
timing_lines() {
  local lines ids
  if [[ -z "${HOSTED_WALK_TIMING_LINES:-}" ]]; then
    log 'timing lines not read: HOSTED_WALK_TIMING_LINES is unset'
    return 0
  fi
  [[ "${#REQUEST_IDS[@]}" -gt 0 ]] || { log 'timing lines: no request ids to select'; return 0; }
  ids="$(printf '%s\n' "${REQUEST_IDS[@]}" | jq -Rsc 'split("\n") | map(select(test("^[0-9a-f-]{36}$")))')"
  lines="$("$HOSTED_WALK_TIMING_LINES" "$START" | jq -Rc --argjson ids "$ids" '
    fromjson? | select(.target == "codewire_credential_broker::timing") | .fields
    | select(.event == "proxied_request" and (.request_id as $r | $ids | index($r)))
    | {request_id, route, outcome, status, cache, material_reads, placeholder, provider_requests}')" ||
    { log 'the timing-line reader failed'; return 1; }
  local id line count expect agrees
  for id in "${REQUEST_IDS[@]}"; do
    count="$(jq -sc --arg id "$id" '[.[] | select(.request_id == $id)] | length' <<<"${lines:-}")"
    line="$(jq -sc --arg id "$id" '[.[] | select(.request_id == $id)] | .[0] // {} | del(.request_id)' <<<"${lines:-}")"
    expect="${REQUEST_EXPECT[$id]:-none}"
    case "$expect" in
      swapped) agrees="$(jq -r '(.cache == "hit" or .cache == "miss") and .provider_requests == 1' <<<"$line")" ;;
      unsent) agrees="$(jq -r '.cache == "bypass" and .provider_requests == 0' <<<"$line")" ;;
      *) agrees=unchecked ;;
    esac
    [[ "$count" == 1 ]] || { [[ "$agrees" == unchecked ]] || agrees=false; }
    printf 'TIMING request_id=%s lines=%s expect=%s agrees=%s %s\n' "$id" "$count" "$expect" "$agrees" "$line"
    [[ "$agrees" != false ]] || fail_step "timing $id (want $expect, lines=$count)"
  done
}

cleanup() {
  local status=0 attempt left
  if [[ "$WALK_STARTED" != true ]]; then
    [[ -z "$PROJECT" ]] || rm -rf -- "$PROJECT"
    return 0
  fi
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
  [[ -n "$A_ID" ]] || A_ID="$(credential_id a)" || true
  [[ -n "$B_ID" ]] || B_ID="$(credential_id b)" || true
  local id
  for id in "$A_ID" "$B_ID"; do
    [[ -n "$id" ]] || continue
    cw credentials --cloud delete "id:$id" --yes || { log "deleting credential $id failed"; status=1; }
  done
  # Nothing this run made is left, by fresh listings that must succeed.
  local check
  for check in sandbox_id profile_id "credential_id a" "credential_id b"; do
    # shellcheck disable=SC2086
    if ! left="$($check)"; then
      log "cannot list to confirm the cleanup ($check)"; status=1
    elif [[ -n "$left" ]]; then
      log "$check: $left is still listed; delete it by its id"; status=1
    fi
  done
  # Every entry of the first listing is still there, unchanged; anything
  # new that is not this run's is another walk's, reported by name only.
  local after
  if [[ -n "$PROJECT" && -s "$PROJECT/first-listing" ]] && after="$(inventory)"; then
    local missing others
    missing="$(LC_ALL=C comm -23 "$PROJECT/first-listing" <(printf '%s\n' "$after") | wc -l)"
    others="$(LC_ALL=C comm -13 "$PROJECT/first-listing" <(printf '%s\n' "$after") | cut -f1,3 | tr '\t' ' ' | paste -sd, -)"
    LC_ALL=C comm -23 "$PROJECT/first-listing" <(printf '%s\n' "$after") | cut -f1,2,3 |
      sed 's/^/RELIST changed_or_missing /'
    log "RELIST first_listing_entries=$(wc -l <"$PROJECT/first-listing") changed_or_missing=$missing now_listed=$(printf '%s\n' "$after" | sed '/^$/d' | wc -l) new_not_this_run=[${others}]"
    printf '%s\n' "$after" | sed '/^$/d' | sed 's/^/RELIST /'
    [[ "$missing" == 0 ]] || { log 'an entry of the first listing changed or is gone'; status=1; }
    if grep -qF "$NAME" <<<"$after"; then log "an object named $NAME is still listed"; status=1; fi
  else
    log 'no re-list against the first listing'; status=1
  fi
  [[ -z "$PROJECT" ]] || rm -rf -- "$PROJECT"
  log "cleanup at $(now) sandbox=${SANDBOX_ID:-none} profile=${PROFILE_ID:-none} credential_a=${A_ID:-none} credential_b=${B_ID:-none} $([[ "$status" == 0 ]] && printf 'deleted_and_none_listed' || printf 'INCOMPLETE')"
  return "$status"
}

finish() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup || status=$((status ? status : 1))
  timing_lines || status=$((status ? status : 1))
  if [[ "${#FAILED[@]}" -gt 0 ]]; then
    log "steps not as expected: ${FAILED[*]}"
    status=$((status ? status : 1))
  fi
  [[ "$status" == 0 ]] && log "PASS run=$RUN_ID agent=$AGENT swap reselect revoke all_four_objects_deleted_by_id"
  exit "$status"
}
trap 'finish $?' EXIT
trap 'exit 130' HUP INT TERM

# What runs in the Sandbox, as one `cw run` session per call, so that each
# call is a new process with the daemon's current projection. It prints only
# WALK lines of closed labels, statuses, refusal codes and request ids. The
# placeholders it keeps (A's, then the new one) stay in 0600 files on the
# workspace volume, which a managed restart retains.
# shellcheck disable=SC2016
readonly INNER='
set -u; umask 077
d=/codewire/run/egress-trust; h=api.anthropic.com
k=/workspace/.hosted-walk; mkdir -p "$k" && chmod 700 "$k"; a="$k/a"; b="$k/b"
body="{\"model\":\"claude-haiku-4-5\",\"max_tokens\":8,\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word WALKOK\"}]}"
agent_probe() { # FILE LABEL: one claude -p turn with the placeholder in FILE
  o=$(mktemp); at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  ANTHROPIC_AUTH_TOKEN="$(cat "$1")" timeout 120 claude -p "Reply with the single word WALKOK" \
    --model claude-haiku-4-5 </dev/null >"$o" 2>&1; x=$?
  c=000
  if grep -qw 403 "$o"; then c=403
  # Claude Code reports a 401 from the provider as "Not logged in · Please run
  # /login"; the timing line at that second shows the swapped 401.
  elif grep -qwE "401|authentication_error" "$o" || grep -qiE "invalid api key|please run /login" "$o"; then c=401
  elif grep -q WALKOK "$o"; then c=200; fi
  f=none
  grep -q "this environment uses was revoked" "$o" && f=credential_revoked
  grep -q "must carry the Sandbox.s Codewire credential" "$o" && f=selected_credential_only
  # Unclassified: what the agent said, placeholders and keys masked.
  said=none
  [ "$c" = 000 ] && said=$(sed -E "s/(cwp1_|sk-ant-)[A-Za-z0-9_-]*/MASKED/g" "$o" | tr -s "[:space:]" " " |
    tr -cd "[:print:]" | cut -c1-160 | tr " =" "__")
  rm -f "$o"
  echo "WALK $2 at=$at agent=claude exit=$x http=$c error_type=agent rid=none refusal=$f said=${said:-empty}"
  last=$c
}
probe() { # FILE LABEL: one request with the placeholder in FILE
  [ "${HOSTED_WALK_AGENT:-curl}" = claude ] && { agent_probe "$@"; return; }
  o=$(mktemp); hd=$(mktemp); at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  c=$(curl -s -o "$o" -D "$hd" --max-time 30 -w "%{http_code}" --cacert $d/ca.pem \
    -H "Authorization: Bearer $(cat "$1")" -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" --data "$body" https://$h/v1/messages 2>/dev/null)
  t=$(jq -r ".error.type // \"none\"" "$o" 2>/dev/null || echo unparsed)
  r=$(tr -d "\r" < "$hd" | awk -F": " "tolower(\$1)==\"codewire-request-id\" {print \$2}" | tail -1)
  f=$(tr -d "\r" < "$hd" | awk -F": " "tolower(\$1)==\"codewire-refusal\" {print \$2}" | tail -1)
  rm -f "$o" "$hd"
  echo "WALK $2 at=$at http=${c:-000} error_type=$t rid=${r:-none} refusal=${f:-none}"
  last=${c:-000}
}
keep() { # FILE: keep this process ANTHROPIC_AUTH_TOKEN in FILE; report its shape
  printf %s "${ANTHROPIC_AUTH_TOKEN-}" > "$1"
  echo "WALK key at=$(date -u +%Y-%m-%dT%H:%M:%SZ) placeholder=$(grep -c "^cwp1_" "$1") canary=$(printf %s "${ANTHROPIC_AUTH_TOKEN-}${ANTHROPIC_API_KEY-}${CLAUDE_CODE_OAUTH_TOKEN-}" | grep -c CWCANARY) api_key_set=$([ -n "${ANTHROPIC_API_KEY-}" ] && echo 1 || echo 0) base_url_set=$([ -n "${ANTHROPIC_BASE_URL-}" ] && echo 1 || echo 0)"
}
until_refused() { # FILE LABEL SECONDS: probe every 5 s until a 403 or SECONDS pass
  t0=$(date +%s); n=0
  while :; do
    n=$((n + 1)); probe "$1" "$2-$n"
    [ "$last" = 403 ] && break
    [ $(( $(date +%s) - t0 )) -ge "$3" ] && break
    sleep 5
  done
}
case "$1" in
  swap)
    echo "WALK trust ca_certs=$(grep -c "BEGIN CERTIFICATE" $d/ca.pem 2>/dev/null || echo 0) node_extra_ca_named=$([ "${NODE_EXTRA_CA_CERTS-}" = $d/ca.pem ] && echo 1 || echo 0)"
    # The claude in the image is a launcher that installs the native build on its
    # first run, which sends no request; run it once before the probes.
    if [ "${HOSTED_WALK_AGENT:-curl}" = claude ]; then
      echo "WALK agent claude_found=$(command -v claude >/dev/null && echo 1 || echo 0)"
      timeout 180 claude --version </dev/null >/dev/null 2>&1; echo "WALK agent installed_exit=$?"
    fi
    keep "$a"
    probe "$a" swap-1
    if [ "$last" = 000 ]; then sleep 2; probe "$a" swap-2; fi ;;
  old)
    echo "WALK kept a_kept=$([ -s "$a" ] && echo 1 || echo 0)"
    [ -s "$a" ] && until_refused "$a" old "$2" ;;
  new)
    keep "$b"
    if cmp -s "$a" "$b"; then echo "WALK new same_as_a=1"
    else
      echo "WALK new same_as_a=0"; probe "$b" new-1
      if [ "$last" = 000 ]; then sleep 2; probe "$b" new-2; fi
    fi ;;
  revoked) until_refused "$b" revoked "$2" ;;
esac
'
inner() { # MODE [ARG]: one new session in the Sandbox; its WALK lines only
  # A random name: each call runs in a command substitution's subshell, so
  # no counter would survive it, and cw never reuses a session's name.
  local raw rc=0 session
  session="walk-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  raw="$(cw run --cloud --in "$SANDBOX_ID" --name "$session" -- \
    env HOSTED_WALK_AGENT="$AGENT" sh -c "$INNER" sh "$@" \
    </dev/null 2>&1)" || rc=$?
  grep -E '^WALK ' <<<"$raw" || true
  # Without a WALK line, cw's own refusal says why: its error and trace lines.
  if ! grep -qE '^WALK ' <<<"$raw"; then
    log "session $session ($1) printed no WALK line at $(now); cw run exited $rc"
    grep -E '^(✗|error|Error|trace )' <<<"$raw" | cut -c1-200 | sed 's/^/[cw] /' >&2 || true
  fi
}
field() { { grep -oE "(^| )$2=[^ ]*" <<<"$1" || true; } | head -1 | cut -d= -f2; }
record_ids() {
  local line rid
  while read -r line; do
    rid="$(field "$line" rid)"
    [[ "$rid" =~ $UUID_PATTERN ]] || continue
    REQUEST_IDS+=("$rid")
    if [[ "$(field "$line" http)" == 401 && "$(field "$line" refusal)" == none ]]; then
      REQUEST_EXPECT[$rid]=swapped
    elif [[ "$(field "$line" http)" == 403 && "$(field "$line" refusal)" != none ]]; then
      REQUEST_EXPECT[$rid]=unsent
    fi
  done < <(grep -E ' rid=' <<<"$1" || true)
}
sandbox_state() {
  cw --cloud info "$SANDBOX_ID" --output json 2>/dev/null | json | first |
    jq -r '.state // .status // "unknown"'
}

log "run $RUN_ID as $WALK_EMAIL on $SERVER at $START with agent $AGENT; canary marker CWCANARY-HOSTED-WALK-$RUN_ID"
# The first listing, before anything is made; the cleanup compares with it.
PROJECT="$(mktemp -d "$XDG_RUNTIME_DIR/hosted-walk.XXXXXX")"
inventory >"$PROJECT/first-listing" || die 'cannot list the account before the walk'
log "FIRST listing: $(wc -l <"$PROJECT/first-listing") entries (kind, id, name, provider or default, status or revision)"
sed 's/^/FIRST /' "$PROJECT/first-listing"
WALK_STARTED=true

# --- 1. set up ------------------------------------------------------------------

printf '\n$ cw credentials --cloud add anthropic --name %s-a   # synthetic key on stdin\n' "$NAME"
printf '%s' "$CANARY_A" | cw credentials --cloud add anthropic --name "$NAME-a"
A_ID="$(credential_id a)" || true
[[ "$A_ID" =~ $UUID_PATTERN ]] || die 'credential A is not listed by its name'
printf '\n$ cw credentials --cloud add anthropic --name %s-b   # synthetic key on stdin\n' "$NAME"
printf '%s' "$CANARY_B" | cw credentials --cloud add anthropic --name "$NAME-b"
B_ID="$(credential_id b)" || true
[[ "$B_ID" =~ $UUID_PATTERN ]] || die 'credential B is not listed by its name'
log "created credential_a=$A_ID credential_b=$B_ID"

profiles="$(cw credentials --cloud profiles list --output json | json)" || die 'cannot list profiles'
# Only the personal-walk identity may get the anchor default; any other
# account's default is never made or changed.
if [[ "$(jq 'length' <<<"$profiles")" == 0 && "$WALK_EMAIL" == "$PERSONAL_WALK_EMAIL" ]]; then
  log "the account has no profile; making the empty default $ANCHOR_PROFILE"
  cw credentials --cloud --profile "$ANCHOR_PROFILE" set anthropic "id:$A_ID"
  cw credentials --cloud --profile "$ANCHOR_PROFILE" unset anthropic
  profiles="$(cw credentials --cloud profiles list --output json | json)" || die 'cannot list profiles'
fi
jq -e 'any(.[]; .is_default == true)' <<<"$profiles" >/dev/null ||
  die 'the account has profiles but no default'

printf '\n$ cw credentials --cloud --profile %s set anthropic id:%s\n' "$NAME" "$A_ID"
cw credentials --cloud --profile "$NAME" set anthropic "id:$A_ID"
PROFILE_ID="$(profile_id)" || true
[[ "$PROFILE_ID" =~ $UUID_PATTERN ]] || die 'the new profile is not listed by its name'
profile="$(cw credentials --cloud --profile "id:$PROFILE_ID" get --output json | json | first)"
jq -e --arg c "$A_ID" '.entries.anthropic == $c and .is_default != true' <<<"$profile" >/dev/null ||
  die 'the profile does not select A, or it became the default'
log "created profile=$PROFILE_ID revision=$(jq -r '.revision // "unknown"' <<<"$profile") selects=credential_a"

jq -n '{version:1, working_directory:"/workspace", agents:{tools:["claude-code"]}}' >"$PROJECT/codewire.json"
printf '\n$ cw --cloud create --name %s --profile id:%s --file codewire.json --ttl 30m --yes\n' "$NAME" "$PROFILE_ID"
create_status=0
cw --cloud create --name "$NAME" --profile "id:$PROFILE_ID" --file "$PROJECT/codewire.json" \
  --ttl 30m --yes || create_status=$?
SANDBOX_ID="$(sandbox_id)" || true
[[ -z "$SANDBOX_ID" ]] || log "created sandbox=$SANDBOX_ID at $(now)"
[[ "$create_status" == 0 ]] || die "cw create exited $create_status"
[[ "$SANDBOX_ID" =~ $UUID_PATTERN ]] || die 'the Sandbox is not listed by its name'
selected="$(cw --cloud info "$SANDBOX_ID" --output json | json | first |
  jq -r '.source_selection.credentials.profile // "none"')"
[[ "$selected" == *"$PROFILE_ID" ]] || die "the Sandbox selects $selected, not the walk's profile"
log "the Sandbox selects only the walk's profile ($PROFILE_ID)"

# --- 2. swap --------------------------------------------------------------------

log "STEP swap at $(now)"
out="$(inner swap)"
printf '%s\n' "$out"
record_ids "$out"
[[ "$(field "$out" placeholder)" == 1 && "$(field "$out" canary)" == 0 ]] ||
  die "the Sandbox's ANTHROPIC_AUTH_TOKEN is not a placeholder, or a variable holds a canary"
last="$(grep -E '^WALK swap-' <<<"$out" | tail -1 || true)"
if [[ "$(field "$last" http)" == 401 && "$(field "$last" refusal)" == none &&
    ( "$AGENT" == claude || "$(field "$last" rid)" =~ $UUID_PATTERN ) ]]; then
  log "ok   swap: A's placeholder got the provider's 401 ($(field "$last" error_type))"
else
  fail_step "swap (http=$(field "$last" http) refusal=$(field "$last" refusal))"
fi

# --- 3. reselect ----------------------------------------------------------------

log "STEP reselect at $(now)"
printf '\n$ cw credentials --cloud --profile id:%s set anthropic id:%s\n' "$PROFILE_ID" "$B_ID"
cw credentials --cloud --profile "id:$PROFILE_ID" set anthropic "id:$B_ID"
log "reselect: the profile selects credential_b at $(now) (revision $(profile_revision))"
# A profile edit alone never rebinds the Sandbox; the update moves it to the
# profile's current revision with a managed restart and follows the restart.
printf '\n$ cw --cloud update %s --profile platform:id:%s --yes\n' "$SANDBOX_ID" "$PROFILE_ID"
update_status=0
timeout --kill-after=30s "$UPDATE_TIMEOUT_S" "$CW_BIN" --server "$SERVER" --cloud update \
  "$SANDBOX_ID" --profile "platform:id:$PROFILE_ID" --yes </dev/null || update_status=$?
log "reselect: cw update exited $update_status at $(now)"
state=unknown
for _ in $(seq 1 $((RUNNING_WINDOW_S / 5))); do
  state="$(sandbox_state)"
  [[ "$state" == running ]] && break
  sleep 5
done
restarted="$(now)"
log "reselect: the Sandbox is $state at $restarted (selected revision $(cw --cloud info "$SANDBOX_ID" --output json | json | first | jq -r '.source_selection.profile_revision // "unknown"'))"
moved=false
if [[ "$update_status" == 0 && "$state" == running ]]; then
  moved=true
else
  fail_step "reselect-update (cw update exited $update_status; state $state after ${RUNNING_WINDOW_S}s)"
fi

new_ok=false
if [[ "$moved" == true ]]; then
  out="$(inner old "$RESELECT_WINDOW_S")"
  printf '%s\n' "$out"
  record_ids "$out"
  last="$(grep -E '^WALK old-' <<<"$out" | tail -1 || true)"
  if [[ "$(field "$out" a_kept)" != 1 ]]; then
    fail_step 'reselect-old (A placeholder was not kept across the restart)'
  elif [[ "$(field "$last" http)" == 403 && "$(field "$last" refusal)" == selected_credential_only ]]; then
    log "ok   reselect: A's old placeholder refused selected_credential_only at $(field "$last" at) (restarted by $restarted)"
  else
    fail_step "reselect-old (last http=$(field "$last" http) refusal=$(field "$last" refusal) within ${RESELECT_WINDOW_S}s)"
  fi

  out="$(inner new)"
  printf '%s\n' "$out"
  record_ids "$out"
  last="$(grep -E '^WALK new-' <<<"$out" | tail -1 || true)"
  if [[ "$(field "$out" same_as_a)" != 0 ]]; then
    fail_step "reselect-new (a new process has A's placeholder: same_as_a=$(field "$out" same_as_a))"
  elif [[ "$(field "$out" placeholder)" == 1 && "$(field "$last" http)" == 401 &&
      "$(field "$last" refusal)" == none ]]; then
    log "ok   reselect: a new process's placeholder differs from A's and got the provider's 401 at $(field "$last" at)"
    new_ok=true
  else
    fail_step "reselect-new (placeholder=$(field "$out" placeholder) http=$(field "$last" http) refusal=$(field "$last" refusal))"
  fi
fi

# --- 4. revoke ------------------------------------------------------------------

if [[ "$new_ok" == true ]]; then
  log "STEP revoke at $(now)"
  printf '\n$ cw credentials --cloud revoke id:%s --yes\n' "$B_ID"
  cw credentials --cloud revoke "id:$B_ID" --yes
  log "revoke: credential_b revoked at $(now)"
  out="$(inner revoked "$REVOKE_WINDOW_S")"
  printf '%s\n' "$out"
  record_ids "$out"
  last="$(grep -E '^WALK revoked-' <<<"$out" | tail -1 || true)"
  if [[ "$(field "$last" http)" == 403 && "$(field "$last" refusal)" == credential_revoked ]]; then
    log "ok   revoke: B's placeholder refused credential_revoked at $(field "$last" at)"
  else
    fail_step "revoke (last http=$(field "$last" http) refusal=$(field "$last" refusal) within ${REVOKE_WINDOW_S}s)"
  fi
else
  fail_step 'revoke (not run: no new process held a swapped placeholder of B)'
fi
