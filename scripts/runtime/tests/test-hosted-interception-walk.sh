#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WALK="$ROOT/scripts/runtime/dev/hosted-interception-walk.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-hosted-interception-walk-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly PERSONAL_EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
readonly E2E_EMAIL="e2e@codewire.sh"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'hosted-interception-walk tests: %s\n' "$*" >&2; exit 1; }

# A cw that keeps the account's credentials, profiles and Sandboxes in JSON
# files and refuses what Dev refuses: a profile that is the default or still
# bound to a Sandbox, and a credential a profile selects. Its `cw run`
# answers each of the walk's in-Sandbox sessions with the WALK lines Dev
# prints. Every id it makes is recorded as "created KIND ID", and every
# deletion it is asked for as "delete-KIND ID".
make_fake_cw() {
  cat >"$1" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_STATE/argv"
[[ "$1 $2" == '--server https://codewire-dev.sh' ]] || exit 90
shift 2
S="$MOCK_STATE"
event() { printf '%s\n' "$*" >>"$S/events"; }
new_id() { printf '%08x-0000-4000-8000-%012x\n' "$(wc -l <"$S/ids")" "$RANDOM"; printf 'x\n' >>"$S/ids"; }
save() { mv "$S/next.json" "$S/$1.json"; }
profile_ref() { # NAME or id:UUID -> the profile's id, or empty
  local ref="$1"
  if [[ "$ref" == id:* ]]; then jq -r --arg id "${ref#id:}" '.[] | select(.id == $id) | .id' "$S/profiles.json"
  else jq -r --arg name "$ref" '.[] | select(.name == $name) | .id' "$S/profiles.json"; fi
}
walk_line() { # LABEL HTTP ERROR_TYPE REFUSAL
  printf 'WALK %s at=2026-11-25T00:00:00Z http=%s error_type=%s rid=%s refusal=%s\n' "$1" "$2" "$3" "$(new_id)" "$4"
}
case "$*" in
  'whoami --output json') jq -n --arg email "$EMAIL" '{email: $email}' ;;
  'credentials --cloud list --output json') cat "$S/credentials.json" ;;
  'credentials --cloud profiles list --output json') cat "$S/profiles.json" ;;
  '--cloud ls --output json') cat "$S/sandboxes.json" ;;
  'credentials --cloud add anthropic --name '*)
    name="$6" key="$(cat)"
    printf '%s\n' "$key" >>"$S/keys"
    id="$(new_id)"
    event "created credential $id"
    jq --arg id "$id" --arg name "$name" '. + [{id: $id, name: $name, provider: "anthropic", status: "active"}]' \
      "$S/credentials.json" >"$S/next.json" && save credentials
    printf '✓ Anthropic connected as %s\n' "$name" ;;
  'credentials --cloud --profile '*' set anthropic id:'*)
    ref="$4" credential="${7#id:}"
    id="$(profile_ref "$ref")"
    if [[ -n "$id" ]]; then
      jq --arg id "$id" --arg c "$credential" \
        'map(if .id == $id then .entries.anthropic = $c | .revision += 1 else . end)' "$S/profiles.json" >"$S/next.json"
    else
      id="$(new_id)"
      event "created profile $id"
      jq --arg id "$id" --arg name "$ref" --arg c "$credential" \
        '. + [{id: $id, name: $name, is_default: (length == 0), revision: 1, entries: {anthropic: $c}}]' \
        "$S/profiles.json" >"$S/next.json"
    fi
    save profiles ;;
  'credentials --cloud --profile '*' unset anthropic')
    id="$(profile_ref "$4")"
    jq --arg id "$id" 'map(if .id == $id then .entries = {} | .revision += 1 else . end)' "$S/profiles.json" >"$S/next.json"
    save profiles ;;
  'credentials --cloud --profile id:'*' get --output json')
    jq --arg id "${4#id:}" '[.[] | select(.id == $id)]' "$S/profiles.json" ;;
  'credentials --cloud --profile id:'*' delete --yes')
    id="${4#id:}"
    event "delete-profile $id"
    jq -e --arg id "$id" 'any(.[]; .id == $id and .is_default == true)' "$S/profiles.json" >/dev/null && exit 1
    jq -e --arg id "$id" 'any(.[]; .profile == $id)' "$S/sandboxes.json" >/dev/null && exit 1
    jq --arg id "$id" 'map(select(.id != $id))' "$S/profiles.json" >"$S/next.json"
    save profiles ;;
  'credentials --cloud delete id:'*' --yes')
    id="${4#id:}"
    event "delete-credential $id"
    jq -e --arg id "$id" 'any(.[]; .entries.anthropic == $id)' "$S/profiles.json" >/dev/null && exit 1
    jq --arg id "$id" 'map(select(.id != $id))' "$S/credentials.json" >"$S/next.json"
    save credentials ;;
  'credentials --cloud revoke id:'*' --yes')
    id="${4#id:}"
    event "revoke-credential $id"
    # revoke_hits_other: the revoke also changes an entry the walk never made.
    jq --arg id "$id" --arg mode "$MOCK_MODE" \
      'map(if .id == $id or ($mode == "revoke_hits_other" and .id == "00000000-0000-4000-8000-0000000000bb")
        then .status = "revoked" else . end)' "$S/credentials.json" >"$S/next.json"
    save credentials ;;
  '--cloud create --name '*' --profile id:'*' --file '*' --ttl 30m --yes')
    name="$4" profile="${6#id:}"
    id="$(new_id)"
    event "created sandbox $id"
    jq --arg id "$id" --arg name "$name" --arg p "$profile" '. + [{id: $id, name: $name, profile: $p}]' \
      "$S/sandboxes.json" >"$S/next.json" && save sandboxes
    # create_lands_uncertain: the Sandbox exists, but cw's answer was lost.
    [[ "$MOCK_MODE" != create_lands_uncertain ]] || exit 1
    printf 'Environment %s created\n' "$name" ;;
  '--cloud info '*' --output json')
    profile="$(jq -r --arg id "$3" '.[] | select(.id == $id) | .profile' "$S/sandboxes.json")"
    revision="$(jq -r --arg id "$profile" '.[] | select(.id == $id) | .revision' "$S/profiles.json")"
    jq -n --arg id "$3" --arg p "$profile" --argjson r "${revision:-0}" \
      '{id: $id, state: "running", source_selection: {credentials: {profile: ("platform:id:" + $p)}, profile_revision: $r}}' ;;
  '--cloud update '*' --profile platform:id:'*' --yes') event "update-sandbox $3" ;;
  '--cloud rm '*' --yes')
    event "delete-sandbox $3"
    jq --arg id "$3" 'map(select(.id != $id))' "$S/sandboxes.json" >"$S/next.json"
    save sandboxes
    printf 'Removal started\n' ;;
  'run --cloud --in '*)
    # The walk's session: its mode is the first argument after `sh -c INNER sh`.
    [[ "$3 $5 $7 $8 ${10} ${11} ${13}" == '--in --name -- env sh -c sh' ]] || exit 92
    event "session ${14}"
    case "${14}" in
      swap)
        printf 'WALK trust ca_certs=1 node_extra_ca_named=1\n'
        printf 'WALK key at=2026-11-25T00:00:00Z placeholder=1 canary=0 api_key_set=0 base_url_set=0\n'
        walk_line swap-1 401 authentication_error none ;;
      old)
        printf 'WALK kept a_kept=1\n'
        if [[ "$MOCK_MODE" == old_not_refused ]]; then walk_line old-1 401 authentication_error none
        else walk_line old-1 403 permission_error selected_credential_only; fi ;;
      new)
        printf 'WALK key at=2026-11-25T00:00:00Z placeholder=1 canary=0 api_key_set=0 base_url_set=0\n'
        printf 'WALK new same_as_a=0\n'
        walk_line new-1 401 authentication_error none ;;
      revoked) walk_line revoked-1 403 permission_error credential_revoked ;;
      *) exit 93 ;;
    esac ;;
  *) printf 'fake cw: unexpected: %s\n' "$*" >&2; exit 91 ;;
esac
FAKE
  chmod 0755 "$1"
}

# run_case NAME MODE EXPECT_STATUS [WALK ARGS...]. PROFILES, CREDENTIALS and
# SANDBOXES seed the account; IDENTITY picks personal-walk (the default) or
# e2e, and SERVER_URL overrides the server.
run_case() {
  local name="$1" mode="$2" expect="$3"; shift 3
  CASE="$TEST_TMP/$name"
  mkdir -p "$CASE/state" "$CASE/xdg/cw-config" "$CASE/bin"
  printf '%s\n' "${CREDENTIALS:-[]}" >"$CASE/state/credentials.json"
  printf '%s\n' "${PROFILES:-[]}" >"$CASE/state/profiles.json"
  printf '%s\n' "${SANDBOXES:-[]}" >"$CASE/state/sandboxes.json"
  SEED="$(cat "$CASE/state/credentials.json" "$CASE/state/profiles.json" "$CASE/state/sandboxes.json" | jq -c .)"
  : >"$CASE/state/events"
  : >"$CASE/state/argv"
  : >"$CASE/state/ids"
  : >"$CASE/state/keys"
  make_fake_cw "$CASE/cw"
  # Sleeping is the wait between polls and retries; the fake answers at once.
  printf '#!/bin/sh\nexit 0\n' >"$CASE/bin/sleep"
  chmod 0755 "$CASE/bin/sleep"
  local email="$PERSONAL_EMAIL"
  [[ "${IDENTITY:-personal-walk}" != e2e ]] || email="$E2E_EMAIL"
  local status=0
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE" MOCK_STATE="$CASE/state" MOCK_MODE="$mode" EMAIL="$email" \
    CODEWIRE_SERVER_URL="${SERVER_URL-https://codewire-dev.sh}" CW_BIN="$CASE/cw" \
    XDG_RUNTIME_DIR="$CASE/xdg" CW_CONFIG_DIR="$CASE/xdg/cw-config" \
    HOSTED_WALK_IDENTITY="${IDENTITY:-personal-walk}" EXPECTED_PERSONAL_WALK_USER_EMAIL="$PERSONAL_EMAIL" \
    bash "$WALK" "$@" >"$CASE/out" 2>"$CASE/err" || status=$?
  [[ "$status" == "$expect" ]] ||
    { cat "$CASE/out" "$CASE/err" >&2; fail "$name: exit $status, want $expect"; }
  local key
  while IFS= read -r key; do
    [[ "$key" =~ ^sk-ant-api03-CWCANARY-HOSTED-WALK-[0-9]{8}t[0-9]{6}z-[0-9a-f]{6}-[ab]$ ]] ||
      fail "$name: the walk added a key that is not a synthetic canary"
    ! grep -qF -- "$key" "$CASE/out" "$CASE/err" "$CASE/state/argv" ||
      fail "$name: a synthetic key reached output or argv"
  done <"$CASE/state/keys"
}

expect_err() {
  grep -qF -- "$1" "$CASE/err" || { cat "$CASE/err" >&2; fail "$(basename "$CASE"): stderr lacks: $1"; }
}
expect_out() {
  grep -qF -- "$1" "$CASE/out" || { cat "$CASE/out" >&2; fail "$(basename "$CASE"): stdout lacks: $1"; }
}
# The walk deleted exactly the ids it made, in this order of kinds, except
# the one id it keeps on purpose (KEPT: the anchor default).
expect_deleted_only_its_own() {
  local made deleted kinds
  made="$(sed -n 's/^created \([a-z]*\) \(.*\)/\1 \2/p' "$CASE/state/events" |
    { grep -vxF "${KEPT:-none}" || true; } | LC_ALL=C sort)"
  deleted="$(sed -n 's/^delete-\([a-z]*\) \(.*\)/\1 \2/p' "$CASE/state/events" | LC_ALL=C sort)"
  [[ "$deleted" == "$made" ]] ||
    fail "$(basename "$CASE"): deleted [$(paste -sd, <<<"$deleted")], made [$(paste -sd, <<<"$made")]"
  kinds="$(sed -n 's/^delete-\([a-z]*\) .*/\1/p' "$CASE/state/events" | paste -sd, -)"
  [[ "$kinds" == "$1" ]] || fail "$(basename "$CASE"): deletions were [$kinds], want [$1]"
}
# The account holds what it was seeded with, and nothing else.
expect_seed_left() {
  local now
  now="$(cat "$CASE/state/credentials.json" "$CASE/state/profiles.json" "$CASE/state/sandboxes.json" | jq -c .)"
  [[ "$now" == "$SEED" ]] || fail "$(basename "$CASE"): the account changed: $now"
}
expect_not_passed() {
  ! grep -q 'PASS run=' "$CASE/err" || fail "$(basename "$CASE"): the walk passed"
}

readonly OTHER_ID="00000000-0000-4000-8000-0000000000bb"
readonly ANCHOR='{"id":"00000000-0000-4000-8000-0000000000aa","name":"personal-walk-default","is_default":true,"revision":3,"entries":{}}'
readonly OTHER_CREDENTIAL="{\"id\":\"$OTHER_ID\",\"name\":\"someone-elses-key\",\"provider\":\"openai\",\"status\":\"active\"}"
readonly OTHER_SANDBOX='{"id":"00000000-0000-4000-8000-0000000000cc","name":"someone-elses-sandbox","profile":"00000000-0000-4000-8000-0000000000aa"}'
readonly ALL_FOUR='sandbox,profile,credential,credential'

# The walk passes and deletes exactly its four objects; what the account held
# before is untouched.
PROFILES="[$ANCHOR]" CREDENTIALS="[$OTHER_CREDENTIAL]" SANDBOXES="[$OTHER_SANDBOX]" run_case walk success 0
expect_deleted_only_its_own "$ALL_FOUR"
expect_seed_left
expect_err 'PASS run='
expect_err 'swap reselect revoke all_four_objects_deleted_by_id'
expect_err 'RELIST first_listing_entries=3 changed_or_missing=0'
[[ "$(sed -n 's/^\(session\|update-sandbox\|revoke-credential\) .*/\1/p' "$CASE/state/events" | paste -sd, -)" == \
  'session,update-sandbox,session,session,revoke-credential,session' ]] ||
  fail "walk: the steps ran out of order: $(paste -sd, <"$CASE/state/events")"
b_id="$(sed -n 's/^created credential //p' "$CASE/state/events" | sed -n 2p)"
grep -qxF "revoke-credential $b_id" "$CASE/state/events" || fail 'walk: the revoke was not of credential B'
grep -q -- "--cloud update .* --profile platform:id:.* --yes$" "$CASE/state/argv" ||
  fail 'walk: the Sandbox was not rebound with cw update'

# A fresh personal-walk account gets the empty anchor default, which stays.
run_case fresh_account success 0
KEPT="profile $(jq -r '.[0].id' "$CASE/state/profiles.json")" expect_deleted_only_its_own "$ALL_FOUR"
expect_err 'making the empty default personal-walk-default'
jq -e 'length == 1 and .[0].name == "personal-walk-default" and .[0].is_default == true and .[0].entries == {}' \
  "$CASE/state/profiles.json" >/dev/null ||
  fail "fresh_account: the profiles left are $(jq -c . "$CASE/state/profiles.json")"

# A failure part-way still deletes exactly the walk's four ids: a create whose
# answer was lost (the Sandbox is found by its name), and a step whose answer
# is wrong (the walk goes on, then fails).
PROFILES="[$ANCHOR]" CREDENTIALS="[$OTHER_CREDENTIAL]" SANDBOXES="[$OTHER_SANDBOX]" \
  run_case create_lands_uncertain create_lands_uncertain 1
expect_deleted_only_its_own "$ALL_FOUR"
expect_seed_left
expect_err 'cw create exited 1'
expect_not_passed
! grep -q '^session ' "$CASE/state/events" || fail 'create_lands_uncertain: a step ran after the failed create'
PROFILES="[$ANCHOR]" CREDENTIALS="[$OTHER_CREDENTIAL]" SANDBOXES="[$OTHER_SANDBOX]" \
  run_case old_not_refused old_not_refused 1
expect_deleted_only_its_own "$ALL_FOUR"
expect_seed_left
expect_err 'steps not as expected: reselect-old (last http=401 refusal=none'
expect_not_passed

# A first-listing entry that changed during the walk fails it, and the walk
# still deletes only its own ids, never the changed entry.
PROFILES="[$ANCHOR]" CREDENTIALS="[$OTHER_CREDENTIAL]" run_case revoke_hits_other revoke_hits_other 1
expect_deleted_only_its_own "$ALL_FOUR"
expect_out "RELIST changed_or_missing credential	$OTHER_ID	someone-elses-key"
expect_err 'changed_or_missing=1'
expect_err 'an entry of the first listing changed or is gone'
expect_not_passed
jq -e --arg id "$OTHER_ID" 'any(.[]; .id == $id and .status == "revoked")' "$CASE/state/credentials.json" >/dev/null ||
  fail 'revoke_hits_other: the changed entry was deleted'

# As e2e, the account's default is used and never changed; with no profile,
# the walk stops before it makes anything and says why.
E2E_DEFAULT='{"id":"00000000-0000-4000-8000-0000000000dd","name":"me","is_default":true,"revision":17,"entries":{}}'
IDENTITY=e2e PROFILES="[$E2E_DEFAULT]" run_case e2e success 0
expect_deleted_only_its_own "$ALL_FOUR"
expect_seed_left
IDENTITY=e2e run_case e2e_no_profiles success 1
expect_err "the account has no profile, so the walk's own would become its default"
expect_err "give $E2E_EMAIL one first"
[[ ! -s "$CASE/state/events" ]] || fail "e2e_no_profiles: the walk made something: $(paste -sd, <"$CASE/state/events")"
expect_seed_left
PROFILES='[{"id":"00000000-0000-4000-8000-0000000000ee","name":"other","is_default":false,"revision":1,"entries":{}}]' \
  run_case no_default success 1
expect_err 'the account has profiles but no default'
[[ ! -s "$CASE/state/events" ]] || fail "no_default: the walk made something: $(paste -sd, <"$CASE/state/events")"

# Only on Dev.
SERVER_URL=https://codewire.sh run_case production success 1
expect_err 'this walk is Dev only'
[[ ! -s "$CASE/state/argv" ]] || fail 'production: cw ran'

printf 'hosted-interception-walk tests: PASS\n'
