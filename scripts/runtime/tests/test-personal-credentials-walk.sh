#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WALK="$ROOT/scripts/runtime/dev/personal-credentials-walk.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-personal-credentials-walk-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly EMAIL="success+codewire-dev-personal-walk@simulator.amazonses.com"
readonly ACCESS_TOKEN="synthetic-walk-access-token-0123456789abcdef"
readonly ORG_ID="0123456789abcdef0123456789abcdef"

cleanup() { rm -rf -- "$TEST_TMP"; }
trap cleanup EXIT
fail() { printf 'personal-credentials-walk tests: %s\n' "$*" >&2; exit 1; }

# A cw that keeps the account's credentials, profiles and Sandboxes in JSON
# files and refuses what Dev refuses: a profile that is the default or still
# bound to a Sandbox, and a credential a profile selects.
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
edit() { jq "$@" >"$S/next.json"; }
profile_ref() { # NAME or id:UUID -> the profile's id, or empty
  local ref="$1"
  if [[ "$ref" == id:* ]]; then jq -r --arg id "${ref#id:}" '.[] | select(.id == $id) | .id' "$S/profiles.json"
  else jq -r --arg name "$ref" '.[] | select(.name == $name) | .id' "$S/profiles.json"; fi
}
case "$*" in
  'whoami --output json') jq -n --arg email "$EMAIL" '{email: $email}' ;;
  'credentials --cloud list --output json') cat "$S/credentials.json" ;;
  'credentials --cloud profiles list --output json') cat "$S/profiles.json" ;;
  '--cloud ls --output json') cat "$S/sandboxes.json" ;;
  'credentials --cloud add anthropic --name '*)
    name="${*: -1}"
    key="$(cat)"
    printf '%s\n' "$key" >>"$S/keys"
    event "add-credential $name"
    [[ "$MOCK_MODE" != add_fails ]] || exit 1
    id="$(new_id)"
    jq --arg id "$id" --arg name "$name" '. + [{id: $id, name: $name, provider: "anthropic"}]' \
      "$S/credentials.json" >"$S/next.json" && mv "$S/next.json" "$S/credentials.json"
    printf '✓ Anthropic connected as %s\n' "$name"
    [[ "$MOCK_MODE" != add_lands_uncertain ]] || exit 1 ;;
  'credentials --cloud --profile '*' set anthropic id:'*)
    ref="$4" credential="${7#id:}"
    event "profile-set $ref"
    [[ "$MOCK_MODE" != profile_set_fails || "$ref" == personal-walk-default ]] || exit 1
    id="$(profile_ref "$ref")"
    if [[ -n "$id" ]]; then
      jq --arg id "$id" --arg c "$credential" 'map(if .id == $id then .entries.anthropic = $c else . end)' \
        "$S/profiles.json" >"$S/next.json"
    else
      id="$(new_id)"
      jq --arg id "$id" --arg name "$ref" --arg c "$credential" \
        '. + [{id: $id, name: $name, is_default: (length == 0), entries: {anthropic: $c}}]' \
        "$S/profiles.json" >"$S/next.json"
    fi
    mv "$S/next.json" "$S/profiles.json" ;;
  'credentials --cloud --profile '*' unset anthropic')
    id="$(profile_ref "$4")"
    event "profile-unset $4"
    jq --arg id "$id" 'map(if .id == $id then .entries = {} else . end)' "$S/profiles.json" >"$S/next.json"
    mv "$S/next.json" "$S/profiles.json" ;;
  'credentials --cloud --profile id:'*' get --output json')
    jq --arg id "${4#id:}" '[.[] | select(.id == $id)]' "$S/profiles.json" ;;
  'credentials --cloud --profile id:'*' delete --yes')
    id="${4#id:}"
    event "delete-profile $id"
    jq -e --arg id "$id" 'any(.[]; .id == $id and .is_default == true)' "$S/profiles.json" >/dev/null && exit 1
    jq -e --arg id "$id" 'any(.[]; .profile == $id)' "$S/sandboxes.json" >/dev/null && exit 1
    jq --arg id "$id" 'map(select(.id != $id))' "$S/profiles.json" >"$S/next.json"
    mv "$S/next.json" "$S/profiles.json" ;;
  'credentials --cloud delete id:'*' --yes')
    id="${4#id:}"
    event "delete-credential $id"
    jq -e --arg id "$id" 'any(.[]; .entries.anthropic == $id)' "$S/profiles.json" >/dev/null && exit 1
    jq --arg id "$id" 'map(select(.id != $id))' "$S/credentials.json" >"$S/next.json"
    mv "$S/next.json" "$S/credentials.json" ;;
  '--cloud create --name '*' --no-file --ttl 30m --no-network --profile '*' --yes')
    name="$4" profile="$(profile_ref "${10}")"
    event "create-sandbox $name"
    [[ "$MOCK_MODE" != create_fails ]] || exit 1
    id="$(new_id)"
    jq --arg id "$id" --arg name "$name" --arg p "$profile" '. + [{id: $id, name: $name, profile: $p, placement: "cloud"}]' \
      "$S/sandboxes.json" >"$S/next.json" && mv "$S/next.json" "$S/sandboxes.json"
    printf 'Environment %s created\n' "$name" ;;
  '--cloud info '*) printf 'ID: %s\nState: running\n' "$3" ;;
  '--cloud rm '*' --yes')
    event "delete-sandbox $3"
    jq --arg id "$3" 'map(select(.id != $id))' "$S/sandboxes.json" >"$S/next.json"
    mv "$S/next.json" "$S/sandboxes.json"
    printf 'Removal started\n' ;;
  *) printf 'fake cw: unexpected: %s\n' "$*" >&2; exit 91 ;;
esac
FAKE
  chmod 0755 "$1"
}

# A curl that answers the two Connect calls the walk makes itself, as Dev
# does: the organization listing, and UpdateAutoTopUp, which a member is
# refused. It takes the Authorization header only from stdin.
make_fake_curl() {
  cat >"$1" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_STATE/argv"
url="${*: -1}" body="" header=""
while (($# > 0)); do
  case "$1" in
    --data) body="$2"; shift 2 ;;
    -H) [[ "$2" != @- ]] || header="$(cat)"; shift 2 ;;
    *) shift ;;
  esac
done
[[ "$header" == "Authorization: Bearer $ACCESS_TOKEN" ]] || { printf '{"code":"unauthenticated"}\n401'; exit 0; }
case "$url" in
  https://codewire-dev.sh/codewire.v1.OrganizationService/ListOrganizations)
    printf 'list-organizations\n' >>"$MOCK_STATE/events"
    role=ORG_ROLE_MEMBER
    [[ "$MOCK_MODE" != walk_owner ]] || role=ORG_ROLE_OWNER
    jq -nc --arg id "$ORG_ID" --arg role "$role" \
      '{organizations: [{organization: {id: $id, slug: "codewire-dev-personal-walk"}, role: $role}]}'
    printf '\n200' ;;
  https://codewire-dev.sh/codewire.console.v1.BillingService/UpdateAutoTopUp)
    printf 'billing-write %s\n' "$body" >>"$MOCK_STATE/events"
    case "$MOCK_MODE" in
      billing_admitted) printf '{"amountCents":500}\n200' ;;
      billing_not_found) printf '{"code":"not_found","message":"organization not found"}\n404' ;;
      *) printf '{"code":"permission_denied","message":"forbidden"}\n403' ;;
    esac ;;
  *) exit 95 ;;
esac
FAKE
  chmod 0755 "$1"
}

# run_case NAME MODE EXPECT_STATUS [WALK ARGS...]. PROFILES, CREDENTIALS and
# SANDBOXES seed the account; SERVER_URL and WALK_EMAIL override the helper's
# environment.
run_case() {
  local name="$1" mode="$2" expect="$3"; shift 3
  CASE="$TEST_TMP/$name"
  mkdir -p "$CASE/state" "$CASE/cw-config"
  printf '%s\n' "${CREDENTIALS:-[]}" >"$CASE/state/credentials.json"
  printf '%s\n' "${PROFILES:-[]}" >"$CASE/state/profiles.json"
  printf '%s\n' "${SANDBOXES:-[]}" >"$CASE/state/sandboxes.json"
  : >"$CASE/state/events"
  : >"$CASE/state/argv"
  : >"$CASE/state/ids"
  : >"$CASE/state/keys"
  make_fake_cw "$CASE/cw"
  local status=0
  # Sleeping is the wait between cleanup retries; the fake answers at once.
  mkdir -p "$CASE/bin"
  printf '#!/bin/sh\nexit 0\n' >"$CASE/bin/sleep"
  chmod 0755 "$CASE/bin/sleep"
  make_fake_curl "$CASE/bin/curl"
  jq -n --arg token "$ACCESS_TOKEN" '{access_token: $token, refresh_token: "synthetic-refresh"}' \
    >"$CASE/cw-config/credentials.json"
  env -i PATH="$CASE/bin:$PATH" HOME="$CASE" MOCK_STATE="$CASE/state" MOCK_MODE="$mode" EMAIL="$EMAIL" \
    ACCESS_TOKEN="$ACCESS_TOKEN" ORG_ID="$ORG_ID" \
    CODEWIRE_SERVER_URL="${SERVER_URL-https://codewire-dev.sh}" CW_BIN="$CASE/cw" \
    CW_CONFIG_DIR="$CASE/cw-config" EXPECTED_PERSONAL_WALK_USER_EMAIL="${WALK_EMAIL-$EMAIL}" \
    bash "$WALK" "$@" >"$CASE/out" 2>"$CASE/err" || status=$?
  [[ "$status" == "$expect" ]] ||
    { cat "$CASE/out" "$CASE/err" >&2; fail "$name: exit $status, want $expect"; }
  local key
  while IFS= read -r key; do
    [[ "$key" =~ ^sk-ant-api03-CWCANARY-PERSONAL-WALK-[0-9]{8}t[0-9]{6}z-[0-9a-f]{6}$ ]] ||
      fail "$name: the walk added a key that is not the synthetic canary"
    ! grep -qF -- "$key" "$CASE/out" "$CASE/err" "$CASE/state/argv" ||
      fail "$name: the synthetic key reached output or argv"
  done <"$CASE/state/keys"
  ! grep -qF -- "$ACCESS_TOKEN" "$CASE/out" "$CASE/err" "$CASE/state/argv" ||
    fail "$name: the sign-in's access token reached output or argv"
}

expect_err() {
  grep -qF -- "$1" "$CASE/err" || { cat "$CASE/err" >&2; fail "$(basename "$CASE"): stderr lacks: $1"; }
}
expect_out() {
  grep -qF -- "$1" "$CASE/out" || { cat "$CASE/out" >&2; fail "$(basename "$CASE"): stdout lacks: $1"; }
}
expect_clean() { # only the anchor profile, empty and default, is left
  [[ "$(cat "$CASE/state/credentials.json")" == '[]' && "$(cat "$CASE/state/sandboxes.json")" == '[]' ]] ||
    fail "$(basename "$CASE"): a credential or Sandbox was left"
  jq -e 'length == 1 and .[0].name == "personal-walk-default" and .[0].is_default == true
    and .[0].entries == {}' "$CASE/state/profiles.json" >/dev/null ||
    fail "$(basename "$CASE"): the profiles left are $(jq -c . "$CASE/state/profiles.json")"
}
# The ids the walk deleted are exactly those it created, in a safe order.
expect_deleted_in_order() {
  local events
  events="$(sed -n 's/^\(delete-[a-z]*\) .*/\1/p' "$CASE/state/events" | tr '\n' ',')"
  [[ "$events" == "$1" ]] || fail "$(basename "$CASE"): deletions were [$events], want [$1]"
}
readonly ANCHOR='[{"id":"00000000-0000-4000-8000-0000000000aa","name":"personal-walk-default","is_default":true,"entries":{}}]'

run_case fresh_account success 0
expect_clean
expect_deleted_in_order 'delete-sandbox,delete-profile,delete-credential,'
expect_err 'making the empty default personal-walk-default'
expect_err 'PASS run='
expect_err 'walk_role=member billing_write_refused all_three_deleted_by_id'
expect_err "member of codewire-dev-personal-walk id=$ORG_ID"
expect_err 'billing write refused: UpdateAutoTopUp HTTP 403 code=permission_denied message=forbidden'
# The probe asks to keep top-up off, for the organization it is a member of,
# once the Sandbox exists and before anything is deleted.
grep -qxF "billing-write {\"orgId\":\"$ORG_ID\",\"enabled\":false,\"amountCents\":500}" "$CASE/state/events" ||
  fail 'fresh_account: the billing write was not the harmless UpdateAutoTopUp'
[[ "$(sed -n '/^create-sandbox /,$p' "$CASE/state/events" | sed -n '2,3p' | cut -d' ' -f1 | tr '\n' ,)" == 'list-organizations,billing-write,' ]] ||
  fail "fresh_account: the billing probe did not run between the create and the cleanup: $(tr '\n' , <"$CASE/state/events")"
sandbox="$(sed -n 's/^create-sandbox //p' "$CASE/state/events")"
[[ "$sandbox" =~ ^personal-walk-[0-9]{8}t[0-9]{6}z-[0-9a-f]{6}$ ]] || fail 'fresh_account: the Sandbox name lacks the walk and run id'
grep -q -- "--server https://codewire-dev.sh credentials --cloud --profile $sandbox set anthropic id:" "$CASE/state/argv" ||
  fail 'fresh_account: the profile was not named for the run'
grep -q -- "--cloud create --name $sandbox .*--profile $sandbox --yes$" "$CASE/state/argv" ||
  fail 'fresh_account: the Sandbox was not created with the profile'

PROFILES="$ANCHOR" run_case existing_anchor success 0
expect_clean
! grep -q 'profile-set personal-walk-default' "$CASE/state/events" || fail 'existing_anchor: the anchor was touched'

# A failed step still deletes what the walk made, by id.
PROFILES="$ANCHOR" run_case create_fails create_fails 1
expect_clean
expect_deleted_in_order 'delete-profile,delete-credential,'
expect_err 'cw create exited 1'

PROFILES="$ANCHOR" run_case profile_set_fails profile_set_fails 1
expect_clean
expect_deleted_in_order 'delete-credential,'

# An add whose answer was lost: the credential is found by its run's name and
# deleted by its id.
PROFILES="$ANCHOR" run_case add_lands_uncertain add_lands_uncertain 1
expect_clean
expect_deleted_in_order 'delete-credential,'

PROFILES="$ANCHOR" run_case add_fails add_fails 1
expect_clean
expect_deleted_in_order ''
! grep -q '^billing-write' "$CASE/state/events" || fail 'add_fails: the billing probe ran after a failed step'

# A billing write the server admits fails the walk, which still deletes what
# it made. So does any refusal but permission_denied, and an identity that is
# not a plain member, which is never sent the write.
PROFILES="$ANCHOR" run_case billing_admitted billing_admitted 1
expect_clean
expect_deleted_in_order 'delete-sandbox,delete-profile,delete-credential,'
expect_err 'a billing write as a member was not refused: HTTP 200 code=none message=none'
! grep -q 'PASS run=' "$CASE/err" || fail 'billing_admitted: the walk passed'
PROFILES="$ANCHOR" run_case billing_not_found billing_not_found 1
expect_clean
expect_err 'was not refused: HTTP 404 code=not_found message=organization not found'
PROFILES="$ANCHOR" run_case walk_owner walk_owner 1
expect_clean
expect_err 'must be a plain member of codewire-dev-personal-walk and nothing else'
! grep -q '^billing-write' "$CASE/state/events" || fail 'walk_owner: an owner was sent the billing write'

# Another walk's objects are never touched.
OTHER_CREDENTIAL='{"id":"00000000-0000-4000-8000-0000000000bb","name":"personal-walk-20261101t000000z-abcdef","provider":"anthropic"}'
PROFILES="$ANCHOR" CREDENTIALS="[$OTHER_CREDENTIAL]" run_case other_walk success 0
[[ "$(jq -c . "$CASE/state/credentials.json")" == "[$OTHER_CREDENTIAL]" ]] ||
  fail "other_walk: another walk's credential was touched"

# Only under the helper, only on Dev.
SERVER_URL=https://codewire.sh run_case production success 1
expect_err 'this walk is Dev only'
[[ ! -s "$CASE/state/argv" ]] || fail 'production: cw ran'
WALK_EMAIL='' run_case no_helper success 1
expect_err 'run under with-dev-personal-walk.sh'
[[ ! -s "$CASE/state/argv" ]] || fail 'no_helper: cw ran'

# The sweep reports what is older than a day or of unknown age, and deletes
# nothing.
recent="personal-walk-$(date -u +%Y%m%dt%H%M%Sz)-123456"
CREDENTIALS="[$OTHER_CREDENTIAL,{\"id\":\"c2\",\"name\":\"$recent\",\"provider\":\"anthropic\"},{\"id\":\"c3\",\"name\":\"someone-elses-key\",\"provider\":\"openai\"}]"
PROFILES='[{"id":"00000000-0000-4000-8000-0000000000aa","name":"personal-walk-default","is_default":true,"entries":{}},{"id":"p2","name":"personal-walk-20261101t000000z-abcdef","is_default":false,"entries":{}}]'
SANDBOXES='[{"id":"s1","name":"personal-walk-20261101t000000z-abcdef","placement":"cloud"}]'
before="$(printf '%s\n%s\n%s' "$CREDENTIALS" "$PROFILES" "$SANDBOXES" | jq -c .)"
CREDENTIALS="$CREDENTIALS" PROFILES="$PROFILES" SANDBOXES="$SANDBOXES" run_case sweep success 0 --sweep
expect_out 'SWEEP credential id=00000000-0000-4000-8000-0000000000bb name=personal-walk-20261101t000000z-abcdef stale'
expect_out 'SWEEP credential id=c3 name=someone-elses-key unknown'
expect_out 'SWEEP profile id=p2 name=personal-walk-20261101t000000z-abcdef stale'
expect_out 'SWEEP sandbox id=s1 name=personal-walk-20261101t000000z-abcdef stale'
! grep -qF "$recent" "$CASE/out" || fail 'sweep: a recent object was reported'
! grep -qF 'personal-walk-default' "$CASE/out" || fail 'sweep: the anchor was reported'
expect_err 'SWEEP stale=3 unknown_age=1 deleted=0'
after="$(cat "$CASE/state/credentials.json" "$CASE/state/profiles.json" "$CASE/state/sandboxes.json" | jq -c .)"
[[ "$before" == "$after" ]] || fail 'sweep: the account changed'
[[ ! -s "$CASE/state/events" ]] || fail 'sweep: it changed something or called the API'

printf 'personal-credentials-walk tests: PASS\n'
