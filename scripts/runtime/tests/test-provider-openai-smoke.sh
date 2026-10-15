#!/usr/bin/env bash
# Public-command doubles only: no login, Dev, provider, or VM calls.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091 # Guarded parent supplies public helper definitions.
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
# shellcheck disable=SC1091 # This test owns the dedicated new helper surface.
source "$REPO_ROOT/scripts/runtime/dev/provider-openai-smoke.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cw-provider-openai-tests.XXXXXXXX")"
TEST_OWNER="$BASHPID"
trap 'if [[ "$BASHPID" == "$TEST_OWNER" ]]; then find "$TEST_ROOT" -type f -delete; find "$TEST_ROOT" -depth -type d -empty -delete; fi' EXIT
COUNT=0
CREDENTIAL_ID=11111111-1111-4111-8111-111111111111
PROFILE_ID=22222222-2222-4222-8222-222222222222
ENVIRONMENT_ID=33333333-3333-4333-8333-333333333333
fail() { printf 'provider OpenAI fixture: %s\n' "$*" >&2; exit 1; }
pass() { COUNT=$((COUNT + 1)); }

fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$TEST_ROOT/case.XXXXXXXX")"
  ENV_ID="$ENVIRONMENT_ID"
  PROVIDER_OPENAI_CREDENTIAL_ID="$CREDENTIAL_ID"
  PROVIDER_OPENAI_PROFILE_ID="$PROFILE_ID"
  PROVIDER_OPENAI_CREDENTIAL_NAME=owned-openai
  PROVIDER_OPENAI_PROFILE_NAME=owned-profile
  FAILURE=''
  LOCAL_PLATFORM_OPENAI_MODEL=fixture-model-v1
  : >"$TMPDIR_SMOKE/calls"
}

cw_with_timeout() { shift; cw "$@"; }
cw() {
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'env info --local '*" --output json")
      local id="$ENV_ID" profile="platform:id:$PROFILE_ID" reference=user/owned-profile cpu=2 memory=16Gi
      [[ "$FAILURE" != info ]] || return 1
      [[ "$FAILURE" != wrong-id ]] || id="$PROFILE_ID"
      [[ "$FAILURE" != wrong-profile ]] || profile="platform:id:$CREDENTIAL_ID"
      [[ "$FAILURE" != wrong-reference ]] || reference=user/replacement
      [[ "$FAILURE" != wrong-topology ]] || cpu=4
      jq -n --arg id "$id" --arg profile "$profile" --arg reference "$reference" \
        --argjson cpu "$cpu" --arg memory "$memory" '{id:$id,backend:"cloud-hypervisor",state:"running",
        cpu:$cpu,memory:$memory,source_selection:{credentials:{profile:$profile,reference:$reference,revision:1}}}' ;;
    'run --no-tty -- /bin/bash -c '*)
      # shellcheck disable=SC2016 # Assert the literal fixed guest command.
      [[ "$#" == 9 && "$6" == 'ulimit -S -c 0 && ulimit -H -c 0 && exec /usr/bin/timeout --kill-after=5s 120s /usr/bin/python3 -I -B "$1" "$2"' &&
        "$7" == codewire-live-openai && "$8" == /workspace/.cw-provider-openai/provider-openai-workload.py &&
        "$9" == fixture-model-v1 ]] || fail 'workload command/model/deadline drifted'
      [[ "$FAILURE" != run ]] || return 1
      if [[ "$FAILURE" == nul ]]; then printf 'CW_LIVE_OPENAI_OK\0\n'
      elif [[ "$FAILURE" != empty ]]; then printf 'CW_LIVE_OPENAI_OK\n'; fi
      printf 'Launched session session-6e3e8f6a-fa62-4128-9dad-bf1e42778613\n' >&2
      if [[ "$FAILURE" == notice-nul ]]; then printf '\0' >&2; fi
      if [[ "$FAILURE" == notice-duplicate ]]; then printf 'Launched session session-6e3e8f6a-fa62-4128-9dad-bf1e42778613\n' >&2; fi
      [[ "$FAILURE" != stderr ]] || printf 'CW_LIVE_OPENAI_ERROR\n' >&2 ;;
    *) fail "unexpected public command: $*" ;;
  esac
}

expect_failure() {
  local label="$1"; shift
  if ( "$@" ) >"$TEST_ROOT/failure.out" 2>"$TEST_ROOT/failure.err"; then
    fail "$label accepted invalid input"
  fi
  pass
}

fixture
run_provider_openai_smoke
grep -qxF 'env info --local 33333333-3333-4333-8333-333333333333 --output json ' "$TMPDIR_SMOKE/calls" ||
  fail 'local environment binding used an ambiguous command'
pass
for failure in info wrong-id wrong-profile wrong-reference wrong-topology run empty nul stderr notice-nul notice-duplicate; do
  invalid_journey() { fixture; FAILURE="$failure"; run_provider_openai_smoke; }
  expect_failure "$failure" invalid_journey
done

# Enrollment is exercised with exact public metadata. The synthetic add result
# is intentionally not redirected, matching the owner-visible hidden prompt.
identity_journey() (
  fixture
  tr() { printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'; }
  cw() {
    printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
    case "$*" in
      'credentials --cloud list --output json') printf '[]\n' ;;
      'credentials --cloud profiles list --output json') printf '[]\n' ;;
      'credentials --cloud add openai --name dev-openai-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        printf 'owner-visible-hidden-prompt\n' ;;
      'credentials --cloud get dev-openai-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --output json')
        jq -n --arg id "$CREDENTIAL_ID" '[{id:$id,name:"dev-openai-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          provider:"openai",status:"CREDENTIAL_STATUS_ACTIVE",
          authenticationKind:"CREDENTIAL_AUTHENTICATION_KIND_API_KEY"}]' ;;
      'credentials --cloud --profile dev-openai-profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa set openai id:'*) ;;
      'credentials --cloud --profile dev-openai-profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa get --output json')
        jq -n --arg id "$PROFILE_ID" --arg key "$CREDENTIAL_ID" '[{id:$id,
          name:"dev-openai-profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",revision:"1",
          entries:[{capabilitySlot:"openai",credentialId:$key}]}]' ;;
      *) fail "unexpected identity command: $*" ;;
    esac
  }
  prepare_provider_openai
  [[ "$PROVIDER_OPENAI_CREDENTIAL_ID" == "$CREDENTIAL_ID" &&
    "$PROVIDER_OPENAI_PROFILE_ID" == "$PROFILE_ID" ]]
  grep -qxF 'credentials --cloud add openai --name dev-openai-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ' "$TMPDIR_SMOKE/calls"
  jq -e --arg profile "platform:id:$PROFILE_ID" '.version == 1 and .working_directory == "/workspace" and
    .agents == null and .credentials == {profile:$profile} and
    (.install_command | contains("provider-openai-workload.py")) and
    .startup_script == "/bin/true"' "$PROVIDER_OPENAI_DOCUMENT" >/dev/null
)
identity_journey
pass

enrollment_cancelled() (
  fixture
  PROVIDER_OPENAI_CREDENTIAL_NAME=''; PROVIDER_OPENAI_CREDENTIAL_ID=''
  PROVIDER_OPENAI_PROFILE_NAME=''; PROVIDER_OPENAI_PROFILE_ID=''
  tr() { printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'; }
  cw() {
    printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
    case "$*" in
      'credentials --cloud list --output json'|'credentials --cloud profiles list --output json') printf '[]\n' ;;
      'credentials --cloud add openai --name dev-openai-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') return 130 ;;
      *) fail "command continued after cancelled enrollment: $*" ;;
    esac
  }
  prepare_provider_openai_identity
)
expect_failure 'cancelled enrollment' enrollment_cancelled

name_collision() (
  fixture
  PROVIDER_OPENAI_CREDENTIAL_NAME=''; PROVIDER_OPENAI_PROFILE_NAME=''
  tr() { printf 'cccccccccccccccccccccccccccccccc\n'; }
  cw() {
    printf '%q ' "$@" >>"$TEST_ROOT/collision.calls"; printf '\n' >>"$TEST_ROOT/collision.calls"
    case "$*" in
      'credentials --cloud list --output json')
        printf '[{"name":"dev-openai-cccccccccccccccccccccccccccccccc"}]\n' ;;
      'credentials --cloud profiles list --output json') printf '[]\n' ;;
      *) fail "collision permitted a mutation: $*" ;;
    esac
  }
  prepare_provider_openai_identity
)
if name_collision >"$TEST_ROOT/collision.out" 2>"$TEST_ROOT/collision.err"; then
  fail 'preexisting credential name was accepted'
fi
[[ "$(wc -l <"$TEST_ROOT/collision.calls")" == 2 ]] || fail 'name collision reached a mutation'
pass

cleanup_cw() {
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'credentials --cloud profiles list --output json')
      [[ "$FAILURE" != profile-list ]] || return 1
      if [[ -e "$TMPDIR_SMOKE/profile-deleted" ]]; then printf '[]\n'; else
        local id="$PROFILE_ID"; [[ "$FAILURE" != profile-rebound ]] || id="$CREDENTIAL_ID"
        jq -n --arg id "$id" '[{id:$id,name:"owned-profile"}]'
      fi ;;
    'credentials --cloud --profile '*" delete --yes")
      [[ "$4" == "id:$PROFILE_ID" ]] || fail 'unowned profile deletion'
      touch "$TMPDIR_SMOKE/profile-deleted" ;;
    'credentials --cloud list --output json')
      if [[ -e "$TMPDIR_SMOKE/credential-deleted" ]]; then printf '[]\n'; else
        local id="$CREDENTIAL_ID"; [[ "$FAILURE" != credential-rebound ]] || id="$PROFILE_ID"
        jq -n --arg id "$id" '[{id:$id,name:"owned-openai"}]'
      fi ;;
    'credentials --cloud get '*" --output json")
      local id="$CREDENTIAL_ID" status=CREDENTIAL_STATUS_ACTIVE kind=CREDENTIAL_AUTHENTICATION_KIND_API_KEY
      [[ "$FAILURE" != get-rebound ]] || id="$PROFILE_ID"
      [[ "$FAILURE" != wrong-kind ]] || kind=CREDENTIAL_AUTHENTICATION_KIND_OAUTH
      [[ "$FAILURE" != already-revoked ]] || status=CREDENTIAL_STATUS_REVOKED
      jq -n --arg id "$id" --arg status "$status" --arg kind "$kind" '[{id:$id,name:"owned-openai",
        provider:"openai",authenticationKind:$kind,status:$status}]' ;;
    'credentials --cloud revoke '*)
      [[ "$4" == "id:$CREDENTIAL_ID" ]] || fail 'unowned credential revocation'
      touch "$TMPDIR_SMOKE/credential-revoked" ;;
    'credentials --cloud delete '*" --yes")
      [[ "$4" == "id:$CREDENTIAL_ID" ]] || fail 'unowned credential deletion'
      touch "$TMPDIR_SMOKE/credential-deleted" ;;
    *) fail "unexpected cleanup command: $*" ;;
  esac
}
for failure in none profile-list profile-rebound credential-rebound get-rebound wrong-kind already-revoked; do
  fixture
  FAILURE="$failure"
  cw() { cleanup_cw "$@"; }
  if cleanup_provider_openai; then
    [[ "$failure" == none || "$failure" == already-revoked ]] || fail 'cleanup failure was hidden'
  else
    [[ "$failure" != none && "$failure" != already-revoked ]] || fail 'owned cleanup failed'
  fi
  case "$failure" in
    profile-list|profile-rebound)
      [[ ! -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/credential-revoked" &&
        -e "$TMPDIR_SMOKE/credential-deleted" ]] || fail 'profile failure skipped credential retirement' ;;
    credential-rebound|get-rebound|wrong-kind)
      [[ -e "$TMPDIR_SMOKE/profile-deleted" && ! -e "$TMPDIR_SMOKE/credential-revoked" &&
        ! -e "$TMPDIR_SMOKE/credential-deleted" ]] || fail 'credential ownership fence failed' ;;
    already-revoked)
      [[ -e "$TMPDIR_SMOKE/profile-deleted" && ! -e "$TMPDIR_SMOKE/credential-revoked" &&
        -e "$TMPDIR_SMOKE/credential-deleted" ]] || fail 'revoked cleanup was not idempotent' ;;
    none)
      [[ -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/credential-revoked" &&
        -e "$TMPDIR_SMOKE/credential-deleted" ]] || fail 'owned cleanup incomplete' ;;
  esac
  pass
done

fixture
PROVIDER_OPENAI_CREDENTIAL_ID=''; PROVIDER_OPENAI_PROFILE_ID=''
cw() { cleanup_cw "$@"; }
cleanup_provider_openai || fail 'lost-response cleanup did not reconcile exact owned names'
[[ -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/credential-revoked" &&
  -e "$TMPDIR_SMOKE/credential-deleted" ]] || fail 'lost-response cleanup omitted an owned surface'
pass

source_text="$(cat "$REPO_ROOT/scripts/runtime/dev/provider-openai-smoke.sh")"
# shellcheck disable=SC2016 # Match literal source variable expansion.
grep -qF 'cw_with_timeout 600 credentials --cloud add openai --name "$PROVIDER_OPENAI_CREDENTIAL_NAME"' <<<"$source_text" ||
  fail 'normal public OpenAI enrollment command drifted'
if grep -E 'add openai.*(>|2>)' <<<"$source_text"; then
  fail 'owner-hidden credential prompt was redirected'
fi
# shellcheck disable=SC2016 # Match literal source variable expansion.
grep -qF 'set openai "id:$PROVIDER_OPENAI_CREDENTIAL_ID"' <<<"$source_text" ||
  fail 'profile does not select the exact metadata ID'
if grep -Eq 'credentials.*(connect|import).*openai|OPENAI_(API_KEY|AUTH_TOKEN)|--model|--key-file' <<<"$source_text"; then
  fail 'host helper contains an ambient/raw/model override path'
fi
pass
# Invalid model choices must stop before even a metadata read or hidden input.
for bad_model in '' '-leading' 'with space' 'a/b' $'line\nbreak' "$(printf 'x%.0s' {1..129})"; do
  invalid_model() {
    fixture
    LOCAL_PLATFORM_OPENAI_MODEL="$bad_model"
    cw() { fail 'invalid model reached a public command'; }
    prepare_provider_openai_identity
  }
  expect_failure 'invalid model' invalid_model
done
printf 'provider OpenAI smoke fixtures passed (%s cases; no live calls)\n' "$COUNT"
