#!/usr/bin/env bash
# Public-command doubles only: no login, Dev, provider, or VM calls.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091 # Guarded parent supplies public helper definitions.
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
# shellcheck disable=SC1091 # This test owns the dedicated new helper surface.
source "$REPO_ROOT/scripts/runtime/dev/provider-github-smoke.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cw-provider-github-tests.XXXXXXXX")"
TEST_OWNER="$BASHPID"
trap 'if [[ "$BASHPID" == "$TEST_OWNER" ]]; then find "$TEST_ROOT" -type f -delete; find "$TEST_ROOT" -depth -type d -empty -delete; fi' EXIT
COUNT=0
CREDENTIAL_ID=11111111-1111-4111-8111-111111111111
PROFILE_ID=22222222-2222-4222-8222-222222222222
ENVIRONMENT_ID=33333333-3333-4333-8333-333333333333
fail() { printf 'provider GitHub fixture: %s\n' "$*" >&2; exit 1; }
pass() { COUNT=$((COUNT + 1)); }

fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$TEST_ROOT/case.XXXXXXXX")"
  ENV_ID="$ENVIRONMENT_ID"
  PROVIDER_GITHUB_CREDENTIAL_ID="$CREDENTIAL_ID"
  PROVIDER_GITHUB_PROFILE_ID="$PROFILE_ID"
  PROVIDER_GITHUB_CREDENTIAL_NAME=owned-github
  PROVIDER_GITHUB_PROFILE_NAME=owned-profile
  FAILURE=''
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
    'run --no-tty -- /usr/bin/python3 /workspace/.cw-provider-github/provider-github-workload.py')
      [[ "$FAILURE" != run ]] || return 1
      if [[ "$FAILURE" == nul ]]; then printf 'CW_LIVE_GITHUB_OK\0\n'
      elif [[ "$FAILURE" != empty ]]; then printf 'CW_LIVE_GITHUB_OK\n'; fi
      [[ "$FAILURE" != stderr ]] || printf 'CW_LIVE_GITHUB_ERROR\n' >&2 ;;
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
run_provider_github_smoke
grep -qxF 'env info --local 33333333-3333-4333-8333-333333333333 --output json ' "$TMPDIR_SMOKE/calls" ||
  fail 'local environment binding used an ambiguous command'
grep -qxF 'run --no-tty -- /usr/bin/python3 /workspace/.cw-provider-github/provider-github-workload.py ' "$TMPDIR_SMOKE/calls" ||
  fail 'live workload used a positional platform environment'
pass
for failure in info wrong-id wrong-profile wrong-reference wrong-topology run empty nul stderr; do
  invalid_journey() { fixture; FAILURE="$failure"; run_provider_github_smoke; }
  expect_failure "$failure" invalid_journey
done

# Enrollment is exercised with exact public metadata and a visible (uncaptured)
# connect call. Substitute a deterministic nonce only within this subshell.
identity_journey() (
  fixture
  tr() { printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'; }
  cw() {
    printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
    case "$*" in
      'credentials --platform list --output json') printf '[]\n' ;;
      'credentials --platform profiles list --output json') printf '[]\n' ;;
      'credentials --platform connect github --name dev-github-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        printf 'owner-visible-device-prompt\n' ;;
      'credentials --platform get dev-github-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --output json')
        jq -n --arg id "$CREDENTIAL_ID" '[{id:$id,name:"dev-github-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          provider:"github",status:"CREDENTIAL_STATUS_ACTIVE",
          authenticationKind:"CREDENTIAL_AUTHENTICATION_KIND_OAUTH",accountHint:"fixture-owner"}]' |
          jq --arg failure "${IDENTITY_FAILURE:-}" '
            if $failure == "missing-hint" then del(.[0].accountHint)
            elif $failure == "hostile-hint" then .[0].accountHint="PRIVATE_CANARY\n"
            elif $failure == "wrong-provider" then .[0].provider="openai"
            elif $failure == "wrong-kind" then .[0].authenticationKind="CREDENTIAL_AUTHENTICATION_KIND_API_KEY"
            elif $failure == "duplicate" then . + . else . end' ;;
      'credentials --platform --profile dev-github-profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa set github id:'*) ;;
      'credentials --platform --profile dev-github-profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa get --output json')
        jq -n --arg id "$PROFILE_ID" --arg key "$CREDENTIAL_ID" '[{id:$id,
          name:"dev-github-profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",revision:"1",
          entries:[{capabilitySlot:"github",credentialId:$key}]}]' |
          jq --arg failure "${IDENTITY_FAILURE:-}" '
            if $failure == "wrong-revision" then .[0].revision="2"
            elif $failure == "extra-slot" then .[0].entries += [{capabilitySlot:"openai",credentialId:"unowned"}]
            elif $failure == "wrong-credential" then .[0].entries[0].credentialId="unowned"
            else . end' ;;
      *) fail "unexpected identity command: $*" ;;
    esac
  }
  prepare_provider_github
  [[ "$PROVIDER_GITHUB_CREDENTIAL_ID" == "$CREDENTIAL_ID" && "$PROVIDER_GITHUB_PROFILE_ID" == "$PROFILE_ID" ]]
  grep -qxF 'credentials --platform connect github --name dev-github-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ' "$TMPDIR_SMOKE/calls"
  jq -e --arg profile "platform:id:$PROFILE_ID" '.version == 1 and .working_directory == "/workspace" and
    (has("agents") | not) and .credentials == {profile:$profile} and
    (.install_command | contains("provider-github-workload.py") and contains("expected-login")) and
    .startup_script == "/bin/true"' "$PROVIDER_GITHUB_DOCUMENT" >/dev/null
)
identity_journey
pass
for IDENTITY_FAILURE in missing-hint hostile-hint wrong-provider wrong-kind duplicate wrong-revision extra-slot wrong-credential; do
  expect_failure "$IDENTITY_FAILURE" identity_journey
  ! grep -Fq PRIVATE_CANARY "$TEST_ROOT/failure.out" "$TEST_ROOT/failure.err" ||
    fail 'metadata rejection disclosed a hostile account hint'
done
unset IDENTITY_FAILURE

enrollment_cancelled() (
  fixture
  PROVIDER_GITHUB_CREDENTIAL_NAME=''; PROVIDER_GITHUB_CREDENTIAL_ID=''
  PROVIDER_GITHUB_PROFILE_NAME=''; PROVIDER_GITHUB_PROFILE_ID=''
  tr() { printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'; }
  cw() {
    printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
    case "$*" in
      'credentials --platform list --output json'|'credentials --platform profiles list --output json') printf '[]\n' ;;
      'credentials --platform connect github --name dev-github-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') return 130 ;;
      *) fail "command continued after cancelled enrollment: $*" ;;
    esac
  }
  prepare_provider_github_identity
)
expect_failure 'cancelled enrollment' enrollment_cancelled

name_collision() (
  fixture
  PROVIDER_GITHUB_CREDENTIAL_NAME=''; PROVIDER_GITHUB_PROFILE_NAME=''
  tr() { printf 'cccccccccccccccccccccccccccccccc\n'; }
  cw() {
    printf '%q ' "$@" >>"$TEST_ROOT/collision.calls"; printf '\n' >>"$TEST_ROOT/collision.calls"
    case "$*" in
      'credentials --platform list --output json')
        printf '[{"name":"dev-github-cccccccccccccccccccccccccccccccc"}]\n' ;;
      'credentials --platform profiles list --output json') printf '[]\n' ;;
      *) fail "collision permitted a mutation: $*" ;;
    esac
  }
  prepare_provider_github_identity
)
if name_collision >"$TEST_ROOT/collision.out" 2>"$TEST_ROOT/collision.err"; then
  fail 'preexisting credential name was accepted'
fi
[[ "$(wc -l <"$TEST_ROOT/collision.calls")" == 2 ]] || fail 'name collision reached a mutation'
pass

# Cleanup reconciles lost responses only by the prechecked exact names and IDs.
cleanup_cw() {
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'credentials --platform profiles list --output json')
      [[ "$FAILURE" != profile-list ]] || return 1
      if [[ -e "$TMPDIR_SMOKE/profile-deleted" ]]; then printf '[]\n'; else
        local id="$PROFILE_ID"; [[ "$FAILURE" != profile-rebound ]] || id="$CREDENTIAL_ID"
        jq -n --arg id "$id" '[{id:$id,name:"owned-profile"}]'
      fi ;;
    'credentials --platform --profile '*" delete --yes")
      [[ "$4" == "id:$PROFILE_ID" ]] || fail 'unowned profile deletion'
      touch "$TMPDIR_SMOKE/profile-deleted" ;;
    'credentials --platform list --output json')
      if [[ -e "$TMPDIR_SMOKE/credential-deleted" ]]; then printf '[]\n'; else
        local id="$CREDENTIAL_ID"; [[ "$FAILURE" != credential-rebound ]] || id="$PROFILE_ID"
        jq -n --arg id "$id" '[{id:$id,name:"owned-github"}]'
      fi ;;
    'credentials --platform get '*" --output json")
      local id="$CREDENTIAL_ID" status=CREDENTIAL_STATUS_ACTIVE kind=CREDENTIAL_AUTHENTICATION_KIND_OAUTH
      [[ "$FAILURE" != get-rebound ]] || id="$PROFILE_ID"
      [[ "$FAILURE" != wrong-kind ]] || kind=CREDENTIAL_AUTHENTICATION_KIND_API_KEY
      [[ "$FAILURE" != already-revoked ]] || status=CREDENTIAL_STATUS_REVOKED
      jq -n --arg id "$id" --arg status "$status" --arg kind "$kind" '[{id:$id,name:"owned-github",
        provider:"github",authenticationKind:$kind,status:$status}]' ;;
    'credentials --platform revoke '*)
      [[ "$4" == "id:$CREDENTIAL_ID" ]] || fail 'unowned credential revocation'
      touch "$TMPDIR_SMOKE/credential-revoked" ;;
    'credentials --platform delete '*" --yes")
      [[ "$4" == "id:$CREDENTIAL_ID" ]] || fail 'unowned credential deletion'
      touch "$TMPDIR_SMOKE/credential-deleted" ;;
    *) fail "unexpected cleanup command: $*" ;;
  esac
}
for failure in none profile-list profile-rebound credential-rebound get-rebound wrong-kind already-revoked; do
  fixture
  FAILURE="$failure"
  cw() { cleanup_cw "$@"; }
  if cleanup_provider_github; then
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

# Lost create/delete replies are reconciled from unique prechecked names. Blank
# IDs are populated from the exact collection metadata before any mutation.
fixture
PROVIDER_GITHUB_CREDENTIAL_ID=''; PROVIDER_GITHUB_PROFILE_ID=''
cw() { cleanup_cw "$@"; }
cleanup_provider_github || fail 'lost-response cleanup did not reconcile exact owned names'
[[ -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/credential-revoked" &&
  -e "$TMPDIR_SMOKE/credential-deleted" ]] || fail 'lost-response cleanup omitted an owned surface'
pass

# A mutation may commit while its reply is lost. Failure remains failure, but
# all independently owned retirement steps must still run.
for lost_reply in profile-delete revoke credential-delete; do
  fixture
  cw() {
    cleanup_cw "$@" || return
    case "$lost_reply:$*" in
      profile-delete:'credentials --platform --profile '*|revoke:'credentials --platform revoke '*|credential-delete:'credentials --platform delete '*) return 1 ;;
    esac
  }
  if cleanup_provider_github; then fail 'lost retirement reply concealed failure'; fi
  [[ -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/credential-deleted" ]] ||
    fail 'lost retirement reply skipped an independent surface'
  pass
done

# Execute the actual enrollment function with a terminal response lost after
# storage. Its EXIT owner resolves only the names prechecked before connect.
uncertain_enrollment() (
  fixture
  PROVIDER_GITHUB_CREDENTIAL_NAME=''; PROVIDER_GITHUB_CREDENTIAL_ID=''
  PROVIDER_GITHUB_PROFILE_NAME=''; PROVIDER_GITHUB_PROFILE_ID=''
  tr() { printf 'dddddddddddddddddddddddddddddddd\n'; }
  cw() {
    case "$*" in
      'credentials --platform profiles list --output json') printf '[]\n' ;;
      'credentials --platform list --output json')
        if [[ -e "$TMPDIR_SMOKE/committed" && ! -e "$TMPDIR_SMOKE/credential-deleted" ]]; then
          jq -n --arg id "$CREDENTIAL_ID" --arg name "$PROVIDER_GITHUB_CREDENTIAL_NAME" '[{id:$id,name:$name}]'
        else printf '[]\n'; fi ;;
      'credentials --platform connect github --name '*)
        touch "$TMPDIR_SMOKE/committed"; return 124 ;;
      'credentials --platform get '*)
        jq -n --arg id "$CREDENTIAL_ID" --arg name "$PROVIDER_GITHUB_CREDENTIAL_NAME" '[{id:$id,name:$name,provider:"github",
          authenticationKind:"CREDENTIAL_AUTHENTICATION_KIND_OAUTH",status:"CREDENTIAL_STATUS_ACTIVE"}]' ;;
      'credentials --platform revoke '*)
        [[ "$4" == "id:$CREDENTIAL_ID" ]] || fail 'uncertain enrollment revoked another identity'
        touch "$TMPDIR_SMOKE/credential-revoked" ;;
      'credentials --platform delete '*)
        [[ "$4" == "id:$CREDENTIAL_ID" ]] || fail 'uncertain enrollment deleted another identity'
        touch "$TMPDIR_SMOKE/credential-deleted" ;;
      *) fail 'unexpected uncertain enrollment command' ;;
    esac
  }
  trap 'cleanup_provider_github && test -e "$TMPDIR_SMOKE/credential-revoked" && test -e "$TMPDIR_SMOKE/credential-deleted" && printf "uncertain-cleanup-proved\n" >"$TEST_ROOT/uncertain-proof" || exit 99' EXIT
  prepare_provider_github_identity
)
expect_failure 'uncertain committed enrollment' uncertain_enrollment
[[ "$(cat "$TEST_ROOT/uncertain-proof")" == uncertain-cleanup-proved ]] || fail 'uncertain enrollment did not retire stored identity'
pass

source_text="$(cat "$REPO_ROOT/scripts/runtime/dev/provider-github-smoke.sh")"
# shellcheck disable=SC2016 # Match literal source variable expansion.
grep -qF 'cw_with_timeout 600 credentials --platform connect github --name "$PROVIDER_GITHUB_CREDENTIAL_NAME"' <<<"$source_text" ||
  fail 'normal public GitHub enrollment command drifted'
if grep -E 'connect github.*(>|2>)' <<<"$source_text"; then
  fail 'owner-visible device prompt was redirected'
fi
# shellcheck disable=SC2016 # Match literal source variable expansion.
grep -qF 'set github "id:$PROVIDER_GITHUB_CREDENTIAL_ID"' <<<"$source_text" ||
  fail 'profile does not select the exact metadata ID'
if grep -Eq 'credentials.*(add|import).*github|GITHUB_HOME|OPENAI_API_KEY|--model' <<<"$source_text"; then
  fail 'host helper contains an ambient/raw/model override path'
fi
pass
printf 'provider GitHub smoke fixtures passed (%s cases; no live calls)\n' "$COUNT"
