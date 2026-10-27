#!/usr/bin/env bash
# Public-command fixtures only: no login, live Dev, key reader or SSH server.
# shellcheck disable=SC2034 # Inputs consumed by sourced smoke functions.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091 # The guarded product script is sourced without running main.
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cw-provider-ssh-tests.XXXXXXXX")"
TEST_OWNER="$BASHPID"
trap 'if [[ "$BASHPID" == "$TEST_OWNER" ]]; then rm -rf -- "$TEST_ROOT"; fi' EXIT
COUNT=0
KEY_ID=11111111-1111-4111-8111-111111111111
PROFILE_ID=22222222-2222-4222-8222-222222222222
HOST_KEY='[127.0.0.1]:22222 ssh-ed25519 AAAATestPublicHostMetadata'
fail() { printf 'provider SSH fixture: %s\n' "$*" >&2; exit 1; }
pass() { COUNT=$((COUNT + 1)); }
fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$TEST_ROOT/case.XXXXXXXX")"
  SMOKE_ONLY_PHASES=(provider-ssh); SMOKE_AUTH_MODE=admin-oidc
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$TMPDIR_SMOKE/fresh-login"
  EXPECTED_CODEWIRE_ADMIN_EMAIL=synthetic@example.invalid
  CODEWIRE_SERVER_URL=https://synthetic.invalid; EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
  ALLOW_NON_DEV=0; ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=0
  SMOKE_EXISTING_ENV_ID=''; SMOKE_KEEP_ENV=0; SMOKE_SKIP_KUBE=0
  SANDBOX_NAMESPACE=synthetic; SMOKE_NAME=synthetic-ssh
  SMOKE_TIMEOUT_SECONDS=1; SMOKE_EXEC_TIMEOUT=1
  ENV_ID=33333333-3333-4333-8333-333333333333
  PROVIDER_SSH_CREDENTIAL_ID="$KEY_ID"
  PROVIDER_SSH_PROFILE_ID="$PROFILE_ID"
  unset CODEWIRE_API_KEY CODEWIRE_DEV_SMOKE_API_KEY
  FAILURE=''
  : >"$TMPDIR_SMOKE/calls"
}
cw_with_timeout() { shift; cw "$@"; }
# shellcheck disable=SC2329 # Invoked indirectly by the sourced workflow through cw_with_timeout.
cw() {
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    '--cloud info '*" --output json")
      [[ "$3" == "$ENV_ID" ]] || fail 'inspected a different environment'
      [[ "$FAILURE" != info ]] || return 1
      local id="$ENV_ID" profile="platform:id:$PROFILE_ID" revision=1
      [[ "$FAILURE" != wrong-environment ]] || id="$KEY_ID"
      [[ "$FAILURE" != wrong-profile ]] || profile="platform:id:$KEY_ID"
      [[ "$FAILURE" != wrong-revision ]] || revision=2
      [[ "$FAILURE" != missing-revision ]] || revision=null
      jq -n --arg id "$id" --arg profile "$profile" --argjson revision "$revision" \
        '{id:$id,source_selection:{credentials:{profile:$profile},profile_revision:$revision}}' ;;
    'run --no-tty '*" public-host-key") printf '%s\n' "$HOST_KEY" ;;
    'run --no-tty '*" prove "*)
      [[ "$9" == "$HOST_KEY" ]] || fail 'changed host trust'
      [[ "$FAILURE" != proof ]] || return 1
      [[ "$FAILURE" == empty-proof ]] || printf 'stock-ssh-workload-proved\n' ;;
    'run --no-tty '*" /bin/cat /workspace/.cw-ssh-smoke/sshd.log")
      printf 'synthetic public-only sshd evidence\n' ;;
    'run --no-tty --detach --output json '*" wait-revoked "*)
      [[ ! -e "$TMPDIR_SMOKE/revoked" ]] || fail 'probe admitted after revocation'
      [[ "${12}" == "$HOST_KEY" ]] || fail 'waiter lost host trust'
      touch "$TMPDIR_SMOKE/admitted"
      printf '{"session_id":"owned-session","state":"Running"}\n' ;;
    'credentials --cloud revoke '*" --output json")
      [[ -e "$TMPDIR_SMOKE/ready" ]] || fail 'revoke occurred before probe readiness'
      [[ "$4" == "id:$KEY_ID" ]] || fail 'different credential revoked'
      touch "$TMPDIR_SMOKE/revoked"
      if [[ "$FAILURE" == bad-revoke ]]; then printf '[]\n'; else
        jq -n --arg id "$KEY_ID" '[{id:$id,status:"CREDENTIAL_STATUS_REVOKED",revocationGeneration:"2"}]'
      fi ;;
    '--cloud cp '*)
      [[ -e "$TMPDIR_SMOKE/revoked" && "$4" == "$ENV_ID:/workspace/.cw-ssh-smoke/revoked-trigger" ]] ||
        fail 'wrong trigger ordering or destination'
      [[ "$(cat "$3")" == revoked ]] || fail 'wrong trigger bytes'
      touch "$TMPDIR_SMOKE/triggered" ;;
    'logs '*" --raw")
      [[ "$3" == --session && "$4" == owned-session ]] || fail 'read a different session'
      if [[ -e "$TMPDIR_SMOKE/triggered" ]]; then
        [[ "$FAILURE" == empty-denial ]] || printf 'stock-ssh-workload-revoked\n'
      else
        [[ -e "$TMPDIR_SMOKE/admitted" ]] || fail 'unadmitted session'
        touch "$TMPDIR_SMOKE/ready"
        printf 'stock-ssh-workload-awaiting-revocation\n'
      fi ;;
    'ls '*" --output json")
      [[ -e "$TMPDIR_SMOKE/triggered" ]] || fail 'completion before trigger'
      [[ "$FAILURE" != denial ]] || return 1
      printf '[{"session_id":"owned-session","state":"Exited","exit_code":0}]\n' ;;
    'run --no-tty --detach --output json '*" -- /bin/true")
      [[ -e "$TMPDIR_SMOKE/triggered" ]] || fail 'new-launch probe before revocation'
      if [[ "$FAILURE" == new-launch ]]; then printf '{"state":"Running"}\n'; else
        printf '{"state":"Failed","exit_code":null,"status_message":"environment launch denied or expired"}\n'
      fi ;;
    *) fail "unexpected public command: $*" ;;
  esac
}
run_kube_assertions() { :; }
wait_for_cw_run() { :; }
wait_until() { shift 2; "$@" || die 'synthetic fixture condition failed'; }
expect_failure() {
  local label="$1"; shift
  if ( "$@" ) >"$TEST_ROOT/failure.out" 2>"$TEST_ROOT/failure.err"; then fail "$label accepted invalid input"; fi
  pass
}
fixture
provider_ssh_selected
validate_provider_ssh_options
pass
for invalid in api-key inherited-key default-login missing-email wrong-origin existing keep no-kube mixed; do
  invalid_options() {
    fixture
    case "$invalid" in
      api-key) SMOKE_AUTH_MODE=api-key ;;
      inherited-key) CODEWIRE_API_KEY=synthetic ;;
      default-login) CODEWIRE_ADMIN_OAUTH_CONFIG_DIR='' ;;
      missing-email) EXPECTED_CODEWIRE_ADMIN_EMAIL='' ;;
      wrong-origin) CODEWIRE_SERVER_URL=https://wrong.invalid ;;
      existing) SMOKE_EXISTING_ENV_ID=unowned ;;
      keep) SMOKE_KEEP_ENV=1 ;;
      no-kube) SMOKE_SKIP_KUBE=1 ;;
      mixed) SMOKE_ONLY_PHASES=(provider-ssh application-secrets) ;;
    esac
    validate_provider_ssh_options
  }
  expect_failure "$invalid" invalid_options
done
fixture
run_provider_ssh_smoke
pass
for failure in info wrong-environment wrong-profile wrong-revision missing-revision \
    proof empty-proof bad-revoke denial empty-denial new-launch; do
  invalid_journey() { fixture; FAILURE="$failure"; run_provider_ssh_smoke; }
  expect_failure "$failure" invalid_journey
done
# Profile enumeration must use the existing collection command. A selected
# profile followed by list is an alias for Get, so it fails for a fresh name.
profile_calls="$(declare -f prepare_provider_ssh_identity cleanup_provider_ssh_profile)"
[[ "$(grep -cF 'credentials --cloud profiles list --output json' <<<"$profile_calls")" == 3 ]]
if grep -E 'credentials --cloud --profile .* list --output json' <<<"$profile_calls"; then
  fail 'selected-profile Get used as collection enumeration'
fi
pass
# A disposable profile is made only beside an existing default, which it can
# never become (#3550); every provider smoke shares this check.
printf '[{"name":"lasting","isDefault":true},{"name":"other"}]\n' >"$TEST_ROOT/profiles.json"
provider_account_has_default_profile "$TEST_ROOT/profiles.json" || fail 'an existing default profile was not found'
for listing in '[]' '[{"name":"other","isDefault":false}]' '[{"name":"other"}]' '{}' ''; do
  printf '%s\n' "$listing" >"$TEST_ROOT/profiles.json"
  if provider_account_has_default_profile "$TEST_ROOT/profiles.json" 2>/dev/null; then
    fail "a profile list without a default was accepted: $listing"
  fi
done
# shellcheck disable=SC2016 # The literal source text of the check.
grep -qF 'provider_account_has_default_profile "$TMPDIR_SMOKE/provider-ssh-profiles-before.json"' \
  <<<"$(declare -f prepare_provider_ssh_identity)" || fail 'SSH identity skipped the default-profile check'
pass

# Failure on one cleanup surface still retires the other owned surface; an
# identity mismatch never authorizes a mutation of the replacement object.
cw() {
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'credentials --cloud profiles list --output json')
      [[ "$FAILURE" != profile-list ]] || return 1
      if [[ -e "$TMPDIR_SMOKE/profile-deleted" ]]; then printf '[]\n'; else
        local id="$PROFILE_ID"
        [[ "$FAILURE" != profile-rebound ]] || id="$KEY_ID"
        jq -n --arg id "$id" '[{id:$id,name:"owned-profile"}]'
      fi ;;
    'credentials --cloud --profile '*" delete --yes")
      [[ "$4" == "id:$PROFILE_ID" ]] || fail 'unowned profile deletion'
      touch "$TMPDIR_SMOKE/profile-deleted" ;;
    'credentials --cloud list --output json')
      if [[ -e "$TMPDIR_SMOKE/key-deleted" ]]; then printf '[]\n'; else
        local id="$KEY_ID"
        [[ "$FAILURE" != key-rebound ]] || id="$PROFILE_ID"
        jq -n --arg id "$id" '[{id:$id,name:"owned-key"}]'
      fi ;;
    'credentials --cloud get '*" --output json")
      local id="$KEY_ID" status=CREDENTIAL_STATUS_ACTIVE
      [[ "$FAILURE" != key-get-rebound ]] || id="$PROFILE_ID"
      [[ "$FAILURE" != already-revoked ]] || status=CREDENTIAL_STATUS_REVOKED
      jq -n --arg id "$id" --arg status "$status" '[{id:$id,name:"owned-key",status:$status}]' ;;
    'credentials --cloud revoke '*)
      [[ "$4" == "id:$KEY_ID" ]] || fail 'unowned key revocation'
      touch "$TMPDIR_SMOKE/key-revoked" ;;
    'credentials --cloud delete '*" --yes")
      [[ "$4" == "id:$KEY_ID" ]] || fail 'unowned key deletion'
      touch "$TMPDIR_SMOKE/key-deleted" ;;
    *) fail "unexpected cleanup command: $*" ;;
  esac
}
for failure in none profile-list profile-rebound key-rebound key-get-rebound already-revoked; do
  fixture
  FAILURE="$failure"; ENV_ID=''; PROVIDER_SSH_CREATE_ATTEMPTED=0
  PROVIDER_SSH_CREDENTIAL_NAME=owned-key; PROVIDER_SSH_PROFILE_NAME=owned-profile
  PROVIDER_SSH_PROFILE_ID="$PROFILE_ID"
  if cleanup_provider_ssh; then
    [[ "$failure" == none || "$failure" == already-revoked ]] || fail 'cleanup failure was hidden'
  else
    [[ "$failure" != none && "$failure" != already-revoked ]] || fail 'owned cleanup failed'
  fi
  case "$failure" in
    profile-list|profile-rebound)
      [[ ! -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/key-revoked" &&
         -e "$TMPDIR_SMOKE/key-deleted" ]] || fail 'profile failure skipped independent key retirement' ;;
    key-rebound|key-get-rebound)
      [[ -e "$TMPDIR_SMOKE/profile-deleted" && ! -e "$TMPDIR_SMOKE/key-revoked" &&
         ! -e "$TMPDIR_SMOKE/key-deleted" ]] || fail 'key identity fence failed' ;;
    already-revoked)
      [[ -e "$TMPDIR_SMOKE/profile-deleted" && ! -e "$TMPDIR_SMOKE/key-revoked" &&
         -e "$TMPDIR_SMOKE/key-deleted" ]] || fail 'revoked cleanup was not idempotent' ;;
    none)
      [[ -e "$TMPDIR_SMOKE/profile-deleted" && -e "$TMPDIR_SMOKE/key-revoked" &&
         -e "$TMPDIR_SMOKE/key-deleted" ]] || fail 'owned cleanup incomplete' ;;
  esac
  pass
done
# Exercise the exact checked-in diagnostic parser without starting a server.
# shellcheck disable=SC1090
source <(sed -n '/^has_diagnostic_line() {$/,/^}$/p' \
  "$REPO_ROOT/scripts/ci/verify/stock-ssh-workload.sh")
# shellcheck disable=SC1090
source <(sed -n '/^strict_modes_component_state() {$/,/^}$/p' \
  "$REPO_ROOT/scripts/ci/verify/stock-ssh-workload.sh")
# shellcheck disable=SC1090
source <(sed -n '/^authorized_keys_command_failure() {$/,/^}$/p' \
  "$REPO_ROOT/scripts/ci/verify/stock-ssh-workload.sh")
for expected in 'Host key verification failed.' 'codewire@127.0.0.1: Permission denied (publickey).'; do
  for ending in '\n' '\r\n'; do
    printf '%s%b' "$expected" "$ending" >"$TEST_ROOT/diagnostic"
    has_diagnostic_line "$expected" "$TEST_ROOT/diagnostic" || fail 'exact LF/CRLF denial was rejected'
    pass
  done
done
[[ "$(strict_modes_component_state 1000 700 1000)" == safe ]] ||
  fail 'owned private authorization component was rejected'
[[ "$(strict_modes_component_state 0 755 1000)" == safe ]] ||
  fail 'root-owned immutable authorization component was rejected'
[[ "$(strict_modes_component_state 1000 770 1000)" == unsafe ]] ||
  fail 'group-writable authorization ancestor was admitted'
[[ "$(strict_modes_component_state 2000 755 1000)" == unsafe ]] ||
  fail 'foreign-owned authorization ancestor was admitted'
printf 'AuthorizedKeysCommand command exited with status 13\n' >"$TEST_ROOT/helper.log"
[[ "$(authorized_keys_command_failure "$TEST_ROOT/helper.log")" == 'helper-exit 13' ]] ||
  fail 'numeric authorization helper exit was not classified'
printf 'AuthorizedKeysCommand failed during setresuid\n' >"$TEST_ROOT/helper.log"
[[ "$(authorized_keys_command_failure "$TEST_ROOT/helper.log")" == 'helper-identity unknown' ]] ||
  fail 'authorization helper identity failure was not classified'
printf 'Failed publickey for codewire\n' >"$TEST_ROOT/helper.log"
[[ "$(authorized_keys_command_failure "$TEST_ROOT/helper.log")" == 'not-reported none' ]] ||
  fail 'generic public-key denial was mistaken for a helper failure'
stock_ssh_source="$(cat -- "$REPO_ROOT/scripts/ci/verify/stock-ssh-workload.sh")"
# shellcheck disable=SC2016 # These contracts intentionally match literal shell variables.
grep -qF 'readonly AUTHORIZED_KEYS="$STATE_ROOT/authorized_keys"' <<<"$stock_ssh_source" ||
  fail 'public authorization is not retained in owned fixture state'
[[ "$(grep -cF '  prepare_authorization' <<<"$stock_ssh_source")" == 2 ]] ||
  fail 'install and restart do not both validate public authorization'
# shellcheck disable=SC2016 # Match the literal variable reference.
grep -qxF 'AuthorizedKeysCommand /usr/bin/cat $AUTHORIZED_KEYS' <<<"$stock_ssh_source" ||
  fail 'sshd does not use the stock root-owned public authorization helper'
# shellcheck disable=SC2016 # Match the literal variable reference.
grep -qxF 'AuthorizedKeysCommandUser $TARGET_USER' <<<"$stock_ssh_source" ||
  fail 'authorization helper does not run as the normal target account'
grep -qxF 'AuthorizedKeysFile none' <<<"$stock_ssh_source" ||
  fail 'group-writable PVC ancestry still participates in strict file authorization'
grep -qF 'stock authorization command path is unsafe' <<<"$stock_ssh_source" ||
  fail 'root-owned authorization command path is not checked before launch'
pass
for rejected in 'prefix Host key verification failed.' 'Host key verification failed. ' \
  'Connection refused.' $'Host key verification failed.\r\r'; do
  printf '%s\n' "$rejected" >"$TEST_ROOT/diagnostic"
  if has_diagnostic_line 'Host key verification failed.' "$TEST_ROOT/diagnostic"; then
    fail 'inexact or unrelated denial was accepted'
  fi
  pass
done
printf 'provider SSH smoke fixtures passed (%s cases; no live calls)\n' "$COUNT"
