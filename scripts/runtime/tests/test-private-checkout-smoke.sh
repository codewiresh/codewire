#!/usr/bin/env bash
# Public commands and synthetic metadata only; no VM, login, or provider access.
# shellcheck disable=SC2034,SC2329 # Inputs and command doubles serve sourced functions.
set -eEuo pipefail
trap 'printf "private checkout test failed at line %s\n" "$LINENO" >&2' ERR
umask 077
REVISION=1111111111111111111111111111111111111111
PUBLIC_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
ready_document() {
  jq -n --arg revision "$REVISION" --arg key "$PUBLIC_KEY" \
    '{version:1,url:"ssh://synthetic@127.0.0.1:22222/repository.git",revision:$revision,
      known_hosts:["[127.0.0.1]:22222 " + $key],content_path:"proof.txt",
      content:"initial-private-checkout-synthetic-v1"}'
}
if [[ "${1:-}" == --public-key-file ]]; then
  [[ $# == 6 && "$3" == --output-dir && "$5" == --timeout-seconds && "$6" == 1800 &&
     "$PATH" == /usr/bin:/bin && "$HOME" == /nonexistent &&
     -z "${BAO_TOKEN+x}" && -z "${SSH_AUTH_SOCK+x}" && -z "${BASH_ENV+x}" ]] || exit 80
  [[ "$(cat "$2")" == "$PUBLIC_KEY" ]] || exit 81
  fixture_dir="$4"; mode="$(cat "$(dirname "$2")/fixture-mode")"
  mkdir -m 700 "$fixture_dir"
  finish_fixture() {
    [[ "$mode" != missing-drain ]] || exit 0
    jq -n --argjson drained "$([[ "$mode" == false-drain ]] && printf false || printf true)" \
      --arg mode "$mode" '{version:1,drained:$drained,authenticated:1,denied:0,unsupported_commands:0} |
        if $mode == "extra-finish" then .extra=true else . end' >"$fixture_dir/finish.json"
    [[ "$mode" != bad-exit ]] || exit 7
    exit 0
  }
  trap finish_fixture TERM
  printf '{"version":1,"authenticated":0,"denied":0,"unsupported_commands":0}\n' >"$fixture_dir/counter.json"
  ready_document >"$fixture_dir/ready.json"
  while [[ ! -e "$fixture_dir/exit-now" ]]; do sleep 0.02; done
  finish_fixture
fi
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SELF="$REPO_ROOT/scripts/runtime/tests/test-private-checkout-smoke.sh"
# shellcheck disable=SC1091
source "$REPO_ROOT/scripts/runtime/dev/smoke-local-platform-sources.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cw-private-checkout-tests.XXXXXXXX")"
TEST_OWNER="$BASHPID"; COUNT=0
KEY_ID=11111111-1111-4111-8111-111111111111
PROFILE_ID=22222222-2222-4222-8222-222222222222
VM_ID=33333333-3333-4333-8333-333333333333
cleanup_test() {
  [[ "$BASHPID" == "$TEST_OWNER" ]] || return 0
  if [[ -n "$CHECKOUT_FIXTURE_PID" ]]; then
    kill -TERM "$CHECKOUT_FIXTURE_PID" 2>/dev/null || true
    wait "$CHECKOUT_FIXTURE_PID" 2>/dev/null || true
  fi
  rm -rf -- "$TEST_ROOT"
}
trap cleanup_test EXIT
fail() { printf 'private checkout fixture: %s\n' "$*" >&2; exit 1; }
pass() { COUNT=$((COUNT + 1)); }
fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$TEST_ROOT/case.XXXXXXXX")"
  LP_RUNTIME="$TMPDIR_SMOKE/runtime"; LP_WORKSPACE="$TMPDIR_SMOKE/workspace"
  mkdir -m 700 "$LP_RUNTIME" "$LP_WORKSPACE" "$TMPDIR_SMOKE/checkout"
  printf normal >"$LP_RUNTIME/fixture-mode"
  LP_INITIAL_PRIVATE_CHECKOUT=1; LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="$SELF"
  LOCAL_PLATFORM_NETWORK_ID=''; LOCAL_PLATFORM_DISPOSABLE_NETWORK=0; LOCAL_PLATFORM_MESH_PROBE_BIN=''
  LOCAL_PLATFORM_IMAGE="registry.invalid/workspace@sha256:$(printf '%064d' 1)"
  CODEWIRE_SERVER_URL=https://codewire-dev.sh; EXPECTED_CODEWIRE_ORGANIZATION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  LP_USER_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; ENV_ID=''; LP_CREATE_ATTEMPTED=0
  CHECKOUT_FIXTURE_PID=''; CHECKOUT_FIXTURE_DIR=''; SMOKE_NAME=synthetic-checkout
  FAILURE=''; : >"$TMPDIR_SMOKE/calls"
}
expect_failure() {
  local label="$1"; shift
  if ( "$@" ) >"$TEST_ROOT/failure.out" 2>"$TEST_ROOT/failure.err"; then fail "$label accepted"; fi
  pass
}
wait_until() {
  shift 2
  local attempt
  for ((attempt=0; attempt<100; attempt++)); do "$@" && return 0; sleep 0.02; done
  die 'synthetic fixture readiness failed'
}
run_guest() {
  local program="${1//\/workspace\/private-checkout/$TMPDIR_SMOKE/checkout}"
  # shellcheck disable=SC2016 # The generated install/exec program runs in an isolated child shell.
  env -i PATH=/usr/bin:/bin HOME=/nonexistent FIXTURE_REVISION="$REVISION" /bin/bash -c \
    'git() { [[ "$*" == "rev-parse HEAD" ]] && printf "%s\n" "$FIXTURE_REVISION"; }; eval "$1"' fixture "$program"
}
cw_with_timeout() { shift; cw "$@"; }
cw() {
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'env --platform list --all --output json'|'credentials --platform list --output json'|\
    'credentials --platform profiles list --output json') printf '[]\n' ;;
    'credentials --platform generate ssh --name '*) [[ "$6" == "$PROVIDER_SSH_CREDENTIAL_NAME" ]] ;;
    'credentials --platform get '*" --output json")
      jq -n --arg id "$KEY_ID" --arg name "$PROVIDER_SSH_CREDENTIAL_NAME" --arg key "$PUBLIC_KEY" \
        '[{id:$id,name:$name,provider:"ssh",status:"CREDENTIAL_STATUS_ACTIVE",
          authenticationKind:"CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY",sshPublicKey:{openssh:$key}}]' ;;
    'credentials --platform --profile '*" set ssh "*) [[ "$7" == "id:$KEY_ID" ]] ;;
    'credentials --platform --profile '*" get --output json")
      local key="$KEY_ID"; [[ "$FAILURE" != wrong-key ]] || key="$VM_ID"
      jq -n --arg id "$PROFILE_ID" --arg name "$PROVIDER_SSH_PROFILE_NAME" --arg key "$key" \
        '[{id:$id,name:$name,revision:"1",entries:[{capabilitySlot:"ssh",credentialId:$key}]}]' ;;
    'env list --local --output json')
      if [[ -e "$TMPDIR_SMOKE/created" ]]; then
        jq -n --arg id "$VM_ID" --arg name "$SMOKE_NAME" '[{id:$id,name:$name,state:"running"}]'
      else printf '[]\n'; fi ;;
    'env create --local '*)
      [[ $# == 16 && "$*" == "env create --local --name $SMOKE_NAME --cpu 2 --memory 16GB --no-docker --no-network --file "*" --yes --output json" ]] ||
        fail 'normal repository create gained path-copy or different resource arguments'
      local document="${13}" reason
      [[ "$PWD" == "$LP_WORKSPACE" && -n "$document" && "$document" == "${document##*/}" ]] ||
        fail 'normal repository create requires owned workspace cwd and a relative document basename'
      if ! jq -e '.credentials.profile != null' "$document" >/dev/null; then
        reason='SSH repository checkout requires a selected credential profile'
      elif ! jq -e '.repositories[0].known_hosts | length == 1' "$document" >/dev/null; then
        reason='must pin at least one SSH host key'
      else reason=''; fi
      if [[ -n "$reason" ]]; then
        [[ "$FAILURE" != generic-denial ]] || reason='unrelated transport failure'
        printf '%s\n' "$reason" >&2; return 1
      fi
      jq -e --arg profile "platform:id:$PROFILE_ID" --arg revision "$REVISION" '
        .credentials == {profile:$profile} and .repositories[0].revision == $revision and
        .repositories[0].destination == "/workspace/private-checkout" and
        .repositories[0].source == "ssh://synthetic@127.0.0.1:22222/repository.git"' "$document" >/dev/null || fail 'repository/profile binding drifted'
      touch "$TMPDIR_SMOKE/created"
      [[ "$FAILURE" != lost-reply ]] || return 1
      printf 'initial-private-checkout-synthetic-v1\n' >"$TMPDIR_SMOKE/checkout/proof.txt"
      if [[ "$FAILURE" != absent-install ]]; then run_guest "$(jq -er .install_command "$document")" || return 1; fi
      [[ "$FAILURE" != unauthenticated ]] || { printf '{"id":"%s"}\n' "$VM_ID"; return; }
      printf '{"version":1,"authenticated":1,"denied":0,"unsupported_commands":0}\n' >"$CHECKOUT_FIXTURE_DIR/counter.json"
      printf '{"id":"%s"}\n' "$VM_ID" ;;
    'env info --local '*" --output json")
      local profile="platform:id:$PROFILE_ID"; [[ "$FAILURE" != wrong-profile ]] || profile="platform:id:$KEY_ID"
      jq -n --arg id "$VM_ID" --arg profile "$profile" --arg reference "user/$PROVIDER_SSH_PROFILE_NAME" \
        --arg server "$CODEWIRE_SERVER_URL" --arg org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" --arg user "$LP_USER_ID" \
        '{id:$id,backend:"cloud-hypervisor",state:"running",cpu:2,memory:"16Gi",generation:1,
          source_selection:{credentials:{profile:$profile,reference:$reference,revision:1},
          platform:{server_url:$server,organization_id:$org,user_id:$user}}}' ;;
    'use --local '*) [[ "$3" == "$VM_ID" ]] ;;
    'run --no-tty -- /bin/sh -c '*) run_guest "$6" ;;
    'env rm --local --yes '*) [[ "$5" == "$VM_ID" ]]; rm -- "$TMPDIR_SMOKE/created" ;;
    *) fail "unexpected public command: $*" ;;
  esac
}
fixture; validate_private_checkout_options; pass
for invalid in disabled missing relative symlink noncanonical network disposable probe; do
  invalid_options() {
    fixture
    case "$invalid" in
      disabled) LP_INITIAL_PRIVATE_CHECKOUT=0 ;;
      missing) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN='' ;;
      relative) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=relative ;;
      symlink) ln -s "$SELF" "$TMPDIR_SMOKE/link"; LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="$TMPDIR_SMOKE/link" ;;
      noncanonical) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="${SELF%/*}/../tests/${SELF##*/}" ;;
      network) LOCAL_PLATFORM_NETWORK_ID=other ;;
      disposable) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 ;;
      probe) LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true ;;
    esac
    validate_private_checkout_options
  }
  expect_failure "$invalid" invalid_options
done
fixture; CHECKOUT_FIXTURE_DIR="$TMPDIR_SMOKE"; ready_document >"$TMPDIR_SMOKE/ready.json"
private_checkout_validate_metadata; pass
# shellcheck disable=SC2016 # The revision is intentionally hostile literal metadata.
for change in '.url="ssh://synthetic@evil.invalid:22222/repository.git"' '.url="ssh://synthetic@127.0.0.1:0/repository.git"' \
  '.url="ssh://synthetic@127.0.0.1:65536/repository.git"' '.known_hosts[0]="[127.0.0.1]:22 ssh-ed25519 AAAA"' \
  '.known_hosts[0]="[127.0.0.1]:22222 ssh-rsa AAAA"' '.known_hosts[0]+="; touch /tmp/forbidden"' \
  '.revision="$(false)"' '.content_path="../proof.txt"' '.content="wrong"' '.extra=true'; do
  ready_document | jq "$change" >"$TMPDIR_SMOKE/ready.json"
  expect_failure "metadata $change" private_checkout_validate_metadata
done
ready_document >"$TMPDIR_SMOKE/ready.json"; chmod 0644 "$TMPDIR_SMOKE/ready.json"
expect_failure public-metadata-mode private_checkout_json ready
chmod 0600 "$TMPDIR_SMOKE/ready.json"; printf '{"version":2}\n' >"$TMPDIR_SMOKE/ready.json"
expect_failure metadata-version private_checkout_json ready
for invalid in outside sibling traversal relative symlink missing directory; do
  fixture; printf '{}\n' >"$LP_WORKSPACE/codewire.yaml"
  case "$invalid" in
    outside) document="$TMPDIR_SMOKE/outside.json"; cp "$LP_WORKSPACE/codewire.yaml" "$document" ;;
    sibling) mkdir "$LP_WORKSPACE-other"; document="$LP_WORKSPACE-other/codewire.yaml"; cp "$LP_WORKSPACE/codewire.yaml" "$document" ;;
    traversal) document="$LP_WORKSPACE/../workspace/codewire.yaml" ;;
    relative) document=codewire.yaml ;;
    symlink) document="$LP_WORKSPACE/link.json"; ln -s codewire.yaml "$document" ;;
    missing) document="$LP_WORKSPACE/missing.json" ;;
    directory) document="$LP_WORKSPACE/nested"; mkdir "$document" ;;
  esac
  expect_failure "document $invalid" private_checkout_create "$document" invalid 1
  [[ ! -s "$TMPDIR_SMOKE/calls" ]] || fail "$invalid document reached the CLI"
  grep -qF 'directly inside the owned workspace' "$TEST_ROOT/failure.err" || fail 'document rejected for unrelated reason'
done
fixture; owner_pwd="$PWD"; private_checkout_journey
[[ "$PWD" == "$owner_pwd" && "$LP_CREATE_ATTEMPTED" == 1 ]] || fail 'create lost parent cwd or cleanup state'
local_platform_cleanup_environment; private_checkout_stop; pass
[[ ! -e "$TMPDIR_SMOKE/created" && -f "$TMPDIR_SMOKE/checkout/.install-proved" ]] || fail 'normal journey missed install or cleanup'
# The preinstall proof must be single-use even when repository content matches.
expect_failure repeated-install run_guest "$(jq -er .install_command "$LP_WORKSPACE/codewire.yaml")"
for failure in generic-denial wrong-key unauthenticated wrong-profile absent-install lost-reply; do
  fixture; FAILURE="$failure"
  # Keep setup and cleanup in the same shell so child ownership survives failure.
  if ( trap 'local_platform_cleanup_environment; private_checkout_stop' EXIT; private_checkout_journey ) \
      >"$TEST_ROOT/failure.out" 2>"$TEST_ROOT/failure.err"; then fail "$failure accepted"; fi
  [[ ! -e "$TMPDIR_SMOKE/created" ]] || fail "$failure leaked its environment after failure"
  if [[ "$failure" == generic-denial ]]; then
    grep -qF 'failed outside the expected validation boundary' "$TEST_ROOT/failure.err" || fail 'generic denial counted as expected rejection'
  fi
  pass
done
fixture; prepare_provider_ssh_identity; private_checkout_start
[[ "$(private_checkout_count)" == 0 ]] || fail 'valid unauthenticated counter rejected'
for change in '.version=2' '.authenticated=-1' '.authenticated=0.5' '.authenticated="1"' \
  '.denied=null' '.unsupported_commands=-1' 'del(.authenticated)' '.extra=true'; do
  printf '{"version":1,"authenticated":0,"denied":0,"unsupported_commands":0}\n' | jq "$change" \
    >"$CHECKOUT_FIXTURE_DIR/counter.json"
  if private_checkout_count >"$TEST_ROOT/count.out" 2>"$TEST_ROOT/count.err"; then fail "counter $change accepted"; fi
  pass
done
private_checkout_stop
for mode in normal missing-drain false-drain extra-finish bad-exit early-exit; do
  fixture; printf '%s' "$mode" >"$LP_RUNTIME/fixture-mode"
  prepare_provider_ssh_identity; private_checkout_start
  if [[ "$mode" == early-exit ]]; then
    touch "$CHECKOUT_FIXTURE_DIR/exit-now"
    wait "$CHECKOUT_FIXTURE_PID"
  fi
  if private_checkout_stop; then [[ "$mode" == normal ]] || fail "$mode accepted";
  else [[ "$mode" != normal ]] || fail 'normal fixture drain rejected'; fi
  pass
done
printf 'private checkout smoke tests passed (%s)\n' "$COUNT"
