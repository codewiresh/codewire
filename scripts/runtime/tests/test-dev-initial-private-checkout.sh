#!/usr/bin/env bash
# No login, Kubernetes, VM or provider access: command doubles only.
# shellcheck disable=SC2034,SC2329 # Sourced wrapper consumes test-owned inputs.
set -euo pipefail
umask 077
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/scripts/runtime/dev/smoke-dev-initial-private-checkout.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/hosted-checkout-tests.XXXXXX")"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
CHECKOUT_ROOT="$TEST_ROOT"
mkdir -p "$CHECKOUT_ROOT/scripts/runtime/dev/testdata"
ADMISSION="$CHECKOUT_ROOT/scripts/runtime/dev/testdata/acceptance-identity.json"
EXPECTED_CODEWIRE_ADMIN_EMAIL=hello@codewire.sh
EXPECTED_CODEWIRE_ADMIN_USER_ID=11111111111111111111111111111111
EXPECTED_CODEWIRE_ORGANIZATION_ID=22222222222222222222222222222222
PROFILE_ID=33333333-3333-4333-8333-333333333333
ENVIRONMENT_ID=44444444-4444-4444-8444-444444444444
COUNT=0
fail() { printf 'hosted checkout test: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  if ( "$@" ) >"$TEST_ROOT/rejected.out" 2>"$TEST_ROOT/rejected.err"; then fail 'invalid input accepted'; fi
  COUNT=$((COUNT + 1))
}
enroll() {
  jq -n --arg user "$EXPECTED_CODEWIRE_ADMIN_USER_ID" --arg org "$EXPECTED_CODEWIRE_ORGANIZATION_ID" \
    '{version:1,status:"enrolled",email:"hello@codewire.sh",userId:$user,organizationId:$org}' >"$ADMISSION"
}
enroll; checkout_admission; COUNT=$((COUNT + 1))
preauth_rejection() {
  jq '.status="not-enrolled"' "$ADMISSION" >"$ADMISSION.next"; mv "$ADMISSION.next" "$ADMISSION"
  prepare_fresh_oauth_cli() { touch "$TEST_ROOT/auth-started"; }
  checkout_main
}
expect_failure preauth_rejection
[[ ! -e "$TEST_ROOT/auth-started" ]] || fail 'unenrolled identity reached authentication'
COUNT=$((COUNT + 1))
for change in '.status="not-enrolled"' '.userId=null' '.organizationId=null' '.userId="00000000000000000000000000000000"' \
  '.organizationId="00000000000000000000000000000000"' '.email="owner@example.invalid"' '.extra=true' '.version=2'; do
  enroll; jq "$change" "$ADMISSION" >"$ADMISSION.next"; mv "$ADMISSION.next" "$ADMISSION"
  expect_failure checkout_admission
done
enroll
wrong_email() { EXPECTED_CODEWIRE_ADMIN_EMAIL=other@example.invalid; checkout_admission; }
wrong_user() { EXPECTED_CODEWIRE_ADMIN_USER_ID=99999999999999999999999999999999; checkout_admission; }
wrong_org() { EXPECTED_CODEWIRE_ORGANIZATION_ID=99999999999999999999999999999999; checkout_admission; }
expect_failure wrong_email; expect_failure wrong_user; expect_failure wrong_org
parser_selected() {
  checkout_validate_inputs() { [[ "$CW_BIN" == /usr/bin/true ]] || fail 'CLI input was not bound'; touch "$TEST_ROOT/parser-bound"; die 'synthetic preflight stop'; }
  checkout_main --cw-bin /usr/bin/true
}
expect_failure parser_selected
[[ -e "$TEST_ROOT/parser-bound" ]] || fail 'fixed CLI argument was rejected before binding'
COUNT=$((COUNT + 1))
expect_failure checkout_main --existing-env foreign
topology_before_auth() {
  printf '# inert synthetic module placeholder\n' >"$CHECKOUT_ROOT/scripts/runtime/dev/hosted-checkout-fixture.py"
  checkout_validate_inputs() { :; }
  timeout() { printf '%s\n' "$*" >"$TEST_ROOT/preflight-call"; return 1; }
  prepare_fresh_oauth_cli() { touch "$TEST_ROOT/topology-auth-started"; }
  checkout_main
}
expect_failure topology_before_auth
[[ ! -e "$TEST_ROOT/topology-auth-started" ]] || fail 'failed topology preflight reached authentication'
grep -Fq 'preflight --context' "$TEST_ROOT/preflight-call" || fail 'topology check did not use the shared fixture preflight'
COUNT=$((COUNT + 1))
enroll
TMPDIR_SMOKE="$TEST_ROOT/state"; mkdir "$TMPDIR_SMOKE"
for mode in start stop inspect; do
  (
    timeout() { printf '%s\n' "$@" >"$TEST_ROOT/fixture-command.args"; }
    checkout_fixture_command "$mode" --state-dir "$TEST_ROOT/owned-state"
  )
  case "$mode" in
    start) expected_timeout=1500 ;;
    stop) expected_timeout=750 ;;
    inspect) expected_timeout=300 ;;
  esac
  mapfile -t fixture_args <"$TEST_ROOT/fixture-command.args"
  [[ "${fixture_args[*]}" == "$expected_timeout python3 $CHECKOUT_ROOT/scripts/runtime/dev/hosted-checkout-fixture.py $mode --state-dir $TEST_ROOT/owned-state" ]] ||
    fail 'fixture mode timeout or exact arguments drifted'
  [[ ! -s "$TMPDIR_SMOKE/fixture-command.out" && ! -s "$TMPDIR_SMOKE/fixture-command.err" ]] ||
    fail 'fixture command redirection drifted'
  COUNT=$((COUNT + 1))
done
SMOKE_NAME=synthetic-hosted-checkout; ENV_ID="$ENVIRONMENT_ID"
PROVIDER_SSH_PROFILE_ID="$PROFILE_ID"
CHECKOUT_REVISION=1111111111111111111111111111111111111111
CHECKOUT_URL=ssh://codewire@10.96.1.2:22222/repository.git
CHECKOUT_HOST_PIN='[10.96.1.2]:22222 ssh-ed25519 AAAA'
DEV_CHECKOUT_WORKSPACE_IMAGE="ghcr.io/codewiresh/workspace@sha256:$(printf '%064d' 3)"
checkout_build_document >"$TEST_ROOT/built-document.json"
expected_install="set -eu; cd /workspace/private-checkout; test \"\$(git rev-parse HEAD)\" = '$CHECKOUT_REVISION'; test \"\$(cat proof.txt)\" = initial-private-checkout-synthetic-v1; test ! -e .install-proved; printf '%s\\n' initial-private-checkout-before-install > .install-proved"
jq -e --arg image "$DEV_CHECKOUT_WORKSPACE_IMAGE" --arg profile "platform:id:$PROFILE_ID" \
  --arg url "$CHECKOUT_URL" --arg pin "$CHECKOUT_HOST_PIN" --arg install "$expected_install" '
  . == {version:1,image:$image,working_directory:"/workspace/private-checkout",credentials:{profile:$profile},
    repositories:[{source:$url,known_hosts:[$pin],destination:"/workspace/private-checkout"}],install_command:$install}
  and (.repositories[0] | has("revision") | not)
' "$TEST_ROOT/built-document.json" >/dev/null || fail 'actual checkout document changed its selector or proof contract'
COUNT=$((COUNT + 1))
mkdir "$TEST_ROOT/install-root"
printf 'initial-private-checkout-synthetic-v1\n' >"$TEST_ROOT/install-root/proof.txt"
execute_built_install() (
  export TEST_ROOT INSTALL_HEAD
  cd() { builtin cd "$TEST_ROOT/install-root"; }
  git() { [[ "$*" == 'rev-parse HEAD' ]] || return 1; printf '%s\n' "$INSTALL_HEAD"; }
  export -f cd git
  bash -e -c "$(jq -r .install_command "$TEST_ROOT/built-document.json")"
)
INSTALL_HEAD=2222222222222222222222222222222222222222
expect_failure execute_built_install
[[ ! -e "$TEST_ROOT/install-root/.install-proved" ]] || fail 'wrong checkout HEAD created an install marker'
INSTALL_HEAD="$CHECKOUT_REVISION"
execute_built_install
grep -qx initial-private-checkout-before-install "$TEST_ROOT/install-root/.install-proved" ||
  fail 'matching checkout HEAD did not produce the exact install marker'
COUNT=$((COUNT + 1))
for invalid_revision in '' deadbeef 111111111111111111111111111111111111111G; do
  reject_document_revision() {
    CHECKOUT_REVISION="$invalid_revision"
    checkout_build_document
  }
  expect_failure reject_document_revision
  [[ ! -s "$TEST_ROOT/rejected.out" ]] || fail 'invalid revision emitted a checkout document'
done
READY_STATE=running; READY_SETUP=true; READY_ERROR=null; READY_PROFILE="platform:id:$PROFILE_ID"; READY_REVISION=1
cw_with_timeout() {
  shift
  case "$*" in
    'env --platform info '*" --output json")
      jq -n --arg id "$ENVIRONMENT_ID" --arg state "$READY_STATE" --argjson setup "$READY_SETUP" \
        --argjson error "$READY_ERROR" --arg profile "$READY_PROFILE" --argjson revision "$READY_REVISION" \
        '{id:$id,state:$state,setup_complete:$setup,setup_error:$error,
          source_selection:{credentials:{profile:$profile},profile_revision:$revision}}' ;;
    'env --platform list --all --output json')
      if [[ "$INVENTORY_STATE" == absent ]]; then printf '[]\n'; else
        jq -n --arg id "$ENVIRONMENT_ID" --arg name "$SMOKE_NAME" --arg state "$INVENTORY_STATE" \
          '[{id:$id,name:$name,state:$state}]'; fi ;;
    'env --platform rm --yes '*)
      [[ "$5" == "$ENVIRONMENT_ID" ]] || fail 'deleted foreign ID'
      printf 'environment\n' >>"$TEST_ROOT/order"; INVENTORY_STATE=destroyed ;;
    'env create --platform '*)
      [[ "$CHECKOUT_ATTEMPTED" == 1 && "$PWD" == "$CHECKOUT_WORKSPACE" &&
         "$*" == "env create --platform --name $SMOKE_NAME --cpu 2000 --memory 4096 --ttl 30m --no-network --file codewire.yaml --no-wait --yes --output json" ]] ||
        fail 'hosted create scope/resources/document or attempted-state drifted'
      printf '{"id":"%s"}\n' "$ENVIRONMENT_ID" ;;
    *) fail 'unexpected public command' ;;
  esac
}
checkout_environment_ready; COUNT=$((COUNT + 1))
READY_SETUP=false; if checkout_environment_ready; then fail 'running before setup accepted'; fi; COUNT=$((COUNT + 1))
READY_SETUP=true; READY_STATE=starting; if checkout_environment_ready; then fail 'not running accepted'; fi; COUNT=$((COUNT + 1))
READY_STATE=running; READY_PROFILE="platform:id:$ENVIRONMENT_ID"
if checkout_environment_ready; then fail 'foreign profile accepted'; fi; COUNT=$((COUNT + 1))
READY_PROFILE="platform:id:$PROFILE_ID"; READY_REVISION=2
if checkout_environment_ready; then fail 'wrong revision accepted'; fi; COUNT=$((COUNT + 1))
READY_REVISION=1; READY_ERROR='"synthetic setup error"'; expect_failure checkout_environment_ready
READY_ERROR=null
CHECKOUT_WORKSPACE="$TMPDIR_SMOKE/workspace"; mkdir "$CHECKOUT_WORKSPACE"
printf '{}\n' >"$CHECKOUT_WORKSPACE/codewire.yaml"
checkout_create "$CHECKOUT_WORKSPACE/codewire.yaml" arguments
jq -e --arg id "$ENVIRONMENT_ID" '.id == $id' "$TMPDIR_SMOKE/checkout-arguments.json" >/dev/null
COUNT=$((COUNT + 1))
expect_failure checkout_create "$TMPDIR_SMOKE/checkout-info.json" outside
# Lost create response: resolve exactly the prechecked name and terminal cleanup.
CHECKOUT_ATTEMPTED=1; ENV_ID=''; INVENTORY_STATE=running; SMOKE_TIMEOUT_SECONDS=30
checkout_cleanup_environment
[[ "$CHECKOUT_ATTEMPTED" == 0 && -z "$ENV_ID" ]] || fail 'lost reply was not cleaned'
COUNT=$((COUNT + 1))
CHECKOUT_ATTEMPTED=1; ENV_ID=55555555-5555-4555-8555-555555555555; INVENTORY_STATE=running
if checkout_cleanup_environment; then fail 'foreign identity cleanup accepted'; fi; COUNT=$((COUNT + 1))
CHECKOUT_ATTEMPTED=1; ENV_ID=''; INVENTORY_STATE=absent
if checkout_cleanup_environment; then fail 'uncertain create absence was accepted as cleanup'; fi; COUNT=$((COUNT + 1))
# Rejections must match validation reason, create no object and never authenticate.
ENV_ID=''; CHECKOUT_ATTEMPTED=0; INVENTORY_STATE=absent; CHECKOUT_AUTHENTICATED=0
REJECT_REASON='SSH repository checkout requires a selected credential profile'
checkout_create() { CHECKOUT_ATTEMPTED=1; printf '%s\n' "$REJECT_REASON" >"$TMPDIR_SMOKE/checkout-$2.err"; return 1; }
checkout_fixture_inspect() { return 0; }
checkout_reject ignored unselected "$REJECT_REASON"; COUNT=$((COUNT + 1))
CHECKOUT_AUTHENTICATED=1; expect_failure checkout_reject ignored unselected "$REJECT_REASON"
CHECKOUT_AUTHENTICATED=0; INVENTORY_STATE=running; expect_failure checkout_reject ignored unselected "$REJECT_REASON"
INVENTORY_STATE=absent; expect_failure checkout_reject ignored unselected 'different validation reason'
# Final PASS requires the existing cleanup ordering, including fixture and logout.
cleanup_order() {
  TMPDIR_SMOKE="$TEST_ROOT/state"; CHECKOUT_SUCCESS=1; CHECKOUT_FIXTURE_STARTED=1
  SMOKE_OAUTH_LOGIN_ATTEMPTED=1; SMOKE_TMP_PARENT="$TEST_ROOT"
  checkout_cleanup_environment() { printf 'environment\n' >>"$TEST_ROOT/cleanup-order"; }
  checkout_fixture_stop() { printf 'fixture\n' >>"$TEST_ROOT/cleanup-order"; }
  cleanup_provider_ssh_profile() { printf 'profile\n' >>"$TEST_ROOT/cleanup-order"; }
  cleanup_provider_ssh_credential() { printf 'credential\n' >>"$TEST_ROOT/cleanup-order"; }
  cleanup_fresh_oauth_login() { printf 'oauth\n' >>"$TEST_ROOT/cleanup-order"; }
  # Invalid disposable-directory suffix must fail, despite otherwise successful cleanup.
  checkout_cleanup
}
expect_failure cleanup_order
[[ "$(tr '\n' ' ' <"$TEST_ROOT/cleanup-order")" == 'environment fixture profile credential oauth ' ]] ||
  fail 'cleanup order drifted'
COUNT=$((COUNT + 1))
ready_document() {
  jq -n '{version:1,url:"ssh://codewire@10.96.1.2:22222/repository.git",
    revision:"1111111111111111111111111111111111111111",
    known_hosts:["[10.96.1.2]:22222 ssh-ed25519 AAAA"],content_path:"proof.txt",
    content:"initial-private-checkout-synthetic-v1"}' >"$TEST_ROOT/ready.json"
}
ready_document; checkout_validate_ready "$TEST_ROOT/ready.json"; COUNT=$((COUNT + 1))
# shellcheck disable=SC2016 # This hostile revision must remain literal input.
for change in '.url="ssh://codewire@127.0.0.1:22222/repository.git"' \
  '.url="ssh://codewire@evil.invalid:22222/repository.git"' '.url="ssh://other@10.96.1.2:22222/repository.git"' \
  '.url="ssh://codewire@10.96.1.2:22/repository.git"' '.url+="?command=evil"' \
  '.known_hosts[0]="[10.96.1.3]:22222 ssh-ed25519 AAAA"' '.known_hosts[0]+="; bad"' \
  '.revision="$(false)"' '.extra=true'; do
  ready_document; jq "$change" "$TEST_ROOT/ready.json" >"$TEST_ROOT/ready.next"; mv "$TEST_ROOT/ready.next" "$TEST_ROOT/ready.json"
  expect_failure checkout_validate_ready "$TEST_ROOT/ready.json"
done
printf 'hosted checkout wrapper tests passed (%s cases)\n' "$COUNT"
