#!/usr/bin/env bash
# Public command fixtures: no KVM, real login, live Dev or credential reads.
# shellcheck disable=SC2034 # Fixture inputs are consumed by sourced functions.
# shellcheck disable=SC2329 # Public-command doubles are invoked by sourced functions.
set -euo pipefail
if [[ "${1:-}" == --mesh-probe-fixture ]]; then
  [[ -z "${OPENAI_API_KEY+x}" && -z "${ANTHROPIC_API_KEY+x}" && -z "${SSH_AUTH_SOCK+x}" &&
    -z "${CODEWIRE_API_KEY+x}" && -z "${BASH_ENV+x}" && "$PATH" == /usr/bin:/bin &&
    "$CW_CONFIG_DIR" == "$HOME/login" ]] || exit 1
  [[ "${CW_MESH_FIXTURE_KIND:-}" != failure ]] || exit 1
  if [[ "${CW_MESH_FIXTURE_KIND:-}" == malformed ]]; then printf '{}\n'; exit 0; fi
  jq -n '
    {version:"codewire-dev-mesh-probe:v1",server_url:"https://codewire-dev.sh",mesh_url:"https://mesh.codewire-dev.sh",
     organization_id:env.CODEWIRE_DEV_MESH_PROBE_ORG,user_id:env.CODEWIRE_DEV_MESH_PROBE_USER,
     network_id:env.CODEWIRE_DEV_MESH_PROBE_NETWORK,node_name:env.CODEWIRE_DEV_MESH_PROBE_NODE,
     environment_id:env.CODEWIRE_DEV_MESH_PROBE_ENVIRONMENT,port:(env.CODEWIRE_DEV_MESH_PROBE_PORT|tonumber),
     nonce:env.CODEWIRE_DEV_MESH_PROBE_NONCE,transport:"derp_relay"} |
    if env.CW_MESH_FIXTURE_KIND == "wrong-network" then .network_id="wrong"
    elif env.CW_MESH_FIXTURE_KIND == "wrong-vm" then .environment_id="wrong"
    elif env.CW_MESH_FIXTURE_KIND == "wrong-nonce" then .nonce="wrong"
    elif env.CW_MESH_FIXTURE_KIND == "wrong-transport" then .transport="websocket" else . end'
  exit 0
fi
if [[ "${1:-}" == --server && "${2:-}" == synthetic && "${3:-}" == isolation-probe ]]; then
  [[ -z "${OPENAI_API_KEY+x}" && -z "${ANTHROPIC_API_KEY+x}" && -z "${SSH_AUTH_SOCK+x}" &&
    -z "${CODEWIRE_API_KEY+x}" && -z "${CODEWIRE_DEV_SMOKE_API_KEY+x}" && -z "${BASH_ENV+x}" &&
    "$HOME" == "$CW_CONFIG_DIR/../isolated" && "$PATH" == /usr/bin:/bin ]] || exit 1
  printf 'isolated-command-proved\n'
  exit 0
fi
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091
source "$REPO_ROOT/scripts/runtime/dev/smoke-local-platform-sources.sh"
REAL_LOCAL_PLATFORM_APPLICATION_PHASE="$(declare -f local_platform_application_phase)"
REAL_LOCAL_PLATFORM_GUEST_CHECK="$(declare -f local_platform_guest_check)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cw-local-platform-tests.XXXXXXXX")"
TEST_OWNER="$BASHPID"
cleanup_test() {
  [[ "$BASHPID" == "$TEST_OWNER" ]] || return 0
  local child
  for child in "${unrecognized_pid:-}" "${resistant_pid:-}"; do
    [[ -n "$child" ]] || continue
    kill -KILL "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  done
  rm -rf -- "$TEST_ROOT"
}
trap cleanup_test EXIT
COUNT=0
KEY_ID=11111111-1111-4111-8111-111111111111
PROFILE_ID=22222222-2222-4222-8222-222222222222
VM_ID=33333333-3333-4333-8333-333333333333
USER_ID=44444444444444448444444444444444
ORG_ID=55555555555545558555555555555555
PROJECT_ID=66666666-6666-4666-8666-666666666666
HOST_KEY='[127.0.0.1]:22222 ssh-ed25519 AAAATestPublicHostMetadata'
fail() { printf 'local/platform fixture: %s\n' "$*" >&2; exit 1; }
pass() { COUNT=$((COUNT + 1)); }
expect_failure() {
  local label="$1"; shift
  if ( "$@" ) >"$TEST_ROOT/failure.out" 2>"$TEST_ROOT/failure.err"; then fail "$label accepted invalid input"; fi
  pass
}
fixture() {
  TMPDIR_SMOKE="$(mktemp -d "$TEST_ROOT/case.XXXXXXXX")"
  SMOKE_AUTH_MODE=admin-oidc
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR=''
  LOCAL_PLATFORM_ARTIFACT_ROOT="$TMPDIR_SMOKE/artifacts"
  LOCAL_PLATFORM_ARTIFACT_LOCK="$TMPDIR_SMOKE/lock.json"
  CW_BIN=/usr/bin/true
  mkdir -m 700 "$LOCAL_PLATFORM_ARTIFACT_ROOT"
  touch "$LOCAL_PLATFORM_ARTIFACT_LOCK"
  EXPECTED_CODEWIRE_ADMIN_EMAIL=synthetic@example.invalid
  CODEWIRE_SERVER_URL=https://codewire-dev.sh; EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
  EXPECTED_CODEWIRE_ORGANIZATION_ID="$ORG_ID"; LP_USER_ID="$USER_ID"
  LOCAL_PLATFORM_IMAGE="ghcr.io/codewire/workspace@sha256:$(printf '%064d' 1)"
  LOCAL_PLATFORM_NETWORK_ID=''
  LOCAL_PLATFORM_DISPOSABLE_NETWORK=0
  LOCAL_PLATFORM_MESH_PROBE_BIN=''
  LP_NETWORK_CREATE_ATTEMPTED=0
  LP_LIVE_GITHUB=0; LP_LIVE_CODEX=0; LP_LIVE_ANTHROPIC=0; LP_LIVE_OPENAI=0
  LP_APPLICATION_ONLY=0
  FIXTURE_EMPTY_SOURCE=0
  LOCAL_PLATFORM_OPENAI_MODEL=fixture-model-v1
  LP_INITIAL_PRIVATE_CHECKOUT=0; LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=''
  FIXTURE_NETWORKS_JSON=''
  FIXTURE_NETWORK_NODES_JSON=''
  SMOKE_EXISTING_ENV_ID=''; SMOKE_KEEP_ENV=0; SMOKE_SKIP_KUBE=0; SMOKE_ONLY_PHASES=()
  ALLOW_NON_DEV=0; ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE=0
  PROVIDER_SSH_PROFILE_ID="$PROFILE_ID"; PROVIDER_SSH_PROFILE_NAME=owned-profile
  PROVIDER_SSH_CREDENTIAL_ID="$KEY_ID"; ENV_ID="$VM_ID"; SMOKE_NAME=owned-local
  LP_GENERATION=0; LP_CREATE_ATTEMPTED=0; LP_RUNTIME=''; LP_HOME=''; LP_LOGIN_ATTEMPTED=0; LP_NETWORK_NODE_OWNED=0
  FAILURE=''; unset CODEWIRE_API_KEY CODEWIRE_DEV_SMOKE_API_KEY
  : >"$TMPDIR_SMOKE/calls"
}
fixture
validate_local_platform_options
pass
local_platform_parse --application-only
[[ "$LP_APPLICATION_ONLY" == 1 ]] || fail 'application-only option was not parsed'
validate_local_platform_options
pass
for invalid in github codex anthropic openai checkout; do
  invalid_application_only_options() {
    fixture
    LP_APPLICATION_ONLY=1
    case "$invalid" in
      github) LP_LIVE_GITHUB=1 ;;
      codex) LP_LIVE_CODEX=1 ;;
      anthropic) LP_LIVE_ANTHROPIC=1 ;;
      openai) LP_LIVE_OPENAI=1 ;;
      checkout) LP_INITIAL_PRIVATE_CHECKOUT=1 ;;
    esac
    validate_local_platform_options
  }
  expect_failure "application-only-$invalid" invalid_application_only_options
done
fixture
LP_APPLICATION_ONLY=1
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true
validate_local_platform_options
pass
fixture
local_platform_parse --live-codex
[[ "$LP_LIVE_CODEX" == 1 ]] || fail 'Codex option was not parsed'
validate_local_platform_options
pass
for invalid in anthropic openai checkout fixture network disposable probe; do
  invalid_codex_options() {
    fixture
    LP_LIVE_CODEX=1
    case "$invalid" in
      anthropic) LP_LIVE_ANTHROPIC=1 ;;
      openai) LP_LIVE_OPENAI=1 ;;
      checkout) LP_INITIAL_PRIVATE_CHECKOUT=1 ;;
      fixture) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=/usr/bin/true ;;
      network) LOCAL_PLATFORM_NETWORK_ID=shared ;;
      disposable) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 ;;
      probe) LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true ;;
    esac
    validate_local_platform_options
  }
  expect_failure "codex-$invalid" invalid_codex_options
done
fixture
local_platform_parse --live-anthropic
[[ "$LP_LIVE_ANTHROPIC" == 1 ]] || fail 'Anthropic option was not parsed'
validate_local_platform_options
pass
for invalid in codex openai checkout fixture network disposable probe; do
  invalid_anthropic_options() {
    fixture
    LP_LIVE_ANTHROPIC=1
    case "$invalid" in
      codex) LP_LIVE_CODEX=1 ;;
      openai) LP_LIVE_OPENAI=1 ;;
      checkout) LP_INITIAL_PRIVATE_CHECKOUT=1 ;;
      fixture) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=/usr/bin/true ;;
      network) LOCAL_PLATFORM_NETWORK_ID=shared ;;
      disposable) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 ;;
      probe) LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true ;;
    esac
    validate_local_platform_options
  }
  expect_failure "anthropic-$invalid" invalid_anthropic_options
done
fixture
local_platform_parse --live-openai
[[ "$LP_LIVE_OPENAI" == 1 ]] || fail 'OpenAI option was not parsed'
validate_local_platform_options
pass
for invalid in codex anthropic checkout fixture network disposable probe model; do
  invalid_openai_options() {
    fixture
    LP_LIVE_OPENAI=1
    case "$invalid" in
      codex) LP_LIVE_CODEX=1 ;;
      anthropic) LP_LIVE_ANTHROPIC=1 ;;
      checkout) LP_INITIAL_PRIVATE_CHECKOUT=1 ;;
      fixture) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=/usr/bin/true ;;
      network) LOCAL_PLATFORM_NETWORK_ID=shared ;;
      disposable) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 ;;
      probe) LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true ;;
      model) LOCAL_PLATFORM_OPENAI_MODEL='' ;;
    esac
    validate_local_platform_options
  }
  expect_failure "openai-$invalid" invalid_openai_options
done
fixture
local_platform_parse --live-github
[[ "$LP_LIVE_GITHUB" == 1 ]] || fail 'GitHub option was not parsed'
validate_local_platform_options
pass
for invalid in codex anthropic openai checkout fixture network disposable probe; do
  invalid_github_options() {
    fixture
    LP_LIVE_GITHUB=1
    case "$invalid" in
      codex) LP_LIVE_CODEX=1 ;;
      anthropic) LP_LIVE_ANTHROPIC=1 ;;
      openai) LP_LIVE_OPENAI=1 ;;
      checkout) LP_INITIAL_PRIVATE_CHECKOUT=1 ;;
      fixture) LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN=/usr/bin/true ;;
      network) LOCAL_PLATFORM_NETWORK_ID=shared ;;
      disposable) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 ;;
      probe) LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true ;;
    esac
    validate_local_platform_options
  }
  expect_failure "github-$invalid" invalid_github_options
done
fixture
local_platform_validate_socket_paths /short/.cwl.XXXXXX/h /run/user/1000/.cwlp-XXXXXX
pass
expect_failure long-scratch-parent local_platform_validate_socket_paths \
  '/long-evidence-parent/codewire-runtime-smoke.XXXXXX/native-home' /run/user/1000/.cwlp-XXXXXX
expect_failure long-runtime-parent local_platform_validate_socket_paths \
  /short/.cwl.XXXXXX/h '/long-runtime-parent-that-would-overflow-the-private-ssh-agent-socket/.cwlp-XXXXXX'
# At the longest home-derived socket boundary, 107 bytes fit and 108 do not.
socket_suffix='/.codewire/credentials-v1/ssh-00000000-0000-4000-8000-000000000000/agent'
printf -v boundary_home '/%*s' "$((106 - ${#socket_suffix}))" ''
boundary_home="${boundary_home// /x}"
local_platform_validate_socket_paths "$boundary_home" /run/user/1000/.cwlp-XXXXXX
pass
expect_failure socket-nul-boundary local_platform_validate_socket_paths "${boundary_home}x" /run/user/1000/.cwlp-XXXXXX
# A multibyte character cannot hide an overlong pathname in a UTF-8 locale.
expect_failure socket-byte-boundary local_platform_validate_socket_paths "${boundary_home%?}é" /run/user/1000/.cwlp-XXXXXX
local_platform_validate_scratch_parent "$TEST_ROOT"
pass
expect_failure relative-scratch-parent local_platform_validate_scratch_parent relative
expect_failure missing-scratch-parent local_platform_validate_scratch_parent "$TEST_ROOT/missing"
ln -s "$TEST_ROOT" "$TEST_ROOT/scratch-link"
expect_failure symlink-scratch-parent local_platform_validate_scratch_parent "$TEST_ROOT/scratch-link"
invalid_scratch_mount() {
  findmnt() { printf '%s\n' rw,noexec,nodev; }
  local_platform_validate_scratch_parent "$TEST_ROOT"
}
expect_failure noexec-scratch-parent invalid_scratch_mount
for invalid in saved-login wrong-auth missing-email api-key alternate-server organization mutable-image keep existing partial no-kube symlink; do
  invalid_options() {
    fixture
    case "$invalid" in
      saved-login) CODEWIRE_ADMIN_OAUTH_CONFIG_DIR=/never-read-existing-login ;;
      wrong-auth) SMOKE_AUTH_MODE=api-key ;;
      missing-email) EXPECTED_CODEWIRE_ADMIN_EMAIL='' ;;
      api-key) CODEWIRE_API_KEY=synthetic ;;
      alternate-server) CODEWIRE_SERVER_URL=https://wrong.invalid ;;
      organization) EXPECTED_CODEWIRE_ORGANIZATION_ID='' ;;
      mutable-image) LOCAL_PLATFORM_IMAGE=workspace:latest ;;
      keep) SMOKE_KEEP_ENV=1 ;;
      existing) SMOKE_EXISTING_ENV_ID=unowned ;;
      partial) SMOKE_ONLY_PHASES=(provider-ssh) ;;
      no-kube) SMOKE_SKIP_KUBE=1 ;;
      symlink) ln -s "$LOCAL_PLATFORM_ARTIFACT_LOCK" "$TMPDIR_SMOKE/link"; LOCAL_PLATFORM_ARTIFACT_LOCK="$TMPDIR_SMOKE/link" ;;
    esac
    validate_local_platform_options
  }
  expect_failure "$invalid" invalid_options
done
invalid_options() { fixture; LOCAL_PLATFORM_NETWORK_ID='bad network'; validate_local_platform_options; }
expect_failure bad-network invalid_options
expect_failure unsupported-option local_platform_parse --keep
for invalid in disposable-value network-modes missing-probe orphan-probe; do
  invalid_mesh_options() {
    fixture
    case "$invalid" in
      disposable-value) LOCAL_PLATFORM_DISPOSABLE_NETWORK=2 ;;
      network-modes) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1; LOCAL_PLATFORM_NETWORK_ID=shared ;;
      missing-probe) LOCAL_PLATFORM_DISPOSABLE_NETWORK=1 ;;
      orphan-probe) LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true ;;
    esac
    validate_local_platform_options
  }
  expect_failure "$invalid" invalid_mesh_options
done
fixture
LOCAL_PLATFORM_DISPOSABLE_NETWORK=1; LOCAL_PLATFORM_MESH_PROBE_BIN=/usr/bin/true
validate_local_platform_options
pass

fixture
LP_NETWORK_ARGS=()
local_platform_set_network_args
[[ "${LP_NETWORK_ARGS[*]}" == --no-network ]] || fail 'baseline journey no longer opts out of Mesh'
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
local_platform_set_network_args
[[ "${LP_NETWORK_ARGS[*]}" == '--network shared-dev-network' ]] || fail 'selected network did not reach public create arguments'
pass

# Organization creation emits UUID simple() strings; the acceptance must use
# that exact current ID format while still rejecting ambiguous input.
for invalid_org in '' 00000000000000000000000000000000 \
  55555555-5555-4555-8555-555555555555 ABCDEF01234545678901234567890123 \
  g5555555555545558555555555555555 5555555555545558555555555555555 \
  555555555555455585555555555555555; do
  invalid_organization() {
    fixture
    EXPECTED_CODEWIRE_ORGANIZATION_ID="$invalid_org"
    validate_local_platform_options
  }
  expect_failure organization-format invalid_organization
done

cw_with_timeout() {
  shift
  printf '%q ' "$@" >>"$TMPDIR_SMOKE/calls"; printf '\n' >>"$TMPDIR_SMOKE/calls"
  case "$*" in
    'network list --org '*" --output json")
      if [[ "$FAILURE" == network-list ]]; then return 1; fi
      if [[ -n "$FIXTURE_NETWORKS_JSON" ]]; then printf '%s\n' "$FIXTURE_NETWORKS_JSON"; return 0; fi
      if [[ "$LOCAL_PLATFORM_DISPOSABLE_NETWORK" == 1 ]]; then
        if [[ ! -e "$TMPDIR_SMOKE/network-created" || -e "$TMPDIR_SMOKE/network-deleted" ]]; then printf '[]\n'; return 0; fi
        jq -n --arg id "$LOCAL_PLATFORM_NETWORK_ID" --arg org "$ORG_ID" '[{id:$id,org_id:$org}]'
        return 0
      fi
      jq -n --arg id "${FIXTURE_NETWORK_ID:-shared-dev-network}" --arg org "${FIXTURE_NETWORK_ORG:-$ORG_ID}" \
        '[{id:$id,org_id:$org,created_at:"synthetic",node_count:1,invite_count:0}]' ;;
    'network create '*)
      [[ "$*" == "network create $SMOKE_NAME-mesh --org $ORG_ID --no-use" && "$LP_NETWORK_CREATE_ATTEMPTED" == 1 ]] || fail 'network create syntax/ownership drifted'
      touch "$TMPDIR_SMOKE/network-created"
      [[ "$FAILURE" != network-create-lost-reply ]] || return 1
      printf 'Network created\n' >&2 ;;
    'network delete '*)
      [[ "$*" == "network delete $SMOKE_NAME-mesh --org $ORG_ID --yes" ]] || fail 'network delete syntax/ownership drifted'
      [[ "$FAILURE" != network-delete ]] || return 1
      touch "$TMPDIR_SMOKE/network-deleted"
      printf 'Network deleted\n' >&2 ;;
    'network nodes --network '*" --output json")
      if [[ "$FAILURE" == network-nodes ]]; then return 1; fi
      if [[ -n "$FIXTURE_NETWORK_NODES_JSON" ]]; then printf '%s\n' "$FIXTURE_NETWORK_NODES_JSON"; return 0; fi
      if [[ -e "$TMPDIR_SMOKE/network-node-revoked" ]]; then printf '[]\n'; return 0; fi
      if [[ "$FAILURE" == collision || -e "$TMPDIR_SMOKE/network-node-created" ]]; then
        jq -n --arg network "${FIXTURE_NETWORK_ID:-shared-dev-network}" --arg name "${FIXTURE_NODE_NAME:-$SMOKE_NAME}" \
          --argjson connected "${FIXTURE_NODE_CONNECTED:-true}" \
          '[{network_id:$network,name:$name,peer_url:"synthetic.invalid",connected:$connected}]'
        return 0
      fi
      printf '[]\n' ;;
    'network revoke --network '*)
      [[ "$4" == shared-dev-network && "$6" == "$ORG_ID" && "$7" == "$SMOKE_NAME" ]] || fail 'wrong owned network-node revocation'
      touch "$TMPDIR_SMOKE/network-node-revoked" ;;
    'org set '*)
      [[ $# == 3 && "$3" == "$ORG_ID" ]] || fail 'Mesh owner selection changed the authenticated organization'
      [[ "$FAILURE" != mesh-owner ]] || return 1
      touch "$TMPDIR_SMOKE/mesh-owner-selected" ;;
    'env info --local '*" --output json")
      jq -n --arg id "$ENV_ID" --arg project "platform:id:$PROJECT_ID" --arg profile "platform:id:$PROFILE_ID" \
        --arg server "$CODEWIRE_SERVER_URL" --arg user "$LP_USER_ID" --arg org "$ORG_ID" --arg failure "$FAILURE" \
        --argjson application_only "$LP_APPLICATION_ONLY" --argjson empty_source "$FIXTURE_EMPTY_SOURCE" '
        {id:$id,backend:"cloud-hypervisor",state:"running",cpu:2,memory:"16Gi",generation:1,
         source_selection:{credentials:(if $application_only == 1 then null else {profile:$profile,reference:"user/owned-profile",revision:1} end),
           secrets:{project:(if $empty_source == 1 then null else $project end)},
           platform:(if $application_only == 1 and $empty_source == 1 then null
                     else {server_url:$server,organization_id:$org,user_id:$user} end)}} |
        if $failure == "wrong-vm" then .id="unowned"
        elif $failure == "wrong-profile" then .source_selection.credentials.profile="local:owned-profile"
        elif $failure == "wrong-revision" then .source_selection.credentials.revision=2
        elif $failure == "unselected-profile" then .source_selection.credentials={profile:$profile,reference:"user/owned-profile",revision:1}
        elif $failure == "empty-credentials" then .source_selection.credentials={}
        elif $failure == "false-credentials" then .source_selection.credentials=false
        elif $failure == "wrong-project" then .source_selection.secrets.project="local:project"
        elif $failure == "wrong-user" then .source_selection.platform.user_id="unowned"
        elif $failure == "wrong-org" then .source_selection.platform.organization_id="unowned"
        elif $failure == "wrong-server" then .source_selection.platform.server_url="https://wrong.invalid"
        elif $failure == "retained-authority" then .source_selection.platform={server_url:$server,organization_id:$org,user_id:$user}
        elif $failure == "false-authority" then .source_selection.platform=false
        elif $failure == "empty-authority" then .source_selection.platform={}
        elif $failure == "missing-authority" then .source_selection.platform=null
        elif $failure == "extra-source" then .source_selection.secrets.user="platform"
        elif $failure == "stale" then .generation=0
        elif $failure == "leaped" then .generation=2 else . end' ;;
    'run --no-tty -- /bin/bash '*" public-host-key") printf '%s\n' "$HOST_KEY" ;;
    'run --no-tty -- /bin/bash '*" prove "*)
      [[ "$7" == "$HOST_KEY" ]] || fail 'wrong public host trust'
      [[ "$FAILURE" != proof ]] || return 1
      [[ "$FAILURE" == empty-proof ]] || printf 'stock-ssh-workload-proved\n' ;;
    'run --no-tty --detach --output json -- /bin/bash '*" wait-revoked "*)
      [[ "${10}" == "$HOST_KEY" ]] || fail 'waiter changed host trust'
      touch "$TMPDIR_SMOKE/admitted"
      printf '{"session_id":"owned-session","state":"Running"}\n' ;;
    'credentials --platform revoke '*" --output json")
      [[ "$4" == "id:$KEY_ID" && -e "$TMPDIR_SMOKE/ready" ]] || fail 'revoke identity/order'
      touch "$TMPDIR_SMOKE/revoked"
      if [[ "$FAILURE" == bad-revoke ]]; then printf '[]\n'; else
        jq -n --arg id "$KEY_ID" '[{id:$id,status:"CREDENTIAL_STATUS_REVOKED",revocationGeneration:"2"}]'
      fi ;;
    'env cp --local '*)
      [[ -e "$TMPDIR_SMOKE/revoked" && "$5" == "$SMOKE_NAME:/workspace/.cw-ssh-smoke/revoked-trigger" ]] || fail 'wrong local trigger'
      touch "$TMPDIR_SMOKE/triggered" ;;
    'logs '*" --raw")
      [[ "$2" == "$VM_ID" && "$3" == owned-session ]] || fail 'wrong session logs'
      if [[ -e "$TMPDIR_SMOKE/triggered" ]]; then
        [[ "$FAILURE" == empty-denial ]] || printf 'stock-ssh-workload-revoked\n'
      else
        [[ -e "$TMPDIR_SMOKE/admitted" ]] || fail 'unadmitted waiter'
        touch "$TMPDIR_SMOKE/ready"; printf 'stock-ssh-workload-awaiting-revocation\n'
      fi ;;
    'list '*" --output json")
      [[ "$2" == "$VM_ID" && -e "$TMPDIR_SMOKE/triggered" ]] || fail 'wrong completion'
      [[ "$FAILURE" != denial ]] || return 1
      printf '[{"session_id":"owned-session","state":"Exited","exit_code":0}]\n' ;;
    'run --no-tty -- /bin/true')
      [[ -e "$TMPDIR_SMOKE/triggered" ]] || fail 'new launch before revocation'
      [[ "$FAILURE" != new-launch ]] || return 0
      if [[ "$FAILURE" == unrelated-error ]]; then printf 'connection refused\n' >&2; else
        printf 'session reached terminal state Failed without an exit code: environment launch denied or expired\n' >&2
      fi
      return 1 ;;
    *) fail "unexpected public command: $*" ;;
  esac
}
wait_until() { shift 2; "$@" || die 'fixture wait failed'; }
fixture
local_platform_prepare_mesh_owner
[[ ! -e "$TMPDIR_SMOKE/mesh-owner-selected" ]] || fail 'network-free journey changed Mesh owner selection'
pass
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
local_platform_prepare_mesh_owner
[[ -e "$TMPDIR_SMOKE/mesh-owner-selected" ]] || fail 'named-network journey did not configure its isolated Mesh owner'
pass
fixture
LOCAL_PLATFORM_DISPOSABLE_NETWORK=1
local_platform_prepare_mesh_owner
[[ -e "$TMPDIR_SMOKE/mesh-owner-selected" ]] || fail 'disposable network did not configure its isolated Mesh owner'
pass
invalid_mesh_owner() { fixture; LOCAL_PLATFORM_DISPOSABLE_NETWORK=1; FAILURE=mesh-owner; local_platform_prepare_mesh_owner; }
expect_failure mesh-owner invalid_mesh_owner
fixture
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
local_platform_validate_network
local_platform_bind_network_attempt
[[ "$LP_NETWORK_NODE_OWNED" == 1 ]] || fail 'network create attempt did not bind partial-failure cleanup'
touch "$TMPDIR_SMOKE/network-node-created"
local_platform_network_member
local_platform_network_prove
local_platform_network_node_present
cw_with_timeout 30 network revoke --network "$LOCAL_PLATFORM_NETWORK_ID" --org "$ORG_ID" "$SMOKE_NAME"
local_platform_network_node_absent
pass
for invalid in network-list wrong-network wrong-network-org network-nodes collision wrong-node disconnected; do
  invalid_network() {
    fixture; LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
    case "$invalid" in
      network-list|network-nodes|collision) FAILURE="$invalid" ;;
      wrong-network) FIXTURE_NETWORK_ID=another-network ;;
      wrong-network-org) FIXTURE_NETWORK_ORG=another-organization ;;
      wrong-node) FIXTURE_NODE_NAME=another-node; touch "$TMPDIR_SMOKE/network-node-created" ;;
      disconnected) FIXTURE_NODE_CONNECTED=false; touch "$TMPDIR_SMOKE/network-node-created" ;;
    esac
    case "$invalid" in
      network-list|wrong-network|wrong-network-org|network-nodes|collision) local_platform_validate_network ;;
      wrong-node|disconnected) local_platform_network_member ;;
    esac
  }
  expect_failure "$invalid" invalid_network
done
for invalid_inventory in '{}' '[{}]' 'null' 'not-json' \
  '[{"network_id":"shared-dev-network","name":42,"connected":true}]' \
  '[{"network_id":"shared-dev-network","name":"owned-local"}]' \
  '[{"network_id":"another-network","name":"owned-local","connected":true}]'; do
  invalid_network_inventory() {
    fixture; LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
    FIXTURE_NETWORK_NODES_JSON="$invalid_inventory"
    "$@"
  }
  expect_failure malformed-network-admission invalid_network_inventory local_platform_validate_network
  expect_failure malformed-network-membership invalid_network_inventory local_platform_network_member
  expect_failure malformed-network-absence invalid_network_inventory local_platform_network_node_absent
  fixture; LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
  FIXTURE_NETWORK_NODES_JSON="$invalid_inventory"
  inventory_rc=0
  local_platform_network_node_present >/dev/null 2>&1 || inventory_rc=$?
  [[ "$inventory_rc" == 2 ]] || fail 'invalid network inventory was confused with node absence'
  pass
done
fixture
LOCAL_PLATFORM_DISPOSABLE_NETWORK=1
local_platform_prepare_network
local_platform_validate_network
local_platform_cleanup_network
[[ -e "$TMPDIR_SMOKE/network-deleted" ]] || fail 'owned disposable network survived cleanup'
pass
fixture
LOCAL_PLATFORM_DISPOSABLE_NETWORK=1; FAILURE=network-create-lost-reply
expect_failure lost-network-create-reply local_platform_prepare_network
# expect_failure runs in a subshell; its durable committed-create marker is
# retained while the real parent would also retain the pre-request ownership.
LOCAL_PLATFORM_NETWORK_ID="$SMOKE_NAME-mesh"; LP_NETWORK_CREATE_ATTEMPTED=1
local_platform_cleanup_network
[[ -e "$TMPDIR_SMOKE/network-deleted" ]] || fail 'lost create reply did not reconcile the owned network'
pass
for invalid in malformed-list foreign-node unknown-nodes delete-failure rebound; do
  unsafe_network_cleanup() {
    fixture; LOCAL_PLATFORM_DISPOSABLE_NETWORK=1
    local_platform_prepare_network
    case "$invalid" in
      malformed-list) FIXTURE_NETWORKS_JSON='{}' ;;
      foreign-node) FIXTURE_NETWORK_NODES_JSON='[{"network_id":"owned-local-mesh","name":"foreign","connected":false}]' ;;
      unknown-nodes) FIXTURE_NETWORK_NODES_JSON='[{}]' ;;
      delete-failure) FAILURE=network-delete ;;
      rebound) LOCAL_PLATFORM_NETWORK_ID=unowned ;;
    esac
    local_platform_cleanup_network
  }
  expect_failure "$invalid" unsafe_network_cleanup
done
fixture
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
local_platform_cleanup_network
[[ ! -e "$TMPDIR_SMOKE/network-deleted" ]] || fail 'explicit shared network was deleted'
pass
fixture
LP_WORKSPACE="$TMPDIR_SMOKE/workspace"; mkdir "$LP_WORKSPACE"
printf '%s\n' '{"startup_script":"app-startup; ssh-startup"}' >"$LP_WORKSPACE/codewire.yaml"
local_platform_prepare_mesh_listener
[[ ! -e "$LP_WORKSPACE/.cw-mesh-smoke" ]] || fail 'baseline created a Mesh listener'
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
local_platform_prepare_mesh_listener
cmp "$REPO_ROOT/scripts/runtime/dev/native-mesh-listener.py" "$LP_WORKSPACE/.cw-mesh-smoke/listener.py" || fail 'guest listener bytes drifted'
jq -e '.ports == [{port:28083}] and (.startup_script | startswith("app-startup; ssh-startup; ") and contains("/workspace/.cw-mesh-smoke/listener.py --port 28083"))' \
  "$LP_WORKSPACE/codewire.yaml" >/dev/null || fail 'named Mesh was not attached to a declared guest port'
pass
fixture
LP_APPLICATION_ONLY=1
LP_WORKSPACE="$TMPDIR_SMOKE/workspace"; mkdir "$LP_WORKSPACE"
printf '%s\n' '{"startup_script":"app-startup"}' >"$LP_WORKSPACE/codewire.yaml"
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
local_platform_prepare_mesh_listener
jq -e '.ports == [{port:28083}] and (has("credentials") | not) and
  (.startup_script | startswith("app-startup; ") and contains("/workspace/.cw-mesh-smoke/listener.py --port 28083") and (contains("ssh-startup") | not))' \
  "$LP_WORKSPACE/codewire.yaml" >/dev/null || fail 'application-only Mesh listener changed source/provider intent'
pass
mesh_probe_fixture() {
  fixture
  LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
  LOCAL_PLATFORM_MESH_PROBE_BIN="$TMPDIR_SMOKE/dev-mesh-probe"
  printf '#!/bin/bash\nexec %q --mesh-probe-fixture\n' "$REPO_ROOT/scripts/runtime/tests/test-local-platform-sources-smoke.sh" >"$LOCAL_PLATFORM_MESH_PROBE_BIN"
  chmod 0700 "$LOCAL_PLATFORM_MESH_PROBE_BIN"
  LP_ENV=(PATH=/usr/bin:/bin "HOME=$TMPDIR_SMOKE" "CW_CONFIG_DIR=$TMPDIR_SMOKE/login")
}
mesh_probe_fixture
export OPENAI_API_KEY=never-import ANTHROPIC_API_KEY=never-import SSH_AUTH_SOCK=/never-import
export CODEWIRE_API_KEY=never-import BASH_ENV=/never-import
local_platform_mesh_probe
unset OPENAI_API_KEY ANTHROPIC_API_KEY SSH_AUTH_SOCK CODEWIRE_API_KEY BASH_ENV
[[ -s "$TMPDIR_SMOKE/local-mesh-probe-binary.sha256" ]] || fail 'accepted Mesh peer binary identity was not recorded'
pass
for invalid in failure malformed wrong-network wrong-vm wrong-nonce wrong-transport; do
  invalid_mesh_probe() { mesh_probe_fixture; LP_ENV+=("CW_MESH_FIXTURE_KIND=$invalid"); local_platform_mesh_probe; }
  expect_failure "$invalid" invalid_mesh_probe
done
fixture
local_platform_binding "platform:id:$PROJECT_ID" 0
pass
for invalid in wrong-vm wrong-profile wrong-revision wrong-project wrong-user wrong-org wrong-server extra-source stale leaped; do
  invalid_binding() { fixture; FAILURE="$invalid"; local_platform_binding "platform:id:$PROJECT_ID" 0; }
  expect_failure "$invalid" invalid_binding
done
fixture
LP_APPLICATION_ONLY=1
local_platform_binding "platform:id:$PROJECT_ID" 0
pass
for invalid in wrong-vm unselected-profile empty-credentials false-credentials wrong-project wrong-user wrong-org wrong-server extra-source stale leaped; do
  invalid_application_only_binding() {
    fixture; LP_APPLICATION_ONLY=1; FAILURE="$invalid"
    local_platform_binding "platform:id:$PROJECT_ID" 0
  }
  expect_failure "application-only-$invalid" invalid_application_only_binding
done
fixture
LP_APPLICATION_ONLY=1; FIXTURE_EMPTY_SOURCE=1
local_platform_binding "" 0
pass
for invalid in retained-authority false-authority empty-authority; do
  invalid_application_only_clear_binding() {
    fixture; LP_APPLICATION_ONLY=1; FIXTURE_EMPTY_SOURCE=1; FAILURE="$invalid"
    local_platform_binding "" 0
  }
  expect_failure "application-only-clear-$invalid" invalid_application_only_clear_binding
done
fixture
FIXTURE_EMPTY_SOURCE=1
local_platform_binding "" 0
pass
invalid_credential_clear_binding() {
  fixture; FIXTURE_EMPTY_SOURCE=1; FAILURE=missing-authority
  local_platform_binding "" 0
}
expect_failure credential-clear-missing-authority invalid_credential_clear_binding
invalid_selected_application_binding() {
  fixture; LP_APPLICATION_ONLY=1; FAILURE=missing-authority
  local_platform_binding "platform:id:$PROJECT_ID" 0
}
expect_failure application-only-selected-missing-authority invalid_selected_application_binding
fixture
local_platform_ssh_prove
local_platform_ssh_revoke
pass
for invalid in proof empty-proof bad-revoke denial empty-denial new-launch unrelated-error; do
  invalid_ssh() { fixture; FAILURE="$invalid"; local_platform_ssh_prove; local_platform_ssh_revoke; }
  expect_failure "$invalid" invalid_ssh
done

# The normal subprocess wrapper must discard ambient credentials, default HOME
# and shell startup, but retain precisely the explicit owner-operated cw login.
fixture
LP_WORKSPACE="$TMPDIR_SMOKE"; CW_BIN="$REPO_ROOT/scripts/runtime/tests/test-local-platform-sources-smoke.sh"
CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$TMPDIR_SMOKE/login"
LP_ENV=(PATH=/usr/bin:/bin "HOME=$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR/../isolated" "CW_CONFIG_DIR=$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR")
CODEWIRE_SERVER_URL=synthetic
export OPENAI_API_KEY=never-import ANTHROPIC_API_KEY=never-import SSH_AUTH_SOCK=/never-import
export CODEWIRE_API_KEY=never-import CODEWIRE_DEV_SMOKE_API_KEY=never-import BASH_ENV=/never-import
[[ "$(local_platform_cw 10 isolation-probe)" == isolated-command-proved ]] || fail 'lost isolated command envelope'
unset OPENAI_API_KEY ANTHROPIC_API_KEY SSH_AUTH_SOCK CODEWIRE_API_KEY CODEWIRE_DEV_SMOKE_API_KEY BASH_ENV
pass

fixture
LP_HOME="$TMPDIR_SMOKE/native-home"; LP_RUNTIME="$TMPDIR_SMOKE/runtime"
local_platform_stop_owners
pass
# An unrecognized live process referencing this state must survive the helper;
# it blocks success instead of becoming an excuse for broad process killing.
bash -c 'sleep 30 & child=$!; trap '\''kill "$child" 2>/dev/null || :; wait "$child" 2>/dev/null || :; exit 0'\'' TERM; wait "$child"' \
  "$LP_HOME/unrecognized" &
unrecognized_pid=$!
expect_failure unrecognized-process local_platform_stop_owners
kill -0 "$unrecognized_pid" || fail 'cleanup signalled an unrecognized process'
kill "$unrecognized_pid"
wait "$unrecognized_pid" 2>/dev/null || true
unrecognized_pid=''
pass
fixture
LP_HOME="$TMPDIR_SMOKE/native-home"; LP_RUNTIME="$TMPDIR_SMOKE/runtime"
CW_BIN="$(realpath /usr/bin/python3)"
(
  cd "$REPO_ROOT/scripts/runtime/tests/fixtures/local-platform"
  exec "$CW_BIN" __local-credential-authority --root "$LP_HOME/.codewire/credentials-v1"
) >"$TMPDIR_SMOKE/resistant-ready" &
resistant_pid=$!
for attempt in {1..100}; do
  grep -qx ready "$TMPDIR_SMOKE/resistant-ready" && break
  sleep 0.02
done
grep -qx ready "$TMPDIR_SMOKE/resistant-ready" || fail 'TERM-resistant fixture did not start'
expect_failure term-resistant-owner local_platform_stop_owners
! kill -0 "$resistant_pid" 2>/dev/null || fail 'exact TERM-resistant authority survived cleanup'
wait "$resistant_pid" 2>/dev/null || true
resistant_pid=''
pass

# A synthetic CLI requires terminal stdin for size detection and nonterminal
# stdout for exit propagation, then allocates an actual guest PTY on --tty.
(
  eval "$REAL_LOCAL_PLATFORM_GUEST_CHECK"
  guest_python="$(local_platform_guest_check absent | awk "/^python3 - <<'PY'$/ { active=1; next } /^PY$/ { active=0 } active")"
  [[ -n "$guest_python" ]] || fail 'actual guest Python heredoc is missing'
  guest_home="$TMPDIR_SMOKE/nondefault-home"
  mkdir -m 0700 "$guest_home"
  env HOME="$guest_home" python3 -c "$guest_python"
  mkdir -p "$guest_home/.codewire"
  printf '{}\n' >"$guest_home/.codewire/environment.json"
  expect_failure persisted-environment-json env HOME="$guest_home" python3 -c "$guest_python"
  rm "$guest_home/.codewire/environment.json"
  mkdir -p "$guest_home/.codewire/daemon/sessions"
  expect_failure readable-private-sessions env HOME="$guest_home" python3 -c "$guest_python"
)
pass
pass
pass

LP_WORKSPACE="$TMPDIR_SMOKE"
(
  eval "$REAL_LOCAL_PLATFORM_APPLICATION_PHASE"
  CW_BIN="$TMPDIR_SMOKE/cw-local-pty-fixture"
  # shellcheck disable=SC2016 # Literal synthetic executable, not host expansion.
  printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'test -t 0; ! test -t 1; stty size >/dev/null' \
    'tty=0; while (($#)) && [[ "$1" != -- ]]; do [[ "$1" != --tty ]] || tty=1; shift; done' \
    '[[ "$tty" == 1 ]]; shift' \
    'if [[ "${LOCAL_PTY_WITHOUT_TERMINAL:-0}" == 1 ]]; then exec "$@"; fi' \
    'printf -v command "%q " "$@"' 'exec script -qefc "$command" /dev/null </dev/null' >"$CW_BIN"
  chmod 0700 "$CW_BIN"
  LP_ENV=(PATH=/usr/bin:/bin HOME="$TMPDIR_SMOKE/home")
  CODEWIRE_SERVER_URL=synthetic
  cw_with_timeout() {
    shift
    if [[ "$*" == 'run --no-tty -- /bin/sh -c '* ]]; then
      printf 'application-secret-check-ok\n'
      printf 'Launched session session-%s\n' "$VM_ID" >&2
      [[ "${SESSION_RECEIPT_FAILURE:-}" != duplicate-ack ]] || printf 'Launched session session-%s\n' "$VM_ID" >&2
    elif [[ "$*" == "list $ENV_ID --output json" ]]; then
      jq -n --arg id "session-$VM_ID" --arg guest "$SYNTHETIC_GUEST_CHECK" \
        '[{session_id:$id,command:["/bin/sh","-c",$guest],pty:false,state:"Exited",exit_code:0}]' |
        jq --arg failure "${SESSION_RECEIPT_FAILURE:-}" '
          if $failure == "wrong-id" then .[0].session_id = "session-unrelated"
          elif $failure == "wrong-command" then .[0].command = ["/bin/true"]
          elif $failure == "pty" then .[0].pty = true
          elif $failure == "nonzero" then .[0].exit_code = 1
          elif $failure == "running" then .[0].state = "Running"
          elif $failure == "duplicate-session" then . + . else . end'
    else fail 'unexpected application or exact environment session command'; fi
  }
  local_platform_binding() { printf '{"generation":1}\n' >"$TMPDIR_SMOKE/local-environment.json"; }
  local_platform_guest_check() { printf '%s' "$SYNTHETIC_GUEST_CHECK"; }
  SYNTHETIC_GUEST_CHECK="printf 'application-secret-check-ok\\n'"
  local_platform_application_phase actual synthetic expected
  for SESSION_RECEIPT_FAILURE in wrong-id wrong-command pty nonzero running duplicate-session duplicate-ack; do
    expect_failure "session-$SESSION_RECEIPT_FAILURE" local_platform_application_phase wrong-session synthetic expected
  done
  unset SESSION_RECEIPT_FAILURE
  SYNTHETIC_GUEST_CHECK="printf 'application-secret-check-ok\\n'; exit 7"
  expect_failure pty-exit-status local_platform_application_phase failure synthetic expected
  SYNTHETIC_GUEST_CHECK="printf 'application-secret-check-ok\\n'"
  LP_ENV+=(LOCAL_PTY_WITHOUT_TERMINAL=1)
  expect_failure missing-guest-pty local_platform_application_phase no-pty synthetic expected
)
pass
pass
pass

pass
pass
pass
pass
pass
pass
pass

# Execute the complete journey with public-command doubles. Preparation and
# per-process guest checks already have their own component fixtures above and
# in the shared Dev smoke tests; here assert their placement and ordering.
prepare_provider_ssh() {
  PROVIDER_SSH_DOCUMENT="$TMPDIR_SMOKE/provider.json"
  jq -n --arg profile "platform:id:$PROFILE_ID" '{credentials:{profile:$profile},install_command:"ssh-install",startup_script:"ssh-startup"}' >"$PROVIDER_SSH_DOCUMENT"
}
prepare_application_secrets() {
  APP_SECRET_IDS=("$PROJECT_ID" "$KEY_ID"); APP_SECRET_HASHES=(hash-a hash-b)
  APP_SECRET_DOCUMENT="$TMPDIR_SMOKE/application.json"
  jq -n --arg project "platform:id:$PROJECT_ID" '{version:1,secrets:{project:$project},install_command:"app-install",startup_script:"app-startup"}' >"$APP_SECRET_DOCUMENT"
}
local_platform_application_phase() {
  [[ "$(cat "$TMPDIR_SMOKE/phase")" == "$1" ]] || fail 'wrong application phase ordering'
  case "$1" in
    a) [[ "$2" == "platform:id:$PROJECT_ID" && "$3" == hash-a ]] ;;
    b) [[ "$2" == "platform:id:$KEY_ID" && "$3" == hash-b ]] ;;
    clear) [[ -z "$2" && "$3" == absent ]] ;;
    *) return 1 ;;
  esac || fail 'wrong source selection'
  [[ "$FAILURE" != "projection-$1" ]] || return 1
  printf '%s\n' "$1" >>"$TMPDIR_SMOKE/application-phases"
}
local_platform_ssh_prove() {
  if [[ "$(cat "$TMPDIR_SMOKE/phase")" == clear ]]; then
    [[ "$(cat "$TMPDIR_SMOKE/ssh-target-actions")" == $'cleanup\ninstall\nstartup' ]] ||
      fail 'repeated positive proof did not use a fresh owned target'
  else
    [[ ! -e "$TMPDIR_SMOKE/ssh-target-actions" ]] || fail 'initial target was reset'
  fi
  printf '%s\n' "$(cat "$TMPDIR_SMOKE/phase")" >>"$TMPDIR_SMOKE/ssh-phases"
}
local_platform_ssh_revoke() {
  [[ "$(cat "$TMPDIR_SMOKE/ssh-phases")" == $'a\nclear' ]] || fail 'SSH not proved with both selected and cleared app sources'
}
cw_with_timeout() {
  shift
  case "$*" in
    'env list --local --output json') printf '[]\n' ;;
    'env create --local '*)
      [[ "$*" == "env create --local --name $SMOKE_NAME --cpu 2 --memory 16GB --no-docker --no-network --path $LP_WORKSPACE --path-mode copy --file codewire.yaml --yes --output json" ]] || fail 'unsupported native create command'
      jq -e --arg profile "platform:id:$PROFILE_ID" --arg project "platform:id:$PROJECT_ID" --arg image "$LOCAL_PLATFORM_IMAGE" \
        --argjson application_only "$LP_APPLICATION_ONLY" '
        .secrets.project == $project and .image == $image and
        (if $application_only == 1 then (has("credentials") | not) and
          .install_command == "app-install" and .startup_script == "app-startup"
        else .credentials.profile == $profile and
          .install_command == "app-install; ssh-install" and .startup_script == "app-startup; ssh-startup" end)' \
        "$LP_WORKSPACE/codewire.yaml" >/dev/null || fail 'combined source document drifted'
      [[ "$FAILURE" != create ]] || return 1
      jq -n --arg id "$VM_ID" '{id:$id}'; printf 'a\n' >"$TMPDIR_SMOKE/phase" ;;
    'use --local '*) [[ "$3" == "$VM_ID" ]] || fail 'wrong local target' ;;
    'env update --local '*" --secrets "*)
      [[ "$*" == "env update --local $VM_ID --secrets platform:id:$KEY_ID --yes --output json" ]] || fail 'wrong update source'
      [[ "$FAILURE" != update ]] || return 1
      printf 'b\n' >"$TMPDIR_SMOKE/phase" ;;
    'env update --local '*" --clear-secrets --yes --output json")
      [[ "$4" == "$VM_ID" ]] || fail 'wrong clear target'
      [[ "$FAILURE" != clear ]] || return 1
      printf 'clear\n' >"$TMPDIR_SMOKE/phase" ;;
    'run --no-tty -- /bin/bash '* )
      [[ "$(cat "$TMPDIR_SMOKE/application-phases")" == $'a\nb\nclear' && "$(cat "$TMPDIR_SMOKE/ssh-phases")" == a ]] ||
        fail 'target lifecycle was not between clear projection proof and repeated SSH proof'
      [[ "$5" == "$PROVIDER_SSH_SCRIPT" ]] || fail 'wrong target fixture'
      case "$6" in
        cleanup) [[ $# == 6 && ! -e "$TMPDIR_SMOKE/ssh-target-actions" ]] ;;
        install) [[ $# == 7 && "$7" == /workspace/.cw-provider-ssh/selected.pub &&
          "$(cat "$TMPDIR_SMOKE/ssh-target-actions")" == cleanup ]] ;;
        startup) [[ $# == 6 && "$(cat "$TMPDIR_SMOKE/ssh-target-actions")" == $'cleanup\ninstall' ]] ;;
        *) fail 'unexpected target lifecycle action' ;;
      esac || fail 'target lifecycle order or preserved public authorization drifted'
      printf '%s\n' "$6" >>"$TMPDIR_SMOKE/ssh-target-actions"
      [[ "$FAILURE" != "target-$6" ]] || return 1 ;;
    *) fail "unexpected journey command: $*" ;;
  esac
}
fixture
LP_WORKSPACE="$TMPDIR_SMOKE"
local_platform_journey
pass
for invalid in create update clear projection-clear target-cleanup target-install target-startup; do
  fixture
  invalid_journey() { LP_WORKSPACE="$TMPDIR_SMOKE"; FAILURE="$invalid"; local_platform_journey; }
  expect_failure "$invalid" invalid_journey
  if [[ "$invalid" == projection-clear ]]; then
    [[ ! -e "$TMPDIR_SMOKE/ssh-target-actions" ]] || fail 'failed clear projection still reset the SSH target'
    ! grep -qx clear "$TMPDIR_SMOKE/ssh-phases" || fail 'failed clear projection still ran positive SSH proof'
  fi
  if [[ "$invalid" == target-* ]]; then
    ! grep -qx clear "$TMPDIR_SMOKE/ssh-phases" || fail 'failed target reset still ran positive SSH proof'
  fi
done

(
  fixture
  LP_APPLICATION_ONLY=1
  LP_WORKSPACE="$TMPDIR_SMOKE"
  PROVIDER_SSH_CREDENTIAL_ID=''; PROVIDER_SSH_PROFILE_ID=''
  prepare_provider_ssh() { fail 'application-only enrolled SSH'; }
  local_platform_ssh_prove() { fail 'application-only invoked provider proof'; }
  local_platform_ssh_reset_target() { fail 'application-only reset a provider target'; }
  local_platform_ssh_revoke() { fail 'application-only revoked a provider'; }
  local_platform_journey
  [[ "$(cat "$TMPDIR_SMOKE/application-phases")" == $'a\nb\nclear' ]] || fail 'application-only omitted source transitions'
  [[ ! -e "$TMPDIR_SMOKE/ssh-phases" && ! -e "$TMPDIR_SMOKE/ssh-target-actions" &&
     ! -e "$TMPDIR_SMOKE/provider.json" ]] || fail 'application-only created provider artifacts'
)
pass

# Each live provider owns a public create/use/run flow, not the application/SSH
# journey. Keep typed dispatch and parent ownership when a reply is lost.
for live_provider in codex anthropic openai github; do
(
  fixture
  LP_WORKSPACE="$TMPDIR_SMOKE"
  prepare_live_provider_fixture() {
    printf 'prepare\n' >>"$TMPDIR_SMOKE/codex-order"
    PROVIDER_CODEX_DOCUMENT="$TMPDIR_SMOKE/codex.json"
    jq -n --arg profile "platform:id:$PROFILE_ID" '{credentials:{profile:$profile}}' >"$PROVIDER_CODEX_DOCUMENT"
  }
  prepare_provider_codex() {
    [[ "$live_provider" == codex ]] || fail 'Anthropic prepared Codex'
    prepare_live_provider_fixture
  }
  prepare_provider_anthropic() {
    [[ "$live_provider" == anthropic ]] || fail 'Codex prepared Anthropic'
    prepare_live_provider_fixture
    PROVIDER_ANTHROPIC_DOCUMENT="$PROVIDER_CODEX_DOCUMENT"
  }
  prepare_provider_openai() {
    [[ "$live_provider" == openai ]] || fail 'another provider prepared OpenAI'
    prepare_live_provider_fixture
    PROVIDER_OPENAI_DOCUMENT="$PROVIDER_CODEX_DOCUMENT"
  }
  prepare_provider_github() {
    [[ "$live_provider" == github ]] || fail 'another provider prepared GitHub'
    prepare_live_provider_fixture
    PROVIDER_GITHUB_DOCUMENT="$PROVIDER_CODEX_DOCUMENT"
  }
  prepare_provider_ssh() { fail 'Codex prepared SSH'; }
  prepare_application_secrets() { fail 'Codex prepared application secrets'; }
  run_live_provider_fixture() {
    [[ "$ENV_ID" == "$VM_ID" && "$(cat "$TMPDIR_SMOKE/codex-order")" == $'prepare\ncreate\nuse' ]] ||
      fail 'Codex ran before binding the created local VM'
    printf 'run\n' >>"$TMPDIR_SMOKE/codex-order"
  }
  run_provider_codex_smoke() {
    [[ "$live_provider" == codex ]] || fail 'Anthropic ran Codex'
    run_live_provider_fixture
  }
  run_provider_anthropic_smoke() {
    [[ "$live_provider" == anthropic ]] || fail 'Codex ran Anthropic'
    run_live_provider_fixture
  }
  run_provider_openai_smoke() {
    [[ "$live_provider" == openai ]] || fail 'another provider ran OpenAI'
    run_live_provider_fixture
  }
  run_provider_github_smoke() {
    [[ "$live_provider" == github ]] || fail 'another provider ran GitHub'
    run_live_provider_fixture
  }
  cw_with_timeout() {
    local duration="$1"; shift
    case "$*" in
      'env list --local --output json') printf '[]\n' ;;
      'env create --local '*)
        [[ "$duration" == 1500 && "$LP_CREATE_ATTEMPTED" == 1 &&
           "$*" == "env create --local --name $SMOKE_NAME --cpu 2 --memory 16GB --no-docker --no-network --path $LP_WORKSPACE --path-mode copy --file codewire.yaml --yes --output json" ]] ||
          fail 'Codex changed owned create arguments or lost parent ownership'
        jq -e --arg image "$LOCAL_PLATFORM_IMAGE" --arg profile "platform:id:$PROFILE_ID" '
          .image == $image and .credentials.profile == $profile and (has("secrets") | not)
        ' "$LP_WORKSPACE/codewire.yaml" >/dev/null || fail 'Codex document selected other sources'
        printf 'create\n' >>"$TMPDIR_SMOKE/codex-order"
        [[ "$FAILURE" != create ]] || return 1
        jq -n --arg id "$VM_ID" '{id:$id}' ;;
      'use --local '*)
        [[ "$3" == "$VM_ID" ]] || fail 'Codex selected another local VM'
        printf 'use\n' >>"$TMPDIR_SMOKE/codex-order" ;;
      *) fail 'unexpected Codex journey command' ;;
    esac
  }
  journey_function=local_platform_codex_journey
  if [[ "$live_provider" == anthropic ]]; then journey_function=local_platform_anthropic_journey; fi
  if [[ "$live_provider" == openai ]]; then journey_function=local_platform_openai_journey; fi
  if [[ "$live_provider" == github ]]; then journey_function=local_platform_github_journey; fi
  "$journey_function"
  [[ "$LP_CREATE_ATTEMPTED" == 1 && "$(cat "$TMPDIR_SMOKE/codex-order")" == $'prepare\ncreate\nuse\nrun' ]] ||
    fail 'Codex journey did not preserve ownership or complete its proof'
  if ( FAILURE=create; "$journey_function" ) >"$TMPDIR_SMOKE/codex-failure.out" 2>&1; then
    fail 'Codex accepted failed creation'
  fi
)
pass
pass
done

# Cleanup must retire only the generated local VM and independently attempt all
# remote-object cleanup, including when creation acknowledgement was lost.
cleanup_provider_ssh_profile() { printf 'profile\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != profile ]]; }
cleanup_provider_ssh_credential() { printf 'credential\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != credential ]]; }
cleanup_provider_codex_profile() {
  [[ "$LP_LIVE_CODEX" == 1 ]] || return 0
  printf 'codex-profile\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != codex-profile ]]
}
cleanup_provider_codex_credential() {
  [[ "$LP_LIVE_CODEX" == 1 ]] || return 0
  printf 'codex-credential\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != codex-credential ]]
}
cleanup_provider_anthropic_profile() {
  [[ "$LP_LIVE_ANTHROPIC" == 1 ]] || return 0
  printf 'anthropic-profile\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != anthropic-profile ]]
}
cleanup_provider_anthropic_credential() {
  [[ "$LP_LIVE_ANTHROPIC" == 1 ]] || return 0
  printf 'anthropic-credential\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != anthropic-credential ]]
}
cleanup_provider_openai_profile() {
  [[ "$LP_LIVE_OPENAI" == 1 ]] || return 0
  printf 'openai-profile\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != openai-profile ]]
}
cleanup_provider_openai_credential() {
  [[ "$LP_LIVE_OPENAI" == 1 ]] || return 0
  printf 'openai-credential\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != openai-credential ]]
}
cleanup_provider_github_profile() {
  [[ "$LP_LIVE_GITHUB" == 1 ]] || return 0
  printf 'github-profile\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != github-profile ]]
}
cleanup_provider_github_credential() {
  [[ "$LP_LIVE_GITHUB" == 1 ]] || return 0
  printf 'github-credential\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != github-credential ]]
}
cleanup_application_secrets() {
  [[ -z "$ENV_ID" ]] || fail 'local ID sent to platform environment cleanup'
  printf 'projects\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != projects ]]
}
local_platform_stop_owners() { printf 'owners\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != owners ]]; }
assert_application_artifacts_redacted() { [[ "$FAILURE" != leakage ]]; }
cw_with_timeout() {
  shift
  case "$*" in
    'env list --local --output json')
      if [[ -e "$TMPDIR_SMOKE/deleted" ]]; then printf '[]\n'; else
        jq -n --arg id "$VM_ID" --arg name "$SMOKE_NAME" --arg failure "$FAILURE" '
          [{id:$id,name:$name}] |
          if $failure == "ambiguous" then . + . elif $failure == "rebound" then .[0].id="11111111-1111-4111-8111-111111111111" else . end'
      fi ;;
    'env rm --local --yes '*)
      [[ "$5" == "$VM_ID" ]] || fail 'deleted a different VM'
      printf 'vm\n' >>"$TMPDIR_SMOKE/cleanup-calls"
      [[ "$FAILURE" != rm ]] || return 1
      touch "$TMPDIR_SMOKE/deleted" ;;
    'env info --local '*" --output json")
      [[ "$4" == "$VM_ID" && ! -e "$TMPDIR_SMOKE/deleted" ]] || fail 'launch observation changed ownership/order'
      [[ "$FAILURE" != info-failure ]] || return 1
      jq -n --arg id "$VM_ID" --arg failure "$FAILURE" '
        {id:$id,state:"error",error_code:"guest_start_failed"} |
        if $failure == "info-rebound" then .id="unowned"
        elif $failure == "info-opaque" then .error_code="opaque-provider-material-canary"
        elif $failure == "info-false" then .error_code=false
        elif $failure == "info-array" then .error_code=["prepare_failed"]
        elif $failure == "info-state" then .state="opaque-provider-material-canary" else . end' ;;
    'network nodes --network '*" --output json")
      [[ "$4" == "$LOCAL_PLATFORM_NETWORK_ID" && "$6" == "$ORG_ID" ]] || fail 'cleanup inspected a different network'
      [[ "$FAILURE" != network-list ]] || return 1
      if [[ -n "$FIXTURE_NETWORK_NODES_JSON" ]]; then printf '%s\n' "$FIXTURE_NETWORK_NODES_JSON"; return 0; fi
      if [[ "${CLEANUP_NETWORK_ABSENT:-0}" == 1 || -e "$TMPDIR_SMOKE/network-node-revoked" ]]; then
        printf '[]\n'
      else
        jq -n --arg network "$LOCAL_PLATFORM_NETWORK_ID" --arg name "$SMOKE_NAME" \
          '[{network_id:$network,name:$name,peer_url:"synthetic.invalid",connected:false}]'
      fi ;;
    'network revoke --network '*)
      [[ "$4" == "$LOCAL_PLATFORM_NETWORK_ID" && "$6" == "$ORG_ID" && "$7" == "$SMOKE_NAME" ]] ||
        fail 'cleanup revoked a different network node'
      printf 'network\n' >>"$TMPDIR_SMOKE/cleanup-calls"
      [[ "$FAILURE" != network-revoke ]] || return 1
      touch "$TMPDIR_SMOKE/network-node-revoked" ;;
    'network list --org '*" --output json")
      [[ "$4" == "$ORG_ID" ]] || fail 'cleanup inspected another organization'
      if [[ "$FAILURE" == malformed-networks ]]; then printf '{}\n'; return 0; fi
      if [[ -e "$TMPDIR_SMOKE/network-deleted" ]]; then printf '[]\n'; else
        jq -n --arg id "$LOCAL_PLATFORM_NETWORK_ID" --arg org "$ORG_ID" '[{id:$id,org_id:$org}]'
      fi ;;
    'network delete '*)
      [[ "$*" == "network delete $SMOKE_NAME-mesh --org $ORG_ID --yes" &&
         -e "$TMPDIR_SMOKE/deleted" && -e "$TMPDIR_SMOKE/network-node-revoked" ]] ||
        fail 'network deleted before owned VM/node cleanup'
      printf 'network-delete\n' >>"$TMPDIR_SMOKE/cleanup-calls"
      [[ "$FAILURE" != network-delete ]] || return 1
      touch "$TMPDIR_SMOKE/network-deleted"
      printf '{}\n' ;;
    logout) printf 'logout\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != logout ]] ;;
    *) fail "unexpected cleanup command: $*" ;;
  esac
}
cleanup_fixture() {
  fixture
  LP_CREATE_ATTEMPTED=1
  LP_HOME="$TMPDIR_SMOKE/h"; mkdir -m 700 "$LP_HOME"
  LP_RUNTIME="$(mktemp -d "$TMPDIR_SMOKE/.cwlp-XXXXXX")"
  CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$LP_RUNTIME/login"; mkdir -m 700 "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR"
  LP_LOGIN_ATTEMPTED=1
  : >"$TMPDIR_SMOKE/cleanup-calls"
}
selected_network_cleanup_fixture() {
  cleanup_fixture
  LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
  LP_NETWORK_NODE_OWNED=1
  CLEANUP_NETWORK_ABSENT=0
}
disposable_network_cleanup_fixture() {
  selected_network_cleanup_fixture
  LOCAL_PLATFORM_DISPOSABLE_NETWORK=1
  LOCAL_PLATFORM_NETWORK_ID="$SMOKE_NAME-mesh"
  LP_NETWORK_CREATE_ATTEMPTED=1
}
run_cleanup() { ( trap local_platform_cleanup EXIT; exit 0 ); }
cleanup_fixture
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
[[ ! -e "$LP_HOME" && ! -e "$LP_RUNTIME" ]] || fail 'successful cleanup retained local state'
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nprofile\ncredential\nprojects\nowners\nlogout' ]] || fail 'incomplete cleanup ordering'
pass
for observation in fixed info-failure info-rebound info-opaque info-false info-array info-state; do
  cleanup_fixture
  FAILURE="$observation"
  failed_launch_cleanup() { ( trap local_platform_cleanup EXIT; exit 1 ); }
  expect_failure "$observation launch cleanup" failed_launch_cleanup
  [[ -e "$TMPDIR_SMOKE/deleted" && ! -e "$LP_RUNTIME" ]] || fail 'launch observer prevented cleanup'
  jq -e '. == []' "$TMPDIR_SMOKE/local-cleanup-environments.json" >/dev/null || fail 'launch cleanup lost final absence proof'
  ! rg -q opaque-provider-material-canary "$TMPDIR_SMOKE/local-failed-launch.json" || fail 'launch observer retained opaque material'
  if [[ "$observation" == fixed ]]; then
    jq -e --arg id "$VM_ID" '.observation == "observed" and .id == $id and
      .state == "error" and .code_recognized == true and .error_code == "guest_start_failed"' \
      "$TMPDIR_SMOKE/local-failed-launch.json" >/dev/null || fail 'fixed launch metadata was lost'
  elif [[ "$observation" == info-opaque || "$observation" == info-false || "$observation" == info-array ]]; then
    jq -e '.observation == "observed" and .code_recognized == false and .error_code == null' \
      "$TMPDIR_SMOKE/local-failed-launch.json" >/dev/null || fail 'unknown launch class was fabricated'
  else
    jq -e '. == {observation:"unavailable"}' "$TMPDIR_SMOKE/local-failed-launch.json" >/dev/null || fail 'observer failure became a VM failure'
  fi
  pass
done
selected_network_cleanup_fixture
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nnetwork\nprofile\ncredential\nprojects\nowners\nlogout' ]] ||
  fail 'selected-network cleanup did not revoke after environment deletion'
pass
disposable_network_cleanup_fixture
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nnetwork\nnetwork-delete\nprofile\ncredential\nprojects\nowners\nlogout' ]] ||
  fail 'disposable network cleanup did not follow VM/node cleanup'
pass
for invalid in malformed-networks network-delete; do
  failed_disposable_cleanup() {
    disposable_network_cleanup_fixture
    FAILURE="$invalid"
    run_cleanup
  }
  expect_failure "$invalid" failed_disposable_cleanup
done
selected_network_cleanup_fixture
CLEANUP_NETWORK_ABSENT=1
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
! grep -qx network "$TMPDIR_SMOKE/cleanup-calls" || fail 'absent network node was revoked'
pass
selected_network_cleanup_fixture
FIXTURE_NETWORK_NODES_JSON='[{}]'
expect_failure malformed-network-cleanup run_cleanup
! grep -qx network "$TMPDIR_SMOKE/cleanup-calls" || fail 'malformed inventory authorized node revocation'
grep -qx projects "$TMPDIR_SMOKE/cleanup-calls" || fail 'invalid network inventory prevented independent project cleanup'
pass
selected_network_cleanup_fixture
ENV_ID=''
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
grep -qx vm "$TMPDIR_SMOKE/cleanup-calls" || fail 'lost create acknowledgement did not resolve owned VM'
grep -qx network "$TMPDIR_SMOKE/cleanup-calls" || fail 'lost create acknowledgement did not reconcile owned network node'
pass
cleanup_fixture
LOCAL_PLATFORM_NETWORK_ID=shared-dev-network
LP_NETWORK_NODE_OWNED=0
LP_CREATE_ATTEMPTED=0
FAILURE=collision
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
! grep -qx network "$TMPDIR_SMOKE/cleanup-calls" || fail 'pre-create collision revoked an unowned network node'
pass
cleanup_fixture
ENV_ID=''
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
[[ ! -e "$LP_HOME" && ! -e "$LP_RUNTIME" ]] || fail 'lost-response cleanup retained state'
pass
for invalid in rebound ambiguous rm profile credential projects owners logout leakage network-list network-revoke; do
  if [[ "$invalid" == network-* ]]; then selected_network_cleanup_fixture; else cleanup_fixture; fi
  FAILURE="$invalid"
  expect_failure "$invalid cleanup" run_cleanup
  for surface in profile credential projects owners logout; do
    grep -qx "$surface" "$TMPDIR_SMOKE/cleanup-calls" || fail "$invalid cleanup skipped $surface"
  done
  [[ ! -e "$CODEWIRE_ADMIN_OAUTH_CONFIG_DIR" && -d "$LP_HOME" ]] || fail 'cleanup retained login or erased failed evidence'
  if [[ "$invalid" == rebound || "$invalid" == ambiguous ]]; then
    ! grep -qx vm "$TMPDIR_SMOKE/cleanup-calls" || fail 'deleted ambiguous/rebound VM'
  fi
done
cleanup_fixture
LP_LIVE_CODEX=1
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
grep -Fq 'PASS: stock Codex request' "$TMPDIR_SMOKE/cleanup-result.out" || fail 'Codex cleanup omitted its named PASS'
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nprofile\ncredential\ncodex-profile\ncodex-credential\nprojects\nowners\nlogout' ]] ||
  fail 'Codex cleanup skipped an independent owned surface'
pass
for invalid in codex-profile codex-credential rm logout; do
  cleanup_fixture
  LP_LIVE_CODEX=1; FAILURE="$invalid"
  expect_failure "$invalid Codex cleanup" run_cleanup
  for surface in codex-profile codex-credential logout; do
    grep -qx "$surface" "$TMPDIR_SMOKE/cleanup-calls" || fail 'failed Codex cleanup skipped another surface'
  done
  if grep -Fq 'PASS:' "$TEST_ROOT/failure.out"; then fail 'Codex passed before successful cleanup'; fi
done
cleanup_fixture
LP_LIVE_ANTHROPIC=1
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
grep -Fq 'PASS: stock Claude request' "$TMPDIR_SMOKE/cleanup-result.out" || fail 'Anthropic cleanup omitted its named PASS'
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nprofile\ncredential\nanthropic-profile\nanthropic-credential\nprojects\nowners\nlogout' ]] ||
  fail 'Anthropic cleanup skipped an independent owned surface'
pass
for invalid in anthropic-profile anthropic-credential rm logout; do
  cleanup_fixture
  LP_LIVE_ANTHROPIC=1; FAILURE="$invalid"
  expect_failure "$invalid Anthropic cleanup" run_cleanup
  for surface in anthropic-profile anthropic-credential logout; do
    grep -qx "$surface" "$TMPDIR_SMOKE/cleanup-calls" || fail 'failed Anthropic cleanup skipped another surface'
  done
  if grep -Fq 'PASS:' "$TEST_ROOT/failure.out"; then fail 'Anthropic passed before successful cleanup'; fi
done
cleanup_fixture
LP_LIVE_OPENAI=1
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
grep -Fq 'PASS: OpenAI Responses HTTP request' "$TMPDIR_SMOKE/cleanup-result.out" || fail 'OpenAI cleanup omitted its named PASS'
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nprofile\ncredential\nopenai-profile\nopenai-credential\nprojects\nowners\nlogout' ]] ||
  fail 'OpenAI cleanup skipped an independent owned surface'
pass
for invalid in openai-profile openai-credential rm logout; do
  cleanup_fixture
  LP_LIVE_OPENAI=1; FAILURE="$invalid"
  expect_failure "$invalid OpenAI cleanup" run_cleanup
  for surface in openai-profile openai-credential logout; do
    grep -qx "$surface" "$TMPDIR_SMOKE/cleanup-calls" || fail 'failed OpenAI cleanup skipped another surface'
  done
  if grep -Fq 'PASS:' "$TEST_ROOT/failure.out"; then fail 'OpenAI passed before successful cleanup'; fi
done
cleanup_fixture
LP_LIVE_GITHUB=1
run_cleanup >"$TMPDIR_SMOKE/cleanup-result.out" 2>&1
grep -Fq 'PASS: stock gh read-only account request' "$TMPDIR_SMOKE/cleanup-result.out" || fail 'GitHub cleanup omitted named PASS'
[[ "$(cat "$TMPDIR_SMOKE/cleanup-calls")" == $'vm\nprofile\ncredential\ngithub-profile\ngithub-credential\nprojects\nowners\nlogout' ]] ||
  fail 'GitHub cleanup skipped an owned surface'
pass
for invalid in github-profile github-credential rm logout leakage; do
  cleanup_fixture
  LP_LIVE_GITHUB=1; FAILURE="$invalid"
  expect_failure "$invalid GitHub cleanup" run_cleanup
  for surface in github-profile github-credential logout; do
    grep -qx "$surface" "$TMPDIR_SMOKE/cleanup-calls" || fail 'failed GitHub cleanup skipped another surface'
  done
  if grep -Fq 'PASS:' "$TEST_ROOT/failure.out"; then fail 'GitHub passed before cleanup'; fi
done
printf 'Local/platform smoke fixtures passed (%s cases)\n' "$COUNT"
