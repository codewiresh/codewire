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
    'env info --local '*" --output json")
      jq -n --arg id "$ENV_ID" --arg project "platform:id:$PROJECT_ID" --arg profile "platform:id:$PROFILE_ID" \
        --arg server "$CODEWIRE_SERVER_URL" --arg user "$LP_USER_ID" --arg org "$ORG_ID" --arg failure "$FAILURE" '
        {id:$id,backend:"cloud-hypervisor",state:"running",cpu:2,memory:"16Gi",generation:1,
         source_selection:{credentials:{profile:$profile,reference:"user/owned-profile",revision:1},
           secrets:{project:$project},platform:{server_url:$server,organization_id:$org,user_id:$user}}} |
        if $failure == "wrong-vm" then .id="unowned"
        elif $failure == "wrong-profile" then .source_selection.credentials.profile="local:owned-profile"
        elif $failure == "wrong-revision" then .source_selection.credentials.revision=2
        elif $failure == "wrong-project" then .source_selection.secrets.project="local:project"
        elif $failure == "wrong-user" then .source_selection.platform.user_id="unowned"
        elif $failure == "wrong-org" then .source_selection.platform.organization_id="unowned"
        elif $failure == "wrong-server" then .source_selection.platform.server_url="https://wrong.invalid"
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
    [[ "$*" == 'run --no-tty -- /bin/sh -c '* ]] || fail 'unexpected non-PTY application command'
    printf 'application-secret-check-ok\n'
  }
  local_platform_binding() { printf '{"generation":1}\n' >"$TMPDIR_SMOKE/local-environment.json"; }
  local_platform_guest_check() { printf '%s' "$SYNTHETIC_GUEST_CHECK"; }
  SYNTHETIC_GUEST_CHECK="printf 'application-secret-check-ok\\n'"
  local_platform_application_phase actual synthetic expected
  SYNTHETIC_GUEST_CHECK="printf 'application-secret-check-ok\\n'; exit 7"
  expect_failure pty-exit-status local_platform_application_phase failure synthetic expected
  SYNTHETIC_GUEST_CHECK="printf 'application-secret-check-ok\\n'"
  LP_ENV+=(LOCAL_PTY_WITHOUT_TERMINAL=1)
  expect_failure missing-guest-pty local_platform_application_phase no-pty synthetic expected
)
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
}
local_platform_ssh_prove() { printf '%s\n' "$(cat "$TMPDIR_SMOKE/phase")" >>"$TMPDIR_SMOKE/ssh-phases"; }
local_platform_ssh_revoke() {
  [[ "$(cat "$TMPDIR_SMOKE/ssh-phases")" == $'a\nclear' ]] || fail 'SSH not proved with both selected and cleared app sources'
}
cw_with_timeout() {
  shift
  case "$*" in
    'env list --local --output json') printf '[]\n' ;;
    'env create --local '*)
      [[ "$*" == "env create --local --name $SMOKE_NAME --cpu 2 --memory 16GB --no-docker --no-network --path $LP_WORKSPACE --path-mode copy --file codewire.yaml --yes --output json" ]] || fail 'unsupported native create command'
      jq -e --arg profile "platform:id:$PROFILE_ID" --arg project "platform:id:$PROJECT_ID" --arg image "$LOCAL_PLATFORM_IMAGE" '
        .credentials.profile == $profile and .secrets.project == $project and .image == $image and
        .install_command == "app-install; ssh-install" and .startup_script == "app-startup; ssh-startup"' \
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
    *) fail "unexpected journey command: $*" ;;
  esac
}
fixture
LP_WORKSPACE="$TMPDIR_SMOKE"
local_platform_journey
pass
for invalid in create update clear; do
  invalid_journey() { fixture; LP_WORKSPACE="$TMPDIR_SMOKE"; FAILURE="$invalid"; local_platform_journey; }
  expect_failure "$invalid" invalid_journey
done

# Cleanup must retire only the generated local VM and independently attempt all
# remote-object cleanup, including when creation acknowledgement was lost.
cleanup_provider_ssh_profile() { printf 'profile\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != profile ]]; }
cleanup_provider_ssh_credential() { printf 'credential\n' >>"$TMPDIR_SMOKE/cleanup-calls"; [[ "$FAILURE" != credential ]]; }
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
printf 'Local/platform smoke fixtures passed (%s cases)\n' "$COUNT"
