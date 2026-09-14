#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEST_ROOT="$(mktemp -d /var/tmp/cw-acceptance-runner-test.XXXXXXXX)"
RUNTIME_ROOT="$(mktemp -d /dev/shm/cw-acceptance-runner-runtime.XXXXXXXX)"
trap 'rm -rf -- "$TEST_ROOT" "$RUNTIME_ROOT"' EXIT
chmod 0700 "$RUNTIME_ROOT"

FAKE_ROOT="$TEST_ROOT/repo"
CALLS="$FAKE_ROOT/fixtures/calls"
SIGNAL_MARKER="$FAKE_ROOT/fixtures/signal-events"
mkdir -p "$FAKE_ROOT/scripts/runtime/dev" "$FAKE_ROOT/scripts/ci/verify" \
  "$FAKE_ROOT/fixtures/native-artifacts" "$FAKE_ROOT/fixtures/local-artifacts" \
  "$FAKE_ROOT/fake-bin" "$RUNTIME_ROOT/provider-login"
chmod 0700 "$RUNTIME_ROOT/provider-login"
cp "$REPO_ROOT/scripts/runtime/dev/run-secrets-credentials-acceptance.sh" \
  "$FAKE_ROOT/scripts/runtime/dev/run-secrets-credentials-acceptance.sh"
chmod 0755 "$FAKE_ROOT/scripts/runtime/dev/run-secrets-credentials-acceptance.sh"

cat >"$FAKE_ROOT/child-stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"
fixtures="$root/fixtures"
calls="$fixtures/calls"
signal_marker="$fixtures/signal-events"
label=""
case "$0" in
  */smoke-native-local-environment.sh) label=native-local ;;
  */smoke-local-platform-sources.sh)
    if [[ " $* " == *' --initial-private-checkout '* ]]; then
      label=initial-private-checkout
    elif [[ "${LOCAL_PLATFORM_DISPOSABLE_NETWORK:-}" == 1 ]]; then
      label=local-platform-mesh
    else
      label=local-platform
    fi
    ;;
  */runtime-dev-commodity-smoke.sh)
    case " $* " in
      *' --only application-secrets-all-scopes '*) label=dev-application-all-scopes ;;
      *' --only provider-ssh '*) label=dev-provider-ssh ;;
      *) exit 91 ;;
    esac
    ;;
  *) exit 92 ;;
esac
case "$label" in
  native-local)
    [[ " $* " == *' --managed-credential-broker '* &&
       " $* " == *' --workspace-image-import-bin '* &&
       " $* " == *" --cw-bin $fixtures/cw-local-credential-broker-smoke "* ]] || exit 93
    ;;
  local-platform)
    [[ "$*" == "--admin-oidc --cw-bin $fixtures/normal-cw" &&
       "${LOCAL_PLATFORM_DISPOSABLE_NETWORK:-}" == 0 &&
       -z "${LOCAL_PLATFORM_NETWORK_ID+x}" &&
       -z "${LOCAL_PLATFORM_MESH_PROBE_BIN+x}" ]] || exit 94
    ;;
  initial-private-checkout)
    [[ "$*" == "--admin-oidc --cw-bin $fixtures/normal-cw --initial-private-checkout" &&
       "${LOCAL_PLATFORM_DISPOSABLE_NETWORK:-}" == 0 &&
       "${LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN:-}" == "$fixtures/checkout-fixture" &&
       -z "${LOCAL_PLATFORM_NETWORK_ID+x}" &&
       -z "${LOCAL_PLATFORM_MESH_PROBE_BIN+x}" ]] || exit 102
    ;;
  local-platform-mesh)
    [[ "$*" == "--admin-oidc --cw-bin $fixtures/normal-cw" &&
       "${LOCAL_PLATFORM_DISPOSABLE_NETWORK:-}" == 1 &&
       -z "${LOCAL_PLATFORM_NETWORK_ID+x}" &&
       "${LOCAL_PLATFORM_MESH_PROBE_BIN:-}" == "$fixtures/dev-mesh-probe" ]] || exit 98
    ;;
  dev-application-all-scopes)
    [[ "$*" == "--admin-oidc --cw-bin $fixtures/normal-cw --only application-secrets-all-scopes" &&
       -z "${CODEWIRE_ADMIN_OAUTH_CONFIG_DIR+x}" && -z "${CW_CONFIG_DIR+x}" ]] || exit 95
    ;;
  dev-provider-ssh)
    [[ "$*" == "--admin-oidc --cw-bin $fixtures/normal-cw --only provider-ssh" ]] || exit 96
    if [[ -n "${DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE:-}" ]]; then
      [[ -z "${CODEWIRE_ADMIN_OAUTH_CONFIG_DIR:-}" &&
         "$DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE" == "$fixtures/browser-input.json" &&
         "$DEV_SMOKE_BROWSER_AUTH_BUN_BIN" == "$fixtures/synthetic-bun" &&
         "$DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN" == "$fixtures/synthetic-chromium" &&
         "$EXPECTED_CODEWIRE_ADMIN_USER_ID" == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa &&
         "$EXPECTED_CODEWIRE_ORGANIZATION_ID" == bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]] || exit 101
    else
      [[ "${CODEWIRE_ADMIN_OAUTH_CONFIG_DIR:-}" == "${XDG_RUNTIME_DIR:-}/provider-login" ]] || exit 96
    fi
    ;;
esac
for forbidden in CODEWIRE_API_KEY CODEWIRE_DEV_SMOKE_API_KEY CW_CONFIG_DIR \
    ALLOW_GENERIC_CODEWIRE_API_KEY_FOR_SMOKE OPENAI_API_KEY CODEX_HOME \
    SSH_AUTH_SOCK BAO_TOKEN HTTPS_PROXY HTTP_PROXY ALL_PROXY NO_PROXY; do
  [[ -z "${!forbidden+x}" ]] || exit 97
done
[[ "$HOME" == /nonexistent && "$PATH" == /usr/local/bin:/usr/bin:/bin ]] || exit 99
printf '%s\n' "$label" >>"$calls"
printf 'opaque child output: %s\n' "$label"
if [[ -f "$fixtures/stdin-$label" ]]; then
  IFS= read -r approval
  [[ "$approval" == owner-approval ]] || exit 100
  printf 'stdin-read\n' >>"$signal_marker"
fi
if [[ -f "$fixtures/signal-$label" ]]; then
  trap 'printf "child-cleanup-HUP\n" >>"$signal_marker"; exit 129' HUP
  trap 'printf "child-cleanup-INT\n" >>"$signal_marker"; exit 130' INT
  trap 'printf "child-cleanup-TERM\n" >>"$signal_marker"; exit 143' TERM
  printf '%s\n' "$$" >"$fixtures/child-pid"
  printf 'child-started\n' >>"$signal_marker"
  "$fixtures/foreground-blocker"
fi
[[ ! -f "$fixtures/fail-$label" ]] || exit 17
STUB
chmod 0755 "$FAKE_ROOT/child-stub"
for child in \
    "$FAKE_ROOT/scripts/runtime/dev/smoke-local-platform-sources.sh" \
    "$FAKE_ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh" \
    "$FAKE_ROOT/scripts/ci/verify/smoke-native-local-environment.sh"; do
  cp "$FAKE_ROOT/child-stub" "$child"
done

cat >"$FAKE_ROOT/fixtures/foreground-blocker" <<'BLOCKER'
#!/usr/bin/env bash
set -u
fixtures="$(cd "$(dirname "$0")" && pwd)"
trap 'printf "foreground-cleanup-HUP\n" >>"$fixtures/signal-events"; exit 129' HUP
trap 'printf "foreground-cleanup-INT\n" >>"$fixtures/signal-events"; exit 130' INT
trap 'printf "foreground-cleanup-TERM\n" >>"$fixtures/signal-events"; exit 143' TERM
printf '%s\n' "$$" >"$fixtures/foreground-pid"
while :; do sleep 1; done
BLOCKER
chmod 0755 "$FAKE_ROOT/fixtures/foreground-blocker"

cat >"$FAKE_ROOT/fake-bin/setsid" <<'EARLY_SETSID'
#!/usr/bin/env bash
set -u
fixtures="$(cd "$(dirname "$0")/../fixtures" && pwd)"
trap 'printf "early-launcher-cleanup-start\n" >>"$fixtures/signal-events"; sleep 0.3; printf "early-launcher-cleanup-done\n" >>"$fixtures/signal-events"; exit 143' TERM
printf '%s\n' "$$" >"$fixtures/early-launcher-pid"
printf 'early-launcher-started\n' >>"$fixtures/signal-events"
while :; do sleep 1; done
EARLY_SETSID
chmod 0755 "$FAKE_ROOT/fake-bin/setsid"

for executable in normal-cw cw-local-credential-broker-smoke mesh derp data-plane \
    credential-bridge state-probe image-import checkout-fixture; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$FAKE_ROOT/fixtures/$executable"
  chmod 0755 "$FAKE_ROOT/fixtures/$executable"
done
printf '#!/usr/bin/env bash\nexit 0\n' >"$FAKE_ROOT/fixtures/dev-mesh-probe"
chmod 0755 "$FAKE_ROOT/fixtures/dev-mesh-probe"
: >"$FAKE_ROOT/fixtures/native-artifacts.lock"
: >"$FAKE_ROOT/fixtures/local-artifacts.lock"
: >"$FAKE_ROOT/fixtures/kubeconfig"

export ACCEPTANCE_NORMAL_CW_BIN="$FAKE_ROOT/fixtures/normal-cw"
export ACCEPTANCE_SYNTHETIC_CW_BIN="$FAKE_ROOT/fixtures/cw-local-credential-broker-smoke"
export ACCEPTANCE_NATIVE_MESH_BIN="$FAKE_ROOT/fixtures/mesh"
export ACCEPTANCE_NATIVE_DERP_BIN="$FAKE_ROOT/fixtures/derp"
export ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN="$FAKE_ROOT/fixtures/data-plane"
export ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN="$FAKE_ROOT/fixtures/credential-bridge"
export ACCEPTANCE_NATIVE_STATE_PROBE_BIN="$FAKE_ROOT/fixtures/state-probe"
export ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN="$FAKE_ROOT/fixtures/image-import"
export ACCEPTANCE_NATIVE_ARTIFACT_ROOT="$FAKE_ROOT/fixtures/native-artifacts"
export ACCEPTANCE_NATIVE_ARTIFACT_LOCK="$FAKE_ROOT/fixtures/native-artifacts.lock"
export ACCEPTANCE_NATIVE_SCRATCH_PARENT="$TEST_ROOT"
export ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR="$RUNTIME_ROOT/provider-login"
export LOCAL_PLATFORM_ARTIFACT_ROOT="$FAKE_ROOT/fixtures/local-artifacts"
export LOCAL_PLATFORM_ARTIFACT_LOCK="$FAKE_ROOT/fixtures/local-artifacts.lock"
export LOCAL_PLATFORM_IMAGE=registry.example/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export LOCAL_PLATFORM_NETWORK_ID=must-not-reach-baseline-or-mesh
export LOCAL_PLATFORM_DISPOSABLE_NETWORK=1
export LOCAL_PLATFORM_MESH_PROBE_BIN="$FAKE_ROOT/fixtures/dev-mesh-probe"
export LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="$FAKE_ROOT/fixtures/checkout-fixture"
export EXPECTED_CODEWIRE_ADMIN_EMAIL=owner@example.test
export EXPECTED_CODEWIRE_ADMIN_USER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export EXPECTED_CODEWIRE_ORGANIZATION_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
export CODEWIRE_SERVER_URL=https://codewire-dev.sh
export EXPECTED_CODEWIRE_DEV_SERVER_URL=https://codewire-dev.sh
export KUBECONFIG="$FAKE_ROOT/fixtures/kubeconfig"
export KUBE_CONTEXT=codewire-dev
export CODEWIRE_SERVER_NAMESPACE=dev
export SANDBOX_NAMESPACE=dev-sandboxes
export EXPECTED_NODE=node.example
export EXPECTED_TAILNET_PEER_RELAY_ENDPOINT=192.0.2.1:41641
export EXPECTED_UDP_RELAY_BIND_ADDRS=relay.dev:41641
export EXPECTED_UDP_RELAY_ALLOCATOR_URL=http://allocator.dev
export EXPECTED_TAILNET_DIRECT_UDP_LB_IP=192.0.2.2
export EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE=dev
export EXPECTED_RUNTIME_TRANSPORT_REGION=test
export XDG_RUNTIME_DIR="$RUNTIME_ROOT"
export SMOKE_TMP_PARENT="$TEST_ROOT"
export CODEWIRE_API_KEY=must-not-reach-child
export CODEWIRE_DEV_SMOKE_API_KEY=must-not-reach-child
export CODEWIRE_ADMIN_OAUTH_CONFIG_DIR=/must/not/reach/child
export CW_CONFIG_DIR=/must/not/reach/child
export OPENAI_API_KEY=must-not-reach-child
export CODEX_HOME=/must/not/reach/child
export SSH_AUTH_SOCK=/must/not/reach/child
export BAO_TOKEN=must-not-reach-child
unset DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE DEV_SMOKE_BROWSER_AUTH_BUN_BIN DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN
export HTTPS_PROXY=http://must-not-reach-child
export HTTP_PROXY=http://must-not-reach-child
export ALL_PROXY=socks5://must-not-reach-child
export NO_PROXY=must-not-reach-child

RUNNER="$FAKE_ROOT/scripts/runtime/dev/run-secrets-credentials-acceptance.sh"
CASES=0
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { CASES=$((CASES + 1)); }
expect_status() {
  local expected="$1" output="$2"
  shift 2
  local status=0
  "$@" >"$output" 2>&1 || status=$?
  [[ "$status" == "$expected" ]] || fail "exit $status, expected $expected: $*"
}

: >"$CALLS"
expect_status 0 "$TEST_ROOT/local-platform.out" "$RUNNER" --only local-platform
[[ "$(cat "$CALLS")" == local-platform ]] || fail 'selected retry invoked another journey'
grep -Fq 'local-platform                 PASS' "$TEST_ROOT/local-platform.out" ||
  fail 'selected local/platform result was not independently reported'
grep -Fq 'selected result: PASS; full acceptance: NOT CLAIMED' "$TEST_ROOT/local-platform.out" ||
  fail 'selected retry claimed the full matrix'
pass

: >"$CALLS"
expect_status 0 "$TEST_ROOT/local-platform-mesh.out" "$RUNNER" --only local-platform-mesh
[[ "$(cat "$CALLS")" == local-platform-mesh ]] || fail 'named Mesh retry invoked another journey'
grep -Fq 'local-platform-mesh            PASS' "$TEST_ROOT/local-platform-mesh.out" ||
  fail 'named Mesh result was not independently reported'
pass

: >"$CALLS"
saved_normal_cw="$ACCEPTANCE_NORMAL_CW_BIN"
export ACCEPTANCE_NORMAL_CW_BIN="$ACCEPTANCE_SYNTHETIC_CW_BIN"
expect_status 1 "$TEST_ROOT/wrong-normal-cw.out" "$RUNNER" --only local-platform
export ACCEPTANCE_NORMAL_CW_BIN="$saved_normal_cw"
[[ ! -s "$CALLS" ]] || fail 'synthetic smoke CLI was accepted as the normal CLI'
grep -Fq 'explicit normal CLI/local platform inputs unavailable' "$TEST_ROOT/wrong-normal-cw.out" ||
  fail 'normal/synthetic CLI separation was not reported'
pass

: >"$CALLS"
expect_status 1 "$TEST_ROOT/default.out" "$RUNNER"
printf '%s\n' native-local local-platform dev-application-all-scopes dev-provider-ssh local-platform-mesh initial-private-checkout \
  | cmp -s - "$CALLS" || fail 'default matrix did not invoke each available fixed child once'
grep -Fq 'live-providers                 NOT RUN (no checked-in live Codex/GitHub/OpenAI/Anthropic journey)' \
  "$TEST_ROOT/default.out" || fail 'missing live providers were not reported honestly'
grep -Eq 'initial-private-checkout +PASS' "$TEST_ROOT/default.out" || fail 'local private checkout did not run'
grep -Fq 'dev-initial-private-checkout   NOT RUN (no checked-in hosted initial private-checkout journey)' \
  "$TEST_ROOT/default.out" || fail 'missing hosted private checkout was not reported honestly'
grep -Fq 'aggregate result: INCOMPLETE; full acceptance: NOT CLAIMED' "$TEST_ROOT/default.out" ||
  fail 'default matrix claimed completion'
pass

: >"$CALLS"
expect_status 0 "$TEST_ROOT/checkout.out" "$RUNNER" --only initial-private-checkout
[[ "$(cat "$CALLS")" == initial-private-checkout ]] || fail 'selected checkout ran another journey'
pass
saved_checkout_fixture="$LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN"
export LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="$TEST_ROOT/missing"
: >"$CALLS"
expect_status 1 "$TEST_ROOT/checkout-missing.out" "$RUNNER" --only initial-private-checkout
[[ ! -s "$CALLS" ]] || fail 'missing checkout fixture started a journey'
export LOCAL_PLATFORM_CHECKOUT_FIXTURE_BIN="$saved_checkout_fixture"
pass

: >"$CALLS"
touch "$FAKE_ROOT/fixtures/fail-native-local"
expect_status 1 "$TEST_ROOT/failure.out" "$RUNNER"
rm "$FAKE_ROOT/fixtures/fail-native-local"
[[ "$(cat "$CALLS")" == native-local ]] || fail 'runner continued after cleanup-ambiguous failure'
grep -Fq 'native-local                   FAIL (child exit 17; cleanup state unknown)' "$TEST_ROOT/failure.out" ||
  fail 'child failure was not reported'
grep -Fq 'local-platform                 NOT RUN (prior child failed; cleanup state unknown)' \
  "$TEST_ROOT/failure.out" || fail 'remaining journey was not stopped after failure'
pass

: >"$CALLS"
saved_provider_dir="$ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR"
export ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR=''
expect_status 1 "$TEST_ROOT/provider-missing.out" "$RUNNER" --only dev-provider-ssh
export ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR="$saved_provider_dir"
[[ ! -s "$CALLS" ]] || fail 'provider journey ran without an explicit fresh OAuth directory'
grep -Fq 'dev-provider-ssh               NOT RUN (explicit canonical fresh provider-SSH OAuth directory unavailable)' \
  "$TEST_ROOT/provider-missing.out" || fail 'missing provider OAuth directory was not reported'
pass

: >"$CALLS"
: >"$SIGNAL_MARKER"
export ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR=''
export DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE="$FAKE_ROOT/fixtures/browser-input.json"
export DEV_SMOKE_BROWSER_AUTH_BUN_BIN="$FAKE_ROOT/fixtures/synthetic-bun"
export DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN="$FAKE_ROOT/fixtures/synthetic-chromium"
expect_status 0 "$TEST_ROOT/provider-browser.out" "$RUNNER" --only dev-provider-ssh
[[ "$(cat "$CALLS")" == dev-provider-ssh ]] || fail 'browser provider selection invoked another journey'
pass
: >"$CALLS"
export ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR="$saved_provider_dir"
expect_status 1 "$TEST_ROOT/provider-browser-saved.out" "$RUNNER" --only dev-provider-ssh
[[ ! -s "$CALLS" ]] || fail 'browser provider path reused a saved login'
unset DEV_SMOKE_BROWSER_AUTH_CREDENTIAL_FILE DEV_SMOKE_BROWSER_AUTH_BUN_BIN DEV_SMOKE_BROWSER_AUTH_CHROMIUM_BIN
pass

: >"$CALLS"
: >"$SIGNAL_MARKER"
printf 'owner-approval\n' | {
  touch "$FAKE_ROOT/fixtures/stdin-local-platform"
  expect_status 0 "$TEST_ROOT/stdin.out" "$RUNNER" --only local-platform
  rm "$FAKE_ROOT/fixtures/stdin-local-platform"
}
grep -Fxq stdin-read "$SIGNAL_MARKER" || fail 'background child did not retain caller stdin'
pass

for signal_case in HUP:129 INT:130 TERM:143; do
  signal="${signal_case%%:*}"
  expected_exit="${signal_case##*:}"
  : >"$CALLS"
  : >"$SIGNAL_MARKER"
  rm -f "$FAKE_ROOT/fixtures/child-pid" "$FAKE_ROOT/fixtures/foreground-pid"
  touch "$FAKE_ROOT/fixtures/signal-local-platform"
  env --default-signal="$signal" "$RUNNER" --only local-platform \
    >"$TEST_ROOT/signal-$signal.out" 2>&1 </dev/null &
  runner_pid=$!
  for _ in $(seq 1 100); do
    [[ -s "$FAKE_ROOT/fixtures/child-pid" && -s "$FAKE_ROOT/fixtures/foreground-pid" ]] && break
    sleep 0.02
  done
  [[ -s "$FAKE_ROOT/fixtures/child-pid" && -s "$FAKE_ROOT/fixtures/foreground-pid" ]] ||
    fail "$signal signal fixture processes did not start"
  child_pid="$(cat "$FAKE_ROOT/fixtures/child-pid")"
  foreground_pid="$(cat "$FAKE_ROOT/fixtures/foreground-pid")"
  kill -s "$signal" "$runner_pid"
  signal_status=0
  wait "$runner_pid" || signal_status=$?
  rm "$FAKE_ROOT/fixtures/signal-local-platform"
  [[ "$signal_status" == "$expected_exit" ]] ||
    fail "$signal runner exit $signal_status, expected $expected_exit"
  grep -Fxq "foreground-cleanup-$signal" "$SIGNAL_MARKER" ||
    fail "$signal did not reach the child's foreground subprocess"
  grep -Fxq "child-cleanup-$signal" "$SIGNAL_MARKER" ||
    fail "runner did not wait for exact child $signal cleanup"
  ! kill -0 "$child_pid" 2>/dev/null || fail "$signal left child $child_pid running"
  ! kill -0 "$foreground_pid" 2>/dev/null || fail "$signal left foreground process $foreground_pid running"
  grep -Fq "local-platform                 INTERRUPTED (signal $signal; child final exit $expected_exit after wait)" \
    "$TEST_ROOT/signal-$signal.out" || fail "$signal interrupted child result was not reported"
  pass
done

: >"$CALLS"
: >"$SIGNAL_MARKER"
rm -f "$FAKE_ROOT/fixtures/early-launcher-pid"
PATH="$FAKE_ROOT/fake-bin:$PATH" env --default-signal=HUP --default-signal=INT \
  --default-signal=TERM "$RUNNER" --only local-platform \
  >"$TEST_ROOT/signal-early.out" 2>&1 </dev/null &
runner_pid=$!
for _ in $(seq 1 100); do
  [[ -s "$FAKE_ROOT/fixtures/early-launcher-pid" ]] && break
  sleep 0.02
done
[[ -s "$FAKE_ROOT/fixtures/early-launcher-pid" ]] || fail 'early-start launcher did not start'
early_launcher_pid="$(cat "$FAKE_ROOT/fixtures/early-launcher-pid")"
kill -TERM "$runner_pid"
for _ in $(seq 1 100); do
  grep -Fxq early-launcher-cleanup-start "$SIGNAL_MARKER" 2>/dev/null && break
  sleep 0.01
done
grep -Fxq early-launcher-cleanup-start "$SIGNAL_MARKER" ||
  fail 'group-miss fallback did not signal the exact pre-setsid launcher PID'
kill -HUP "$runner_pid"
kill -INT "$runner_pid"
signal_status=0
wait "$runner_pid" || signal_status=$?
[[ "$signal_status" == 143 ]] || fail "repeated-signal runner exit $signal_status, expected 143"
grep -Fxq early-launcher-cleanup-done "$SIGNAL_MARKER" ||
  fail 'runner did not finish the exact early-start cleanup wait'
! kill -0 "$early_launcher_pid" 2>/dev/null ||
  fail "early-start launcher $early_launcher_pid remained after cleanup wait"
[[ ! -s "$CALLS" ]] || fail 'early-start signal fixture reached a checked-in child'
grep -Fq 'local-platform                 INTERRUPTED (signal TERM; child final exit 143 after wait)' \
  "$TEST_ROOT/signal-early.out" || fail 'repeated signals replaced the first interruption result'
pass

: >"$CALLS"
expect_status 2 "$TEST_ROOT/invalid.out" "$RUNNER" --only unknown
[[ ! -s "$CALLS" ]] || fail 'invalid selection invoked a child'
pass

expect_status 0 "$TEST_ROOT/help.out" "$RUNNER" --help
for input_name in ACCEPTANCE_NORMAL_CW_BIN ACCEPTANCE_SYNTHETIC_CW_BIN \
    ACCEPTANCE_NATIVE_MESH_BIN ACCEPTANCE_NATIVE_DERP_BIN \
    ACCEPTANCE_NATIVE_DATA_PLANE_SMOKE_BIN ACCEPTANCE_NATIVE_CREDENTIAL_BRIDGE_SMOKE_BIN \
    ACCEPTANCE_NATIVE_STATE_PROBE_BIN ACCEPTANCE_NATIVE_WORKSPACE_IMAGE_IMPORT_BIN \
    ACCEPTANCE_NATIVE_ARTIFACT_ROOT ACCEPTANCE_NATIVE_ARTIFACT_LOCK \
    ACCEPTANCE_NATIVE_SCRATCH_PARENT ACCEPTANCE_PROVIDER_SSH_FRESH_OAUTH_CONFIG_DIR \
    LOCAL_PLATFORM_ARTIFACT_ROOT LOCAL_PLATFORM_ARTIFACT_LOCK LOCAL_PLATFORM_IMAGE \
    LOCAL_PLATFORM_MESH_PROBE_BIN CODEWIRE_SERVER_URL EXPECTED_CODEWIRE_DEV_SERVER_URL \
    EXPECTED_CODEWIRE_ADMIN_EMAIL EXPECTED_CODEWIRE_ADMIN_USER_ID \
    EXPECTED_CODEWIRE_ORGANIZATION_ID KUBECONFIG KUBE_CONTEXT \
    CODEWIRE_SERVER_NAMESPACE SANDBOX_NAMESPACE EXPECTED_NODE \
    EXPECTED_TAILNET_PATH_TRANSPORT EXPECTED_TAILNET_PEER_RELAY_ENDPOINT \
    EXPECTED_UDP_RELAY_BIND_ADDRS EXPECTED_UDP_RELAY_ALLOCATOR_URL \
    EXPECTED_TAILNET_DIRECT_UDP_LB_IP EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE \
    EXPECTED_RUNTIME_TRANSPORT_REGION XDG_RUNTIME_DIR SMOKE_TMP_PARENT; do
  grep -Fq "$input_name" "$TEST_ROOT/help.out" || fail "help omitted $input_name"
done
pass

if rg -Fq must-not-reach-child "$TEST_ROOT"/*.out; then
  fail 'runner summary leaked an inherited credential canary'
fi
pass

printf 'PASS: secrets/credentials acceptance runner (%d cases)\n' "$CASES"
