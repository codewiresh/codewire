#!/usr/bin/env bash
set -euo pipefail

# Synthetic ownership fixtures must not inherit the caller's live CI cluster.
export KIND_CLUSTER_NAME=codewire-e2e-ci
unset CLUSTER KIND_PROFILE
# The fixture requests the default host topology even when the caller exports
# a shifted harness port set; behavior cases that assert shifted renderings or
# shifted preflights set their own assignment explicitly in a subshell.
export KIND_INGRESS_HOST_PORT=8090
export KIND_INGRESS_TLS_HOST_PORT=10443
export KIND_TEMPORAL_HOST_PORT=7233
export KIND_ORCHESTRATION_HOST_PORT=8084
export KIND_COORDINATOR_DIRECT_HOST_PORT=18092
export KIND_POSTGRES_HOST_PORT=25432

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="$ROOT/scripts/ci/verify/kind-e2e.sh"
COMMON="$ROOT/scripts/ci/verify/kind/common.sh"
CREDENTIALS="$ROOT/scripts/ci/verify/kind/credentials.sh"
INTEGRATED="$ROOT/scripts/ci/verify/kind/suites/integrated.sh"
DASHBOARD_BROWSER="$ROOT/scripts/ci/verify/kind/suites/dashboard-browser.sh"
FINAL_FENCING="$ROOT/scripts/ci/verify/kind/suites/final-fencing.sh"
ENVIRONMENT_SESSION="$ROOT/scripts/ci/verify/kind/suites/environment-session.sh"
SANDBOX_SUPPLY_CHAIN="$ROOT/scripts/ci/verify/kind/suites/sandbox-supply-chain.sh"
RUNTIME_ACCEPTANCE="$ROOT/scripts/ci/verify/kind/suites/runtime-acceptance.sh"
UP="$ROOT/scripts/ci/verify/kind/suites/up.sh"
mkdir -p "$ROOT/.tmp"
FIXTURE="$(mktemp -d "$ROOT/.tmp/kind-e2e-suites.XXXXXX")"
CALLS="$FIXTURE/calls"
readonly SEALED_CONTROLLER_IMAGE='registry.example.invalid/oci-approved/ingress-nginx/controller@sha256:5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180'
readonly SEALED_CERTGEN_IMAGE='registry.example.invalid/oci-approved/ingress-nginx/kube-webhook-certgen@sha256:334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053'
readonly SEALED_AGENT_IMAGE='registry.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:6081ae66b4134ebc6b170d965741b8dae09442ec74563b6c1ac999c366dac125'
readonly SEALED_WORKSPACE_IMAGE='registry.example.invalid/oci-approved/codewire/workspace@sha256:cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510'
readonly SEALED_DIND_IMAGE='registry.example.invalid/oci-approved/docker/dind@sha256:66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e'

cleanup_fixture() {
  rm -rf "$FIXTURE"
}
trap cleanup_fixture EXIT

fail() {
  printf '[test-kind-e2e-suites] ERROR: %s\n' "$*" >&2
  exit 1
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$FIXTURE/${label}.out" 2>&1; then
    fail "$label unexpectedly succeeded"
  fi
}

record() {
  printf '%s\n' "$1" >>"$CALLS"
}

# Workspace exec uses the production private adapter and authenticated daemon,
# not a bare container shell. Reuse the gateway fixture without giving the host
# exec binary ownership of its Pod lifecycle.
exec_source="$ROOT/crates/codewire-orchestration/src/bin/exec-smoke.rs"
grep -Fq 'std::env::var("SMOKE_POD_NAME")?' "$exec_source" ||
  fail 'workspace exec must require the caller-owned authenticated Pod'
if grep -Eq 'pods\.(create|delete)\(|busybox:|SMOKE_KEEP_POD' "$exec_source"; then
  fail 'workspace exec still creates an unauthenticated Pod or owns its lifecycle'
fi
gateway_fixture="$(sed -n '/^gateway_host_key_restart_smoke() {/,/^billing_contract_through_ingress() {/p' "$COMMON")"
for binding in \
    'name: workspace' \
    'name: codewire-daemon-init' \
    'cp /usr/local/bin/cw /codewire/bin/.cw.tmp' \
    'chmod 0755 /codewire/bin/.cw.tmp' \
    'mv /codewire/bin/.cw.tmp /codewire/bin/cw' \
    'command: ["/codewire/bin/cw", "__hosted-daemon"]' \
    'name: CODEWIRE_DAEMON_AUTH_TOKEN' \
    'value: 0.0.0.0:7777' \
    'mountPath: /codewire/bin' \
    'mountPath: /codewire/run' \
    'mountPath: /home/codewire' \
    'mountPath: /workspace'; do
  grep -Fq "$binding" <<<"$gateway_fixture" ||
    fail "authenticated workspace exec fixture missing: $binding"
done
grep -Fq 'SMOKE_POD_NAME=crd-smoke-workspace-daemon' "$COMMON" ||
  fail 'workspace exec does not target the authenticated gateway fixture'

# Terminal tickets connect through that same authenticated daemon. The public
# helper must run inside the ready claim/database binding, before its cleanup.
terminal_fixture="$(sed -n '/^environment_setup_terminal_smoke() (/,/^file_service_smoke() (/p' "$COMMON")"
grep -Fq 'local environment_id="$1"' <<<"$terminal_fixture" ||
  fail 'terminal smoke must use the caller-owned environment'
if grep -Eq 'busybox:|kubectl|psql|cleanup_terminal_fixture' <<<"$terminal_fixture"; then
  fail 'terminal smoke still owns an isolated unauthenticated fixture'
fi
grep -Fq '"$CARGO_CI_DIR/environment-setup-smoke"' <<<"$terminal_fixture" ||
  fail 'terminal smoke no longer exercises the public ticket/WebSocket helper'
file_fixture="$(sed -n '/^file_service_smoke() (/,/^platform_run_connect_smoke() {/p' "$COMMON")"
[[ "$(grep -Fc 'environment_setup_terminal_smoke "$environment_id"' "$COMMON")" -eq 1 ]] ||
  fail 'terminal smoke must run exactly once against the bound environment'
awk '
  /if \[ "\$ready" != "True" \]/ { ready = 1 }
  /setup_owner_pod_uid = NULL;/ { bound = ready }
  /environment_daemon_proxy_smoke "\$environment_id"/ { daemon = bound }
  /environment_setup_terminal_smoke "\$environment_id"/ { terminal = daemon }
  /DELETE FROM sandbox_environment_backend/ { cleaned = terminal }
  END { exit !(terminal && cleaned) }
' <<<"$file_fixture" || fail 'terminal smoke must follow authenticated binding and precede cleanup'
# A manually prepared Ready workspace is not an active setup owner. Preserve
# the production readiness guard and seed/upsert coherent completed metadata.
for binding in \
    '       true, NULL, NULL, NULL, NULL, NULL, NULL' \
    '    setup_complete = true,' \
    '    setup_owner_generation = NULL,' \
    '    setup_owner_activity_id = NULL,' \
    '    setup_owner_attempt = NULL,' \
    '    setup_owner_phase = NULL,' \
    '    setup_owner_status = NULL,' \
    '    setup_owner_pod_uid = NULL;' \
    "RAISE EXCEPTION 'prepared FileService fixture is not ready and idle';"; do
  grep -Fq "$binding" <<<"$file_fixture" ||
    fail "prepared workspace readiness binding missing: $binding"
done
workspace_fixture="$(sed -n '/^workspace_service_smokes() {/,/^environment_resize_smoke() (/p' "$COMMON")"

# Bash suppresses errexit throughout functions invoked from an if/|| condition.
# Exercise the actual composites in that context, with synthetic leaf commands,
# so neither a failed child nor a failed fixture transition can emit green.
workspace_smoke_definition() {
  awk -v name="$1" '
    /^[[:alnum:]_]+\(\) [({]$/ {
      if (copying) exit
      if ($1 == name "()") copying = 1
    }
    copying { print }
  ' "$COMMON"
}

run_workspace_failure_fixture() (
  local target="$1" failure="$2"
  local NS=codewire-e2e SANDBOX_NS=dev-sandboxes
  local KIND_INGRESS_URL=http://fixture.invalid KIND_INGRESS_TLS_URL=https://fixture.invalid
  # shellcheck disable=SC2034 # Read by the extracted smoke function below.
  local KIND_ORCHESTRATION_HTTP_URL=http://fixture-direct.invalid
  local CARGO_CI_DIR="$FIXTURE/workspace-bin" GATEWAY_SMOKE_TMPDIR="$FIXTURE/gateway"
  local RUN_DIR="$FIXTURE" GATEWAY_PUBLIC_FINGERPRINT
  local claim_deletes=0
  export WORKSPACE_FIXTURE_CALLS="$CALLS" WORKSPACE_FIXTURE_FAILURE="$failure"
  mkdir -p "$CARGO_CI_DIR/examples" "$GATEWAY_SMOKE_TMPDIR"
  cat >"$CARGO_CI_DIR/leaf" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
step="${0##*/}"
if [[ "$step" == crd-smoke ]]; then
  step="crd-${CRD_SMOKE_GATEWAY_PHASE:-${CRD_SMOKE_RESIZE_PHASE:-missing}}"
fi
printf '%s\n' "$step" >>"$WORKSPACE_FIXTURE_CALLS"
[[ "$step" != "$WORKSPACE_FIXTURE_FAILURE" ]] || exit 43
if [[ "$step" == crd-render ]]; then
  printf '{"items":[{"kind":"SandboxTemplate","metadata":{"name":"fixture-template"}},{"kind":"SandboxWarmPool","metadata":{"name":"fixture-pool"}},{"kind":"SandboxClaim","metadata":{"name":"sandbox-%s"},"spec":{"warmPoolRef":{"name":"fixture-pool"}}}]}\n' "$CRD_SMOKE_RESIZE_ENVIRONMENT_ID"
fi
SH
  chmod +x "$CARGO_CI_DIR/leaf"
  for leaf in exec-smoke exec-stream-smoke environment-setup-smoke file-service-smoke crd-smoke; do
    cp "$CARGO_CI_DIR/leaf" "$CARGO_CI_DIR/$leaf"
  done

  fixture_step() {
    record "$1"
    [[ "$1" != "$failure" ]] || return 41
  }
  log() { record "log $*"; }
  kind_workspace_runtime_image() { printf '%s\n' fixture-workspace; }
  gateway_auth_token_for_environment() { printf '%s\n' fixture-coordinate; }
  daemon_auth_token_for_environment() { printf '%s\n' fixture-daemon; }
  gateway_host_key_restart_smoke() { fixture_step gateway; }
  file_service_smoke() { fixture_step file-composite; }
  environment_resize_smoke() { fixture_step resize; }
  environment_daemon_proxy_smoke() { fixture_step proxy; }
  environment_setup_terminal_smoke() { fixture_step terminal; }
  exec_service_connect_smoke() { fixture_step exec-service; }
  platform_run_connect_smoke() { fixture_step platform-run; }
  environment_session_protocol_smoke() { fixture_step session-protocol; }
  capture_gateway_public_fingerprint() {
    fixture_step "fingerprint-$1" || return $?
    GATEWAY_PUBLIC_FINGERPRINT=SHA256:fixture
  }
  delete_kind_credential_bootstrap() { fixture_step credential-cleanup; }
  kubectl_apply() { cat >/dev/null; fixture_step claim-apply; }
  kubectl() {
    case " $* " in
      *' get deploy/agent-sandbox-controller '*) printf '1\n' ;;
      *' scale deploy/agent-sandbox-controller '*--replicas=0*) fixture_step controller-stop ;;
      *' scale deploy/agent-sandbox-controller '*) fixture_step controller-restore ;;
      *' wait pod '*) fixture_step controller-drain ;;
      *' wait pod/'*) fixture_step daemon-ready ;;
      *' wait sandboxclaim/'*) fixture_step resize-claim-ready ;;
      *' rollout restart '*) fixture_step gateway-restart ;;
      *' rollout status '*) fixture_step controller-ready ;;
      *' get secret '*metadata.uid*) printf 'fixture-secret-uid\n' ;;
      *' get pod '*status.podIP*) printf '10.0.0.1\n' ;;
      *' get pod '*metadata.uid*) printf 'fixture-pod-uid\n' ;;
      *' delete sandboxclaim '*)
        claim_deletes=$((claim_deletes + 1))
        if [[ "$claim_deletes" -eq 1 ]]; then
          fixture_step claim-reset
        else
          fixture_step claim-cleanup
        fi
        ;;
      *' patch sandboxclaim '*) fixture_step claim-ready ;;
      *' get sandboxclaim '*)
        if [[ "$failure" == claim-not-ready ]]; then printf 'False\n'; else printf 'True\n'; fi
        ;;
      *' exec -i deploy/postgres '*)
        local sql
        sql="$(cat)"
        if [[ "$sql" == INSERT* ]]; then
          fixture_step database-setup
        else
          fixture_step database-cleanup
        fi
        ;;
      *' delete pod '*) fixture_step pod-cleanup ;;
      *' delete pod/'*) fixture_step daemon-reset ;;
      *' --cascade=foreground '*) fixture_step resize-foreground ;;
      *' delete secret/'*) fixture_step host-key-cleanup ;;
      *) fail "unexpected workspace fixture command: $*" ;;
    esac
  }
  case "$target" in
    workspace_service_smokes|file_service_smoke|environment_resize_smoke)
      eval "$(workspace_smoke_definition "$target")" || return $?
      "$target"
      ;;
    gateway_host_key_restart_smoke)
      mktemp() { command mktemp -d "$FIXTURE/gateway.XXXXXX"; }
      eval "$(workspace_smoke_definition "$target")" || return $?
      "$target"
      ;;
    environment_setup_terminal_smoke)
      eval "$(workspace_smoke_definition "$target")" || return $?
      "$target" env-fixture
      ;;
    file-cleanup)
      local claim_name=fixture-claim original_replicas=1 initial_status=0
      eval "$(sed -n '/^  cleanup_file_service_binding() {/,/^  }/p' "$COMMON")" || return $?
      if [[ "$failure" == cleanup-preserve ]]; then
        initial_status=43
        failure=controller-restore
      fi
      (exit "$initial_status")
      cleanup_file_service_binding
      ;;
    curl_settled)
      eval "$(workspace_smoke_definition "$target")" || return $?
      mktemp() { fixture_step probe-temp || return $?; printf '%s\n' "$FIXTURE/probe-headers"; }
      curl() {
        printf 'HTTP/1.1 200 OK\n' >"$PROBE_HEADERS"
        printf '%s\n' fixture-body
        fixture_step probe-transport
      }
      awk() { fixture_step probe-headers || return $?; command awk "$@"; }
      "$target" http://fixture.invalid
      ;;
    auth_token_for_environment_scope)
      eval "$(workspace_smoke_definition "$target")" || return $?
      kubectl() { fixture_step token-secret || return $?; printf '%s\n' Zml4dHVyZQ==; }
      openssl() {
        case "$1" in
          base64) fixture_step token-encode || return $? ;;
          dgst) fixture_step token-sign || return $? ;;
          *) fail "unexpected fixture openssl command: $*" ;;
        esac
        cat
      }
      "$target" env-fixture coordinate
      ;;
    exec_service_connect_smoke)
      # A failed stream binary must stop before any subsequent REST probes.
      curl_settled() { fixture_step unexpected-curl; return 1; }
      eval "$(workspace_smoke_definition "$target")" || return $?
      "$target" env-fixture
      ;;
    *) fail "unexpected workspace fixture target: $target" ;;
  esac
)

workspace_failure_cases=0
expect_workspace_failure() {
  local target="$1" failure="$2" expected_status="$3" forbidden="$4" status
  : >"$CALLS"
  if run_workspace_failure_fixture "$target" "$failure" >"$FIXTURE/workspace-failure.out" 2>&1; then
    fail "$target ignored failed $failure"
  else
    status=$?
  fi
  if [[ "$status" -ne "$expected_status" ]]; then
    cat "$FIXTURE/workspace-failure.out" >&2
    fail "$target changed failed $failure status: got $status, want $expected_status"
  fi
  if grep -Eq "$forbidden" "$CALLS"; then
    fail "$target continued or emitted green after failed $failure"
  fi
  workspace_failure_cases=$((workspace_failure_cases + 1))
}

expect_workspace_failure workspace_service_smokes gateway 41 '^(exec-smoke|file-composite|resize)$'
expect_workspace_failure workspace_service_smokes exec-smoke 43 '^(file-composite|resize)$'
expect_workspace_failure workspace_service_smokes file-composite 41 '^resize$'
expect_workspace_failure workspace_service_smokes resize 41 'green$'
for failure in proxy terminal exec-service platform-run session-protocol; do
  case "$failure" in
    proxy) forbidden='^(terminal|exec-service|platform-run|session-protocol|file-service-smoke)$|green$' ;;
    terminal) forbidden='^(exec-service|platform-run|session-protocol|file-service-smoke)$|green$' ;;
    exec-service) forbidden='^(platform-run|session-protocol|file-service-smoke)$|green$' ;;
    platform-run) forbidden='^(session-protocol|file-service-smoke)$|green$' ;;
    session-protocol) forbidden='^file-service-smoke$|green$' ;;
  esac
  expect_workspace_failure file_service_smoke "$failure" 41 "$forbidden"
done
expect_workspace_failure file_service_smoke file-service-smoke 43 'green$'
for failure in controller-stop controller-drain claim-reset claim-apply claim-ready database-setup; do
  expect_workspace_failure file_service_smoke "$failure" 41 '^(proxy|terminal|exec-service|platform-run|session-protocol|file-service-smoke)$|green$'
done
expect_workspace_failure file_service_smoke claim-not-ready 1 '^(proxy|terminal|exec-service|platform-run|session-protocol|file-service-smoke)$|green$'
for failure in database-cleanup claim-cleanup controller-restore controller-ready pod-cleanup; do
  expect_workspace_failure file_service_smoke "$failure" 41 'green$'
done
expect_workspace_failure file_service_smoke crd-cleanup 43 'green$'
expect_workspace_failure environment_setup_terminal_smoke environment-setup-smoke 43 'green$'
expect_workspace_failure exec_service_connect_smoke exec-stream-smoke 43 '^unexpected-curl$|green$'
expect_workspace_failure gateway_host_key_restart_smoke crd-setup 43 '^(daemon-reset|claim-apply)$|green$'
expect_workspace_failure gateway_host_key_restart_smoke fingerprint-before-restart 41 '^gateway-restart$|green$'
expect_workspace_failure gateway_host_key_restart_smoke gateway-restart 41 '^fingerprint-after-restart$|green$'
expect_workspace_failure environment_resize_smoke crd-render 43 '^claim-apply$|green$'
expect_workspace_failure environment_resize_smoke claim-apply 41 '^resize-claim-ready$|green$'
for failure in claim-reset controller-restore controller-ready; do
  expect_workspace_failure file-cleanup "$failure" 41 'green$'
done
expect_workspace_failure file-cleanup cleanup-preserve 43 'green$'
for failure in probe-temp probe-transport probe-headers; do
  expect_workspace_failure curl_settled "$failure" 41 'green$'
done
for failure in token-secret token-encode token-sign; do
  expect_workspace_failure auth_token_for_environment_scope "$failure" 41 'green$'
done
for target in workspace_service_smokes file_service_smoke gateway_host_key_restart_smoke file-cleanup curl_settled auth_token_for_environment_scope; do
  : >"$CALLS"
  if ! run_workspace_failure_fixture "$target" none >"$FIXTURE/workspace-passing.out" 2>&1; then
    fail "$target rejected passing leaves and fixture transitions"
  fi
  case "$target" in
    workspace_service_smokes) grep -Fxq resize "$CALLS" || fail 'workspace success omitted resize' ;;
    file_service_smoke) grep -Fq 'FileService streaming and black-box Connect contract green' "$CALLS" ||
      fail 'file-service success omitted its green result' ;;
    gateway_host_key_restart_smoke) grep -Fxq fingerprint-after-restart "$CALLS" || fail 'gateway success omitted the restart fingerprint' ;;
  esac
  workspace_failure_cases=$((workspace_failure_cases + 1))
done
printf '[test-kind-e2e-suites] workspace failure propagation: %s cases passed\n' "$workspace_failure_cases"

python3 - "$ROOT" <<'PY'
import hashlib
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
seed = root / "tests/fixtures/orchestration/seed.sql"
assert hashlib.sha256(seed.read_bytes()).hexdigest() == "6d45bddfa5ad285ea68acd9bd90c7f608bd558bd03b057cc11e3b326025dad64"
adapter = root / "tests/fixtures/orchestration/runtime-ready.sql"
sql = adapter.read_text()
for field in ["generation", "activity_id", "attempt", "phase", "status", "pod_uid"]:
    assert f"setup_owner_{field} = NULL" in sql
assert "setup_complete = TRUE" in sql
assert "<> 2 THEN" in sql
assert "WHERE environment_id IN ('env_exec_contract_backend', 'env_exec_contract_unavailable')" in sql
for relative, startup in [
    ("scripts/ci/verify/run-integration-verification.sh", "start_orchestration_process configured"),
    ("scripts/ci/verify/rust-stack-rehearsal.sh", 'start_proc orchestration "$ORCHESTRATION_PORT" env'),
]:
    source = (root / relative).read_text()
    marker = '-f "$ROOT/tests/fixtures/orchestration/seed.sql"'
    assert source.count(marker) == 1
    tail = source.split(marker, 1)[1]
    adapter_marker = '-f "$ROOT/tests/fixtures/orchestration/runtime-ready.sql"'
    assert source.count(adapter_marker) == 1
    assert 0 <= tail.find(adapter_marker) < tail.find(startup)
    assert re.search(r'psql "\$DATABASE_URL" -v ON_ERROR_STOP=1 \\\n\s+-f "\$ROOT/tests/fixtures/orchestration/runtime-ready.sql"', source)
PY
if grep -Fq 'environment_setup_terminal_smoke' <<<"$workspace_fixture"; then
  fail 'workspace suite runs terminal smoke outside the authenticated binding'
fi

# A runnable resize fixture cannot use the deliberately non-runnable shared
# contract preset. Keep its image/base mapping and the original runtime proof.
resize_fixture="$(sed -n '/^environment_resize_smoke() (/,/^temporal_workflow_smoke() {/p' "$COMMON")"
grep -Fq "environment_id=\"\$(python3 -c 'import uuid; print(uuid.uuid4())')\"" <<<"$resize_fixture" ||
  fail 'resize fixture does not use the canonical environment identity shape'
grep -Fq "'kind-resize-smoke', 'running', 'started', '\$preset_id'" <<<"$resize_fixture" ||
  fail 'resize fixture does not use its own runnable preset'
grep -Fq "VALUES ('\$preset_id', 'codewire-gateway:e2e', 'resize-template');" <<<"$resize_fixture" ||
  fail 'resize fixture image/template base does not match its runtime'
grep -Fq 'INSERT INTO environment_presets (id, org_id, name, official, project_spec)' <<<"$resize_fixture" ||
  fail 'resize fixture does not own its preset'
# Resize refuses a running Sandbox whose setup still owns the runtime (#2328).
grep -Fq "'\$pod_name', '\$pod_ip', true" <<<"$resize_fixture" ||
  fail 'resize fixture does not model completed setup'
# Names and immutable daemon bootstrap come from the same Rust renderer used
# by runtime reconciliation. This also covers shadow names exceeding 63 bytes.
for binding in \
    'CRD_SMOKE_RESIZE_PHASE=render CRD_SMOKE_RESIZE_ENVIRONMENT_ID="$environment_id"' \
    'SANDBOX_CREDENTIAL_BROKER_NAMESPACE="$NS"' \
    'SANDBOX_CREDENTIAL_GATEWAY_ROOTS_CONFIGMAP=codewire-credential-gateway-roots' \
    'SANDBOX_CREDENTIAL_BROKER_ROOTS_CONFIGMAP=codewire-credential-broker-roots' \
    'CRD_SMOKE_GATEWAY_TOKEN="$gateway_token" CRD_SMOKE_DAEMON_AUTH_TOKEN="$daemon_token"' \
    '"$CARGO_CI_DIR/crd-smoke" >"$resize_manifest"' \
    'select(.kind == "SandboxTemplate") | .metadata.name' \
    'select(.kind == "SandboxWarmPool") | .metadata.name' \
    '.metadata.name == $claim and .spec.warmPoolRef.name == $pool' \
    'kubectl_apply -f "$resize_manifest"' \
    'CRD_SMOKE_RESIZE_PHASE=release CRD_SMOKE_RESIZE_ENVIRONMENT_ID="$environment_id"'; do
  grep -Fq "$binding" <<<"$resize_fixture" || fail "resize renderer binding missing: $binding"
done
if grep -Eq '^kind: (SandboxTemplate|SandboxWarmPool|SandboxClaim)$|local shadow_pool_name="shadow-pool-' <<<"$resize_fixture"; then
  fail 'resize fixture still duplicates production bootstrap or shadow naming'
fi
[[ "$(grep -c '^BEGIN;' <<<"$resize_fixture")" -eq 2 && "$(grep -c '^COMMIT;' <<<"$resize_fixture")" -eq 2 ]] ||
  fail 'resize fixture creation and cleanup must each be atomic'
for assertion in \
    'live resize replaced the owned workspace Pod UID' \
    'live resize changed workspace restart count' \
    'Sandbox or SandboxClaim did not retain the desired resize' \
    'explicit restart failed to preserve PVC identity or workspace data'; do
  grep -Fq "$assertion" <<<"$resize_fixture" || fail "resize assertion missing: $assertion"
done

# Exercise the actual cleanup definition with no Kubernetes or database.
# A failed foreground drain must never race a still-live issuer/key writer.
resize_cleanup_definition="$(sed -n '/^  cleanup_environment_resize_smoke() {/,/^  }/p' "$COMMON")"
credential_cleanup_definition="$(sed -n '/^delete_kind_credential_bootstrap() {/,/^}/p' "$CREDENTIALS")"
[[ -n "$credential_cleanup_definition" ]] || fail 'credential cleanup helper is missing'
run_resize_cleanup_fixture() (
  local failure="$1" initial_status="$2"
  local environment_id=00000000-0000-4000-8000-000000000123 preset_id=preset-env-resize-fixture
  local claim_name="sandbox-$environment_id" template_name="resize-template-$environment_id"
  local shadow_pool_name="shadow-pool-resize-template-$environment_id"
  local daemon_service="cw-daemon-$environment_id" NS=codewire-e2e SANDBOX_NS=dev-sandboxes
  local CARGO_CI_DIR="$FIXTURE" resize_manifest="$FIXTURE/resize-manifest.json"
  export RESIZE_FIXTURE_CALLS="$CALLS" RESIZE_FIXTURE_FAILURE="$failure"
  cat >"$CARGO_CI_DIR/crd-smoke" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$CRD_SMOKE_RESIZE_PHASE" == release && "$CRD_SMOKE_NAMESPACE" == dev-sandboxes &&
   "$CRD_SMOKE_RESIZE_ENVIRONMENT_ID" == 00000000-0000-4000-8000-000000000123 ]] || exit 2
printf 'release %s\n' "$CRD_SMOKE_RESIZE_ENVIRONMENT_ID" >>"$RESIZE_FIXTURE_CALLS"
[[ "$RESIZE_FIXTURE_FAILURE" != release ]]
SH
  chmod +x "$CARGO_CI_DIR/crd-smoke"
  kubectl() {
    record "$*"
    if [[ " $* " == *' exec '* ]]; then
      cat >"$FIXTURE/resize-cleanup.sql"
      [[ "$failure" != database ]]
    elif [[ " $* " == *' --cascade=foreground '* ]]; then
      [[ " $* " != *' certificate/'* && " $* " != *' secret/'* ]] ||
        fail 'foreground workload drain includes a credential issuer or key'
      [[ "$failure" != foreground ]]
    elif [[ " $* " == *" certificate/cw-credential-gateway-$environment_id "* ]]; then
      [[ " $* " == *' --cascade=background --wait=true --timeout=120s '* ]] ||
        fail 'issuing Certificate must disappear before its outputs'
      [[ "$failure" != certificate ]]
    elif [[ " $* " == *" secret/cw-credential-gateway-$environment_id "* ]]; then
      [[ " $* " == *" configmap/cw-credential-codex-$environment_id "* ]] ||
        fail 'credential cleanup omitted its exact configuration'
      [[ "$failure" != leaf ]]
    elif [[ " $* " == *" secret/cw-gateway-host-key-$environment_id "* ]]; then
      [[ "$failure" != hostkey ]]
    else
      fail "unexpected resize cleanup command: $*"
    fi
  }
  eval "$credential_cleanup_definition"
  eval "$resize_cleanup_definition"
  set +e
  (exit "$initial_status")
  cleanup_environment_resize_smoke
)
: >"$CALLS"
run_resize_cleanup_fixture none 0
[[ "$(wc -l <"$CALLS")" -eq 6 ]] || fail 'resize cleanup lost a required phase'
mapfile -t resize_cleanup_calls <"$CALLS"
[[ "${resize_cleanup_calls[0]}" == *' exec '* &&
   "${resize_cleanup_calls[1]}" == 'release '* &&
   "${resize_cleanup_calls[2]}" == *' --cascade=foreground '* &&
   "${resize_cleanup_calls[3]}" == *' delete certificate/'* &&
   "${resize_cleanup_calls[4]}" == *' delete secret/cw-credential-gateway-'* &&
   "${resize_cleanup_calls[5]}" == *' delete secret/cw-gateway-host-key-'* ]] ||
  fail 'resize cleanup does not preserve database, claim release, workload, issuer, leaf and host-key order'
grep -Fq -- '--cascade=foreground --wait=true --timeout=120s' "$CALLS" ||
  fail 'resize cleanup does not wait for exact dependants to stop'
grep -Fq "DELETE FROM environment_presets WHERE id = 'preset-env-resize-fixture' AND org_id = 'org_contract_1';" \
  "$FIXTURE/resize-cleanup.sql" || fail 'resize cleanup omitted its exact preset'
for failure in database release foreground certificate leaf hostkey; do
  : >"$CALLS"
  expect_failure "resize-cleanup-$failure" run_resize_cleanup_fixture "$failure" 0
  case "$failure" in
    database|hostkey) expected_calls=6 ;;
    release) expected_calls=2 ;;
    foreground) expected_calls=3 ;;
    certificate) expected_calls=4 ;;
    leaf) expected_calls=5 ;;
  esac
  [[ "$(wc -l <"$CALLS")" -eq "$expected_calls" ]] ||
    fail "resize cleanup continued past failed $failure phase or omitted bounded cleanup"
done
if run_resize_cleanup_fixture none 7 >"$FIXTURE/resize-cleanup-original-failure.out" 2>&1; then
  fail 'resize cleanup erased the original failure'
else
  [[ "$?" -eq 7 ]] || fail 'resize cleanup changed the original failure status'
fi

bash -n "$SCRIPT" "$COMMON" "$INTEGRATED" "$DASHBOARD_BROWSER" "$FINAL_FENCING" \
  "$ENVIRONMENT_SESSION" "$SANDBOX_SUPPLY_CHAIN" "$RUNTIME_ACCEPTANCE" "$0"
grep -Fq 'CRD_SMOKE_GATEWAY_TOKEN="$gateway_token"' "$COMMON" ||
  fail 'local gateway does not receive its coordinate-scoped capability'
grep -Fq 'CRD_SMOKE_DAEMON_AUTH_TOKEN="$daemon_token"' "$COMMON" ||
  fail 'local gateway and workspace daemon do not receive the daemon-scoped capability'
grep -Fq 'CRD_SMOKE_GATEWAY_TOKEN is required with CRD_SMOKE_LOCAL_GATEWAY=1' \
  "$ROOT/crates/codewire-orchestration/src/bin/crd-smoke.rs" ||
  fail 'local CRD smoke permits an unrelated literal gateway credential'
grep -Fq 'CRD_SMOKE_DAEMON_AUTH_TOKEN is required with CRD_SMOKE_LOCAL_GATEWAY=1' \
  "$ROOT/crates/codewire-orchestration/src/bin/crd-smoke.rs" ||
  fail 'local CRD smoke permits an unrelated literal daemon credential'
grep -Fq 'std::env::var("CRD_SMOKE_WORKSPACE_IMAGE")' \
  "$ROOT/crates/codewire-orchestration/src/bin/crd-smoke.rs" ||
  fail 'CRD smoke cannot consume the sealed workspace alias'
grep -Fq 'std::env::var("SMOKE_WORKSPACE_IMAGE")' \
  "$ROOT/crates/codewire-orchestration/src/bin/temporal-fencing-smoke.rs" ||
  fail 'Temporal fencing smoke cannot consume the sealed workspace alias'
awk '
  /list TTL smoke workspace Pods/ { ready = NR }
  /\.args\(\["suite", "sandbox-supply-chain"\]\)/ { observe = NR }
  /provenance\.success\(\)/ { checked = NR }
  /UPDATE environments/ { expire = NR }
  END { exit !(ready > 0 && ready < observe && observe < checked && checked < expire) }
' "$ROOT/crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs" ||
  fail 'TTL smoke must pass the live provenance gate after Ready and before expiry'
[[ "$(grep -Fc 'SMOKE_WORKSPACE_IMAGE="$workspace_image"' "$COMMON")" -eq 4 ]] ||
  fail 'Kind smoke callers do not consistently select the sealed workspace alias'
grep -Fq 'PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE="$workspace_image"' "$COMMON" ||
  fail 'dashboard lifecycle does not select the sealed workspace alias'
grep -Fq 'process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE || workspaceImage' \
  "$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts" ||
  fail 'dashboard lifecycle preset cannot consume the sealed workspace alias'
grep -Fq '(${presetId}, ${workspaceRuntimeImage},' \
  "$ROOT/apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts" ||
  fail 'dashboard lifecycle preset ignores its selected runtime workspace image'
grep -Fq 'KIND_INGRESS_HOST_PORT="${KIND_INGRESS_HOST_PORT:-${KIND_INGRESS_HTTP_HOST_PORT:-8090}}"' "$COMMON" ||
  fail 'Kind ingress host port is not configurable with the accepted default'
grep -Fq 'KIND_INGRESS_TLS_HOST_PORT="${KIND_INGRESS_TLS_HOST_PORT:-10443}"' "$COMMON" ||
  fail 'Kind ingress TLS host port is not configurable with the accepted default'
grep -Fq 'KIND_TEMPORAL_HOST_PORT="${KIND_TEMPORAL_HOST_PORT:-7233}"' "$COMMON" ||
  fail 'Kind Temporal host port is not configurable with the accepted default'
grep -Fq 'KIND_ORCHESTRATION_HOST_PORT="${KIND_ORCHESTRATION_HOST_PORT:-8084}"' "$COMMON" ||
  fail 'Kind orchestration host port is not configurable with the accepted default'
grep -Fq 'KIND_COORDINATOR_DIRECT_HOST_PORT="${KIND_COORDINATOR_DIRECT_HOST_PORT:-${KIND_COORDINATOR_HOST_PORT:-18092}}"' "$COMMON" ||
  fail 'Kind coordinator direct host port is not configurable with the accepted default'
grep -Fq 'KIND_POSTGRES_HOST_PORT="${KIND_POSTGRES_HOST_PORT:-25432}"' "$COMMON" ||
  fail 'Kind Postgres host port is not configurable with the accepted default'
grep -Fq "KIND_POSTGRES_IMAGE='docker.io/library/postgres:17-alpine@sha256:7456ef82e5f5bc43d997f4781bbd7c0d6389bff397564649a356e206ba473aee'" "$COMMON" ||
  fail 'Kind Postgres support input is not bound to the reviewed linux/amd64 manifest'
grep -Fq "KIND_TEMPORAL_IMAGE='docker.io/temporalio/auto-setup:1.29.0@sha256:6605395ec22aa6a1993bb0bfd35002b011603e21d11c4a71ee646038c59e8909'" "$COMMON" ||
  fail 'Kind Temporal support input is not bound to the reviewed linux/amd64 manifest'
grep -Fq 'KIND_INGRESS_URL="${KIND_INGRESS_URL:-http://127.0.0.1:${KIND_INGRESS_HOST_PORT}}"' "$COMMON" ||
  fail 'Kind ingress URL does not follow the requested ingress host port'
grep -Fq 'KIND_TEMPORAL_ADDRESS="${KIND_TEMPORAL_FRONTEND_URL:-${KIND_TEMPORAL_ADDRESS:-http://127.0.0.1:${KIND_TEMPORAL_HOST_PORT}}}"' "$COMMON" ||
  fail 'Kind Temporal client address does not follow the requested host port'
grep -Fq 'KIND_ORCHESTRATION_URL="${KIND_ORCHESTRATION_HTTP_URL:-${KIND_ORCHESTRATION_URL:-http://127.0.0.1:${KIND_ORCHESTRATION_HOST_PORT}}}"' "$COMMON" ||
  fail 'Kind orchestration client address does not follow the requested host port'
grep -Fq 'KIND_COORDINATOR_DIRECT_URL="${KIND_COORDINATOR_DIRECT_URL:-http://127.0.0.1:${KIND_COORDINATOR_DIRECT_HOST_PORT}}"' "$COMMON" ||
  fail 'Kind coordinator direct address does not follow the requested host port'
grep -Fq 'render_kind_host_port_mappings "$kind_config" "$rendered_kind_config"' "$COMMON" ||
  fail 'Kind cluster creation does not render the requested host-port mappings'
grep -Fq 'module.render_host_ports(data.decode(), replacements)' "$COMMON" ||
  fail 'Kind host-port rendering does not use the shared single-pass mapping renderer'
grep -Fq 'require_kind_host_ports_available "$KIND_CLUSTER_NAME"' "$COMMON" ||
  fail 'Kind cluster creation does not preflight requested host-port ownership'
grep -Fq 'log_kind_bound_endpoints' "$COMMON" ||
  fail 'Kind cluster creation does not print the bound endpoint set'
grep -Fq 'require_kind_host_ports_available || return $?' "$UP" ||
  fail 'kind-e2e.sh up does not fail fast when requested host ports are held'
grep -Fq -- '--forward "${KIND_INGRESS_HOST_PORT}:80"' "$COMMON" ||
  fail 'remote DinD forwarding does not follow the requested ingress host port'
grep -Fq -- '--forward "${KIND_INGRESS_TLS_HOST_PORT}:443"' "$COMMON" ||
  fail 'remote DinD forwarding does not follow the requested ingress TLS host port'
grep -Fq -- '--forward "${KIND_TEMPORAL_HOST_PORT}:30733"' "$COMMON" ||
  fail 'remote DinD forwarding does not follow the requested Temporal host port'
grep -Fq -- '--forward "${KIND_ORCHESTRATION_HOST_PORT}:30084"' "$COMMON" ||
  fail 'remote DinD forwarding does not follow the requested orchestration host port'
grep -Fq -- '--forward "${KIND_COORDINATOR_DIRECT_HOST_PORT}:30090"' "$COMMON" ||
  fail 'remote DinD forwarding does not follow the requested coordinator host port'
grep -Fq 'TEMPORAL_ADDRESS="$KIND_TEMPORAL_FRONTEND_URL"' "$COMMON" ||
  fail 'Temporal fencing smoke does not dial the requested Temporal endpoint'
grep -Fq 'SMOKE_ORCHESTRATION_URL="$KIND_ORCHESTRATION_HTTP_URL"' "$COMMON" ||
  fail 'orchestration smoke callers do not dial the requested orchestration endpoint'
grep -Fq 'configure_remote_dind_kind_network' "$COMMON" ||
  fail 'Kind cluster creation does not adapt the remote DinD network boundary'
[[ "$(grep -Fc '"$ROOT/scripts/ci/verify/dashboard-image.sh" "codewire-dashboard:e2e"' "$COMMON")" -eq 1 ]] ||
  fail 'Kind does not verify the exact dashboard image it already built'
if grep -Fq '127.0.0.1:25432/codewire' "$COMMON"; then
  fail 'Kind smoke callers bypass the configurable Postgres URL'
fi
# The overlay renderer recognizes the checked-in template's four default
# origins; profile-gate fixtures prove all four become the saved origin.
# Client callers must still use the selected endpoint variables throughout.
common_client_source="$(cat "$COMMON")"
overlay_renderer_source="$(workspace_smoke_definition render_kind_overlay_manifest)"
[ -n "$overlay_renderer_source" ] || fail 'overlay renderer source is missing'
common_client_source="${common_client_source/"$overlay_renderer_source"/}"
for hardcoded_loopback in '127.0.0.1:7233' '127.0.0.1:8084' '127.0.0.1:18092' '127.0.0.1:8090' 'localhost:10443'; do
  if grep -Fq "$hardcoded_loopback" <<<"$common_client_source"; then
    fail "Kind harness still hardcodes client address ${hardcoded_loopback}"
  fi
done
grep -Fq 'audience: codewire.internal.gateway-binding.v1' "$COMMON" ||
  fail 'Kind gateway-binding fixture does not project the exact audience'
grep -Fq 'mountPath: /var/run/secrets/codewire/gateway-binding' "$COMMON" ||
  fail 'Kind gateway-binding fixture does not isolate its projected token mount'
grep -Fq "token=\"\$(cat /var/run/secrets/codewire/gateway-binding/token)\"" "$COMMON" ||
  fail 'Kind gateway-binding fixture does not reread the projected identity'
grep -Fq 'anonymous internal binding command was not rejected' "$COMMON" ||
  fail 'Kind gateway-binding fixture does not assert anonymous rejection'
grep -Fq 'coordinate capability crossed into gateway binding' "$COMMON" ||
  fail 'Kind gateway-binding fixture does not assert cross-scope rejection'
if grep -Fq -- '--post-data="{\"pod\"' "$COMMON"; then
  fail 'Kind gateway-binding fixture still sends caller-selected Pod coordinates'
fi

# Sourcing the dispatcher defines every suite without executing one.
# The default fixtures model public, initially uncached dependencies. Hosted
# Edge/Kind exports a sealed tuple for its later real runtime; inheriting that
# tuple here would turn the deliberate cache miss into a preload rejection.
# Sealed scenarios below supply all five exact inputs to their own child shell.
unset KIND_INGRESS_CONTROLLER_IMAGE KIND_INGRESS_CERTGEN_IMAGE \
  KIND_AGENT_SANDBOX_IMAGE KIND_WORKSPACE_IMAGE KIND_DIND_IMAGE
# shellcheck source=scripts/ci/verify/kind-e2e.sh
source "$SCRIPT"

# Protected delivery may supply exact locally materialized release candidates.
# The suite accepts them only when every product alias carries the same exact
# source identity and release/promotable labels; ordinary PR Kind still builds
# the non-promotable CI profile itself.
docker() {
  if [ "${1:-} ${2:-} ${3:-}" = 'image inspect --format' ]; then
    case "${4:-}" in
      *dev.codewire.build.profile*) printf '%s\n' release ;;
      *dev.codewire.promotable*) printf '%s\n' true ;;
      *org.opencontainers.image.revision*) printf '%s\n' 0123456789abcdef0123456789abcdef01234567 ;;
      *) fail "unexpected protected image assertion: $*" ;;
    esac
    return
  fi
  [ "${1:-} ${2:-}" = 'image inspect' ] || fail "unexpected protected image command: $*"
}
CODEWIRE_KIND_EXPECTED_SOURCE_SHA=0123456789abcdef0123456789abcdef01234567
assert_prebuilt_release_product_images
CODEWIRE_KIND_EXPECTED_SOURCE_SHA=not-a-sha
expect_failure malformed-prebuilt-source assert_prebuilt_release_product_images
grep -Fq 'prebuilt release images require one exact expected source SHA' \
  "$FIXTURE/malformed-prebuilt-source.out" ||
  fail 'prebuilt release image mode accepted a malformed source identity'
unset -f docker
unset CODEWIRE_KIND_EXPECTED_SOURCE_SHA

missing_tool=codewire-deliberately-missing-kind-tool
if (require_tool "$missing_tool") >"$FIXTURE/missing-tool.out" 2>&1; then
  fail 'missing Kind prerequisite unexpectedly succeeded'
fi
grep -Fq "missing required tool: $missing_tool" "$FIXTURE/missing-tool.out" ||
  fail 'missing Kind prerequisite did not explain its failure'

# The integrated gate validates browser host inputs before it spends the image,
# smoke-binary or cluster transaction. Exercise the shared resolver against a
# missing frozen install and an exact local fixture.
browser_fixture="$FIXTURE/browser-host"
mkdir -p \
  "$browser_fixture/apps/dashboard/node_modules/.bin" \
  "$browser_fixture/bin" \
  "$browser_fixture/scripts/ci"
if (ROOT="$browser_fixture" require_dashboard_browser_host_dependencies) \
    >"$FIXTURE/missing-browser-host.out" 2>&1; then
  fail 'missing dashboard browser host dependencies unexpectedly succeeded'
fi
grep -Fq 'dashboard Playwright dependencies are missing' \
  "$FIXTURE/missing-browser-host.out" ||
  fail 'missing dashboard browser host dependency did not explain its failure'
printf '#!/bin/sh\nexit 0\n' >"$browser_fixture/apps/dashboard/node_modules/.bin/playwright"
printf "readonly chromium_version='145.0.7632.6'\n" \
  >"$browser_fixture/scripts/ci/install-pinned-playwright-chromium.sh"
printf '#!/bin/sh\nprintf "Chromium 151.0.7922.71\\n"\n' \
  >"$browser_fixture/bin/chromium"
chmod 0755 "$browser_fixture/apps/dashboard/node_modules/.bin/playwright" \
  "$browser_fixture/bin/chromium"
if ROOT="$browser_fixture" \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$browser_fixture/bin/chromium" \
    require_dashboard_browser_host_dependencies \
    >"$FIXTURE/wrong-browser-version.out" 2>&1; then
  fail 'wrong dashboard browser version unexpectedly passed the early prerequisite'
fi
grep -Fq 'expected pinned Chromium 145.0.7632.6' \
  "$FIXTURE/wrong-browser-version.out" ||
  fail 'wrong dashboard browser version did not explain the pinned requirement'
printf '#!/bin/sh\nprintf "Chromium 145.0.7632.6\\n"\n' \
  >"$browser_fixture/bin/chromium"
ROOT="$browser_fixture" \
PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="$browser_fixture/bin/chromium" \
  require_dashboard_browser_host_dependencies

# No arguments retain the complete integrated gate; the retained suite requires
# the exact two-token command and unknown input fails closed.
: >"$CALLS"
run_integrated_kind_suite() { record integrated; }
run_kind_up() { record up; }
run_retained_integrated_suite() { record integrated-retained; }
run_retained_dashboard_browser_suite() { record dashboard-browser-retained; }
run_retained_final_fencing_suite() { record final-fencing; }
run_retained_environment_session_suite() { record environment-session; }
run_retained_sandbox_supply_chain_suite() { record sandbox-supply-chain; }
run_retained_runtime_acceptance_suite() { record runtime-acceptance; }
dispatch_kind_e2e
printf '%s\n' integrated | cmp -s - "$CALLS" || fail 'no-argument dispatch changed'

: >"$CALLS"
dispatch_kind_e2e up
printf '%s\n' up | cmp -s - "$CALLS" || fail 'up dispatch changed'

# A shard brings its cluster up and runs every mapped suite in one process, so
# the remote DinD attachment and loopback forwarders survive into each suite.
: >"$CALLS"
dispatch_kind_e2e shard environment-session runtime-acceptance
printf '%s\n' up environment-session runtime-acceptance | cmp -s - "$CALLS" ||
  fail 'shard dispatch did not chain up and its suites in order'

: >"$CALLS"
run_retained_environment_session_suite() { record environment-session; return 44; }
if dispatch_kind_e2e shard environment-session runtime-acceptance; then
  fail 'shard dispatch accepted a failed suite'
else
  [ "$?" -eq 44 ] || fail 'shard dispatch lost the suite failure status'
fi
printf '%s\n' up environment-session | cmp -s - "$CALLS" ||
  fail 'shard dispatch continued after a failed suite'
run_retained_environment_session_suite() { record environment-session; }

expect_failure empty-shard dispatch_kind_e2e shard
grep -Fq 'the Kind shard command requires at least one suite name' \
  "$FIXTURE/empty-shard.out" || fail 'empty shard did not explain its failure'
grep -Fq 'cluster ${KIND_CLUSTER_NAME} is up; no test suites ran' "$SCRIPT" ||
  fail 'standalone up no longer reports its suite-free exit'

# Restore the production up replaced by the dispatch spies.
# shellcheck source=scripts/ci/verify/kind/suites/up.sh
source "$ROOT/scripts/ci/verify/kind/suites/up.sh"

# Up refuses an implicit name before setup, and an existing cluster under the
# transaction lock before building or changing any image or cluster.
(
  require_tool() { :; }
  KIND_CLUSTER_NAME=up-implicit KIND_CLUSTER_NAME_EXPLICIT=0
  expect_failure up-implicit-name run_kind_up
  grep -Fq 'up requires an explicit KIND_CLUSTER_NAME' \
    "$FIXTURE/up-implicit-name.out" || fail 'implicit up name was not decisive'
)
(
  require_tool() { :; }
  kind() {
    [ "$*" = 'get clusters' ] || fail "unexpected up-guard kind invocation: $*"
    printf '%s\n' up-existing
  }
  prepare_kind_temp_runtime() { :; }
  acquire_kind_host_lock() { :; }
  build_images_and_smokes() { fail 'existing-cluster up built images'; }
  create_cluster() { fail 'existing-cluster up recreated its cluster'; }
  KIND_CLUSTER_NAME=up-existing KIND_CLUSTER_NAME_EXPLICIT=1
  expect_failure up-existing-cluster run_kind_up
  grep -Fq 'already exists' "$FIXTURE/up-existing-cluster.out" ||
    fail 'existing-cluster up was not decisive'
)

# Up restores the serial gate's static ingress drift check between the host
# lock and the image build, so every CI shard leg runs it.
: >"$CALLS"
(
  require_tool() { :; }
  require_kind_host_ports_available() { record port-preflight; }
  prepare_kind_temp_runtime() { record temp-runtime; }
  acquire_kind_host_lock() { record acquire-lock; }
  cleanup() { :; }
  ingress_path_drift_check() { record ingress-drift; }
  build_images_and_smokes() { record build; }
  create_cluster() { record create-cluster; }
  load_images_into_kind() { record load; }
  deploy_overlay() { record deploy; }
  deploy_agent_sandbox() { record agent-sandbox; }
  mark_retained_cluster_prepared() { record prepared-marker; }
  kind() {
    [ "$*" = 'get clusters' ] || fail "unexpected up kind invocation: $*"
    printf '%s\n' other-cluster
  }
  KIND_CLUSTER_NAME=up-fixture KIND_CLUSTER_NAME_EXPLICIT=1
  run_kind_up
)
cat >"$FIXTURE/want-up-order" <<'EOF'
temp-runtime
acquire-lock
port-preflight
ingress-drift
build
create-cluster
load
deploy
agent-sandbox
prepared-marker
EOF
cmp -s "$FIXTURE/want-up-order" "$CALLS" || {
  diff -u "$FIXTURE/want-up-order" "$CALLS" >&2 || true
  fail 'kind up order changed'
}

: >"$CALLS"
if (
  require_tool() { :; }
  require_kind_host_ports_available() { record port-preflight; }
  prepare_kind_temp_runtime() { record temp-runtime; }
  acquire_kind_host_lock() { record acquire-lock; }
  cleanup() { :; }
  # The real check exits on failure; exit here too so the fixture does not
  # depend on set -e surviving the if-condition subshell.
  ingress_path_drift_check() { record ingress-drift; exit 43; }
  build_images_and_smokes() { fail 'kind up continued after an ingress drift failure'; }
  kind() { printf '%s\n' other-cluster; }
  KIND_CLUSTER_NAME=up-fixture KIND_CLUSTER_NAME_EXPLICIT=1
  run_kind_up
); then
  fail 'kind up accepted an ingress drift failure'
else
  [ "$?" -eq 43 ] || fail 'kind up lost the ingress drift failure status'
fi
printf '%s\n' temp-runtime acquire-lock port-preflight ingress-drift | cmp -s - "$CALLS" ||
  fail 'kind up continued after an ingress drift failure'

: >"$CALLS"
dispatch_kind_e2e suite integrated
printf '%s\n' integrated-retained | cmp -s - "$CALLS" ||
  fail 'integrated dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite dashboard-browser
printf '%s\n' dashboard-browser-retained | cmp -s - "$CALLS" ||
  fail 'dashboard-browser dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite final-fencing
printf '%s\n' final-fencing | cmp -s - "$CALLS" || fail 'final-fencing dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite environment-session
printf '%s\n' environment-session | cmp -s - "$CALLS" ||
  fail 'environment-session dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite sandbox-supply-chain
printf '%s\n' sandbox-supply-chain | cmp -s - "$CALLS" ||
  fail 'sandbox-supply-chain dispatch changed'

: >"$CALLS"
dispatch_kind_e2e suite runtime-acceptance
printf '%s\n' runtime-acceptance | cmp -s - "$CALLS" ||
  fail 'runtime-acceptance dispatch changed'

expect_failure missing-suite dispatch_kind_e2e suite
grep -Fq 'requires exactly one suite name' "$FIXTURE/missing-suite.out" ||
  fail 'missing suite did not explain its failure'
expect_failure unknown-suite dispatch_kind_e2e suite unknown
grep -Fq 'unknown Kind e2e suite: unknown' "$FIXTURE/unknown-suite.out" ||
  fail 'unknown suite did not explain its failure'
expect_failure unknown-command dispatch_kind_e2e retained
grep -Fq 'unknown Kind e2e command: retained' "$FIXTURE/unknown-command.out" ||
  fail 'unknown command did not explain its failure'

# Restore the production suite functions replaced by the dispatcher spies.
# shellcheck source=scripts/ci/verify/kind/suites/integrated.sh
source "$INTEGRATED"
# shellcheck source=scripts/ci/verify/kind/suites/dashboard-browser.sh
source "$DASHBOARD_BROWSER"
# shellcheck source=scripts/ci/verify/kind/suites/final-fencing.sh
source "$FINAL_FENCING"
# shellcheck source=scripts/ci/verify/kind/suites/environment-session.sh
source "$ENVIRONMENT_SESSION"
# shellcheck source=scripts/ci/verify/kind/suites/sandbox-supply-chain.sh
source "$SANDBOX_SUPPLY_CHAIN"
# shellcheck source=scripts/ci/verify/kind/suites/runtime-acceptance.sh
source "$RUNTIME_ACCEPTANCE"

# A browser prerequisite failure preserves its status and stops before the
# temp runtime, host lock, image build or cluster lifecycle begins.
: >"$CALLS"
set +e
(
  require_tool() { :; }
  require_dashboard_browser_host_dependencies() { record browser-prerequisites; return 29; }
  prepare_kind_temp_runtime() { record temp-runtime; }
  acquire_kind_host_lock() { record acquire-lock; }
  run_integrated_kind_suite
)
browser_prerequisite_status=$?
set -e
[ "$browser_prerequisite_status" -eq 29 ] ||
  fail "browser prerequisite failure status changed: ${browser_prerequisite_status}"
printf '%s\n' browser-prerequisites | cmp -s - "$CALLS" ||
  fail 'browser prerequisite failure entered the expensive Kind transaction'

# The integrated suite builds before starting its disposable control plane and
# proves API readiness after image import. Stub every expensive action so this
# fixture proves dispatch and order without creating a cluster.
: >"$CALLS"
require_tool() { record "require:$1"; }
require_dashboard_browser_host_dependencies() { record browser-prerequisites; }
acquire_kind_host_lock() { record acquire-lock; }
reclaim_cancelled_ci_clusters() { record reclaim; }
# shellcheck disable=SC2329 # Invoked indirectly by the integrated EXIT trap.
cleanup() { :; }
ingress_path_drift_check() { record ingress-drift; }
create_cluster() { record create-cluster; }
build_images_and_smokes() { record build; }
load_images_into_kind() { record load; }
deploy_overlay() { record deploy; }
host_key_authorization_smoke() { record host-key-authz; }
edge_routing_probes() { record edge; }
connect_edge_probes() { record connect-edge; }
coordinator_runtime_smokes() {
  record internal-connect
  record mesh-product-connect-ownership
  record coordinator
}
billing_contract_through_ingress() { record billing; }
deploy_agent_sandbox_and_smoke() { record sandbox-temporal; }
dashboard_browser_e2e() { record dashboard-browser; }
assert_sandbox_supply_chain() { record sandbox-supply-chain; }
rust_reconciler_ttl_e2e() { record ttl; }
log() { record "log:$*"; }
run_integrated_kind_suite
trap - EXIT
trap cleanup_fixture EXIT
cat >"$FIXTURE/want-order" <<'EOF'
require:curl
require:base64
require:docker
require:flock
require:jq
require:kind
require:kubectl
require:openssl
require:psql
require:python3
require:ssh-keygen
require:ssh-keyscan
browser-prerequisites
acquire-lock
reclaim
ingress-drift
build
create-cluster
load
deploy
host-key-authz
edge
connect-edge
internal-connect
mesh-product-connect-ownership
coordinator
billing
sandbox-temporal
dashboard-browser
ttl
log:green
EOF
cmp -s "$FIXTURE/want-order" "$CALLS" || {
  diff -u "$FIXTURE/want-order" "$CALLS" >&2 || true
  fail 'integrated suite order changed'
}

# Restore shared production functions replaced by the integrated-order spies.
# shellcheck source=scripts/ci/verify/kind/common.sh
source "$COMMON"

# The retained integrated remainder validates its cluster, proves the consumed
# or rebuilt smoke set, quiesces the agent-sandbox controller so the synthetic
# binding fixture keeps its patched status, reruns exactly the coordinator and
# billing probe groups, and restores the controller — never an image build,
# cluster lifecycle change, or deletion.
integrated_fixture_kubectl() {
  case "$*" in
    '-n agent-sandbox-system get deploy/agent-sandbox-controller -o jsonpath={.spec.replicas}')
      record get-replicas
      printf '1'
      ;;
    '-n agent-sandbox-system scale deploy/agent-sandbox-controller --replicas=0')
      record scale-0
      ;;
    '-n agent-sandbox-system wait pod -l app=agent-sandbox-controller --for=delete --timeout=60s')
      record wait-delete
      ;;
    '-n agent-sandbox-system scale deploy/agent-sandbox-controller --replicas=1')
      record scale-restore
      ;;
    '-n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=180s')
      record rollout-restore
      ;;
    *) fail "unexpected integrated-suite kubectl invocation: $*" ;;
  esac
}
: >"$CALLS"
(
  validate_retained_cluster() { record validate; }
  build_retained_kind_smokes() { record smokes; }
  coordinator_runtime_smokes() { record coordinator; }
  billing_contract_through_ingress() { record billing; }
  require_tool() { :; }
  kubectl() { integrated_fixture_kubectl "$@"; }
  build_images_and_smokes() { fail 'retained integrated suite rebuilt images'; }
  create_cluster() { fail 'retained integrated suite recreated its cluster'; }
  deploy_overlay() { fail 'retained integrated suite redeployed its cluster'; }
  docker() { fail "retained integrated suite invoked Docker: $*"; }
  log() { :; }
  RETAINED_KUBECONFIG=""
  run_retained_integrated_suite
)
cat >"$FIXTURE/want-integrated-retained-order" <<'EOF'
validate
smokes
get-replicas
scale-0
wait-delete
coordinator
scale-restore
rollout-restore
billing
EOF
cmp -s "$FIXTURE/want-integrated-retained-order" "$CALLS" || {
  diff -u "$FIXTURE/want-integrated-retained-order" "$CALLS" >&2 || true
  fail 'retained integrated suite order changed'
}

for failed_step in validate smokes coordinator billing; do
  : >"$CALLS"
  if (
    validate_retained_cluster() {
      record validate
      [ "$failed_step" != validate ] || return 41
    }
    build_retained_kind_smokes() {
      record smokes
      [ "$failed_step" != smokes ] || return 42
    }
    coordinator_runtime_smokes() {
      record coordinator
      [ "$failed_step" != coordinator ] || return 43
    }
    billing_contract_through_ingress() {
      record billing
      [ "$failed_step" != billing ] || return 44
    }
    require_tool() { :; }
    kubectl() { integrated_fixture_kubectl "$@"; }
    stop_gateway_port_forward() { :; }
    dump_cluster_state() { record dump; }
    kind() { record "kind:$*"; }
    docker() { record "docker:$*"; }
    log() { record "log:$*"; }
    RETAINED_KUBECONFIG=""
    run_retained_integrated_suite
  ) >"$FIXTURE/integrated-retained-${failed_step}.out" 2>&1; then
    fail "retained integrated suite accepted a failed ${failed_step} step"
  else
    retained_status=$?
  fi
  case "$failed_step" in
    validate) expected_status=41 ;;
    smokes) expected_status=42 ;;
    coordinator) expected_status=43 ;;
    billing) expected_status=44 ;;
  esac
  [ "$retained_status" -eq "$expected_status" ] ||
    fail "retained integrated suite lost the ${failed_step} failure status"
  case "$failed_step" in
    validate)
      if grep -Eq '^(get-replicas|scale-0|coordinator|billing)$' "$CALLS"; then
        fail 'retained integrated suite ran a probe after a failed validate step'
      fi
      ;;
    smokes)
      if grep -Eq '^(get-replicas|scale-0|coordinator|billing)$' "$CALLS"; then
        fail 'retained integrated suite quiesced the controller after a failed smokes step'
      fi
      ;;
    coordinator)
      # The controller must come back even when the coordinator probes fail;
      # billing must not run.
      grep -Fxq scale-restore "$CALLS" ||
        fail 'retained integrated suite stranded the scaled-down controller'
      grep -Fxq rollout-restore "$CALLS" ||
        fail 'retained integrated suite did not await the restored controller'
      if grep -Fxq billing "$CALLS"; then
        fail 'retained integrated suite ran billing after a failed coordinator step'
      fi
      ;;
    billing)
      grep -Fxq scale-restore "$CALLS" ||
        fail 'retained integrated suite skipped the controller restore'
      ;;
  esac
  grep -Fxq dump "$CALLS" ||
    fail 'retained integrated suite did not diagnose its failure'
  if grep -Eq '^(kind:|docker:)|suite green' "$CALLS"; then
    fail 'retained integrated suite claimed green or changed its retained runtime after failure'
  fi
done

# In the CI artifact mode the retained smoke set is consumed by `up`; the
# retained builder verifies it instead of rebuilding on an empty cache.
mkdir -p "$FIXTURE/consumed-ci/examples" "$FIXTURE/consumed-run"
for consumed_binary in \
    crd-smoke environment-setup-smoke exec-smoke exec-stream-smoke \
    file-service-smoke prepare-stream-smoke log-stream-smoke temporal-smoke \
    temporal-fencing-smoke reconciler-ttl-smoke cw \
    examples/platform-run-smoke examples/environment-session-smoke \
    examples/coordinator-ingress-smoke; do
  printf '#!/usr/bin/env bash\nexit 0\n' >"$FIXTURE/consumed-ci/$consumed_binary"
  chmod +x "$FIXTURE/consumed-ci/$consumed_binary"
done
: >"$FIXTURE/consumed-run/credential-bootstrap-build.jsonl"
: >"$FIXTURE/consumed-run/billing-contract-build.jsonl"
(
  CARGO_CI_DIR="$FIXTURE/consumed-ci"
  RUN_DIR="$FIXTURE/consumed-run"
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-ci
  log() { :; }
  build_retained_kind_smokes
)
(
  CARGO_CI_DIR="$FIXTURE/consumed-ci"
  RUN_DIR="$FIXTURE/consumed-run"
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-ci
  log() { :; }
  rm -f "$FIXTURE/consumed-ci/temporal-fencing-smoke"
  expect_failure missing-consumed-smoke build_retained_kind_smokes
  grep -Fq 'consumed Kind smoke binary is missing' \
    "$FIXTURE/missing-consumed-smoke.out" ||
    fail 'missing consumed smoke binary was not decisive'
  printf '#!/usr/bin/env bash\nexit 0\n' >"$FIXTURE/consumed-ci/temporal-fencing-smoke"
  chmod +x "$FIXTURE/consumed-ci/temporal-fencing-smoke"
  rm -f "$FIXTURE/consumed-run/billing-contract-build.jsonl"
  expect_failure missing-consumed-receipt build_retained_kind_smokes
  grep -Fq 'consumed Kind smoke build receipt is missing' \
    "$FIXTURE/missing-consumed-receipt.out" ||
    fail 'missing consumed smoke build receipt was not decisive'
)
# The verified consumed inventory is exactly the artifact transport contract.
python3 - "$ROOT" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
common = (root / "scripts/ci/verify/kind/common.sh").read_text()
artifacts = (root / "scripts/ci/verify/kind-build-artifacts.py").read_text()
suite_block = common.split("build_retained_kind_smokes() {", 1)[1].split("\n}", 1)[0]
verified = set()
for span in re.findall(r"for consumed in(.*?); do", suite_block, re.S):
    verified |= set(re.findall(r"[a-z][a-z0-9.-]+(?:/[a-z0-9.-]+)*", span))
smoke_block = artifacts.split("SMOKE_FILES = {", 1)[1].split("}", 1)[0]
transport = set(re.findall(r'^\s{4}"[a-z0-9-]+": "((?:examples/)?[a-z0-9-]+)",$',
                           smoke_block, re.M))
test_block = artifacts.split("TEST_FILES = {", 1)[1].split("}", 1)[0]
transport |= set(re.findall(r'^\s{8}"([a-z0-9.-]+\.jsonl)"', test_block, re.M))
assert transport, "artifact transport inventory did not parse"
assert verified == transport, f"consumed verification drifted: {verified ^ transport}"
PY

# Unchanged sealed/release fixtures below exercise their original runtime
# selection. Source-build selection has its own closed receipt fixture.
CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release

# A build-ci workspace is selected only from the canonical verified receipt.
# Even a valid receipt cannot bypass a partial or substituted sealed tuple.
(
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci
  source_alias="localhost/codewire-ci/workspace:source-$(printf '%064d' 3)"
  python3() {
    [ "$*" = "$ROOT/scripts/ci/verify/workspace-image-artifact.py reuse $ROOT $ROOT/.tmp/codewire-workspace-image-verification.json" ] ||
      fail 'workspace source selection bypassed the canonical receipt helper'
    [ "${receipt_valid:-1}" = 1 ] || return 42
    printf '%s\n' "$source_alias"
  }
  [ "$(kind_workspace_runtime_image)" = "$source_alias" ] || fail 'source workspace was not selected'
  receipt_valid=0
  expect_failure absent-workspace-receipt kind_workspace_runtime_image
  receipt_valid=1
  expect_failure invalid-sealed-source-workspace env \
    KIND_INGRESS_CONTROLLER_IMAGE=unaccepted CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci \
    bash -seuc 'source "$1"; python3() { printf "%s\n" "$2"; }; kind_workspace_runtime_image' \
    _ "$COMMON" "$source_alias"
  grep -Fq 'sealed Kind inputs must match the five approved Harbor digests' \
    "$FIXTURE/invalid-sealed-source-workspace.out" || fail 'source receipt bypassed sealed input rejection'
)

# The integrated transaction lock is host-wide rather than worktree-local and
# is bounded, so concurrent local suites wait instead of deleting each other.
: >"$CALLS"
KIND_HOST_LOCK_FILE="$FIXTURE/kind-host.lock"
KIND_HOST_LOCK_TIMEOUT_SECONDS=37
flock() { record "flock:$*"; }
log() { :; }
acquire_kind_host_lock
[ -f "$KIND_HOST_LOCK_FILE" ] || fail 'Kind host lock file was not created'
grep -Eq '^flock:-w 37 [0-9]+$' "$CALLS" ||
  fail 'Kind host lock is not acquired with the configured bound'

# A suite nested in the same process — the shard path runs up and runtime
# acceptance back to back — must not flock the file its caller already holds.
: >"$CALLS"
acquire_kind_host_lock
[ ! -s "$CALLS" ] || fail 'nested Kind host lock acquisition re-acquired the lock'

# Every checked-in hostPort renders to its requested assignment, so a shifted
# cluster never binds a host port another session's default topology holds.
cat >"$FIXTURE/kind-config-render.yaml" <<'EOF'
nodes:
  - extraPortMappings:
      - containerPort: 80
        hostPort: 8090
      - containerPort: 443
        hostPort: 10443
      - containerPort: 30733
        hostPort: 7233
      - containerPort: 30084
        hostPort: 8084
      - containerPort: 30090
        hostPort: 18092
      - containerPort: 30432
        hostPort: 25432
EOF
(
  KIND_INGRESS_HOST_PORT=18090
  KIND_TEMPORAL_HOST_PORT=17233
  KIND_POSTGRES_HOST_PORT=25433
  render_kind_host_port_mappings "$FIXTURE/kind-config-render.yaml" "$FIXTURE/kind-config-rendered.yaml"
) || fail 'default Kind host-port mappings were not accepted for rendering'
for rendered in 'hostPort: 18090' 'hostPort: 10443' 'hostPort: 17233' 'hostPort: 8084' 'hostPort: 18092' 'hostPort: 25433'; do
  grep -Fq "$rendered" "$FIXTURE/kind-config-rendered.yaml" ||
    fail "requested Kind host-port mapping ${rendered} was not rendered"
done
if grep -Eq 'hostPort: (8090|7233|25432)$' "$FIXTURE/kind-config-rendered.yaml"; then
  fail 'default Kind host ports survived requested-port rendering'
fi

# Swapped defaults remain distinct: a sequential substitution would rewrite
# the first requested value again when rendering the second mapping.
(
  KIND_INGRESS_HOST_PORT=7233
  KIND_TEMPORAL_HOST_PORT=8090
  render_kind_host_port_mappings "$FIXTURE/kind-config-render.yaml" "$FIXTURE/kind-config-swapped.yaml"
) || fail 'swapped default Kind host ports were not accepted'
awk '
  /containerPort: 80$/ { ingress = 1; next }
  ingress && /hostPort:/ { if ($2 != 7233) exit 1; ingress = 0; checked++ }
  /containerPort: 30733$/ { temporal = 1; next }
  temporal && /hostPort:/ { if ($2 != 8090) exit 1; temporal = 0; checked++ }
  END { if (checked != 2) exit 1 }
' "$FIXTURE/kind-config-swapped.yaml" || fail 'swapped Kind ports were rendered more than once'

printf preserved >"$FIXTURE/kind-config-rejected.yaml"
(
  KIND_INGRESS_HOST_PORT=7233
  KIND_TEMPORAL_HOST_PORT=7233
  if render_kind_host_port_mappings "$FIXTURE/kind-config-render.yaml" "$FIXTURE/kind-config-rejected.yaml"; then
    exit 1
  fi
) || fail 'duplicate Kind ports were accepted'
[ "$(cat "$FIXTURE/kind-config-rejected.yaml")" = preserved ] ||
  fail 'rejected Kind rendering changed an existing output'

# A held requested port fails fast and names the owning cluster; shifted
# assignments pass. Ignoring a selected holder here does not authorize replacing
# an existing cluster; create_cluster independently refuses that operation.
docker() {
  [ "${1:-}" = ps ] || fail "unexpected Docker invocation during port preflight: $*"
  printf '%s\n' 'codewire-ux-2099-control-plane 0.0.0.0:8090->80/tcp, 0.0.0.0:10443->443/tcp'
}
ss() { return 1; }
if require_kind_host_ports_available >"$FIXTURE/preflight-held.out" 2>&1; then
  fail 'held default Kind host ports were not rejected before startup'
fi
grep -Fq 'KIND_INGRESS_HOST_PORT=8090' "$FIXTURE/preflight-held.out" ||
  fail 'held-port error does not name the requested assignment'
grep -Fq 'held by kind cluster codewire-ux-2099' "$FIXTURE/preflight-held.out" ||
  fail 'held-port error does not name the owning Kind cluster'
(
  KIND_INGRESS_HOST_PORT=18090
  KIND_INGRESS_TLS_HOST_PORT=10444
  require_kind_host_ports_available
) || fail 'shifted Kind host-port assignments were rejected'
docker() {
  [ "${1:-}" = ps ] || fail "unexpected Docker invocation during port preflight: $*"
  printf '%s\n' 'codewire-e2e-ci-control-plane 0.0.0.0:8090->80/tcp'
}
require_kind_host_ports_available codewire-e2e-ci ||
  fail 'port observation cannot exclude the selected cluster holder'
if require_kind_host_ports_available >/dev/null 2>&1; then
  fail 'ports held by an existing cluster were accepted for a new cluster'
fi
unset -f docker ss

# Startup never replaces an existing cluster, even when its selected name or
# prefix matches a disposable CI convention.
: >"$CALLS"
cat >"$FIXTURE/kind-config.yaml" <<'EOF'
hostPort: 8090
EOF
kind() {
  case "${1:-} ${2:-}" in
    'get clusters') printf '%s\n' codewire-e2e-ci codewire-e2e-ci-873 agent-sandbox codewire e2e-test ;;
    'delete cluster') record "kind:delete ${4:-}" ;;
    *) fail "unexpected Kind startup invocation: $*" ;;
  esac
}
docker() { record "docker:$*"; }
log() { :; }
expect_failure existing-startup reclaim_cancelled_ci_clusters "$FIXTURE/kind-config.yaml"
[ ! -s "$CALLS" ] || fail 'startup touched an existing selected or same-prefix cluster'

# Support services are pulled before cluster creation by immutable digest and
# receive disposable local aliases. A missing upstream digest fails before any
# Kubernetes object can wait on a registry pull.
: >"$CALLS"
docker() {
  case "${1:-} ${2:-}" in
    'image inspect') return 1 ;;
    'pull '*|'image tag') record "docker:$*" ;;
    *) fail "unexpected support-image Docker invocation: $*" ;;
  esac
}
log() { :; }
prepare_kind_support_images
cat >"$FIXTURE/want-support-images" <<EOF
docker:pull ${KIND_POSTGRES_IMAGE}
docker:pull ${KIND_TEMPORAL_IMAGE}
docker:image tag ${KIND_POSTGRES_IMAGE} ${KIND_POSTGRES_LOCAL_IMAGE}
docker:image tag ${KIND_TEMPORAL_IMAGE} ${KIND_TEMPORAL_LOCAL_IMAGE}
docker:pull quay.io/jetstack/cert-manager-controller@sha256:8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a
docker:image tag quay.io/jetstack/cert-manager-controller@sha256:8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a localhost/codewire-ci/cert-manager-controller:verified-8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a
docker:pull quay.io/jetstack/cert-manager-webhook@sha256:f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246
docker:image tag quay.io/jetstack/cert-manager-webhook@sha256:f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246 localhost/codewire-ci/cert-manager-webhook:verified-f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246
docker:pull quay.io/jetstack/cert-manager-cainjector@sha256:da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985
docker:image tag quay.io/jetstack/cert-manager-cainjector@sha256:da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985 localhost/codewire-ci/cert-manager-cainjector:verified-da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985
EOF
cmp -s "$FIXTURE/want-support-images" "$CALLS" || {
  diff -u "$FIXTURE/want-support-images" "$CALLS" >&2 || true
  fail 'Kind support images are not resolved and aliased by exact digest'
}

# A sealed runtime must still reject each missing credential dependency rather
# than falling back to a public pull. Exercise the real guard with synthetic
# Docker state; neither these negative cases nor the positive case below can
# contact a Docker daemon or load anything into a real cluster.
public_credential_images="$(kind_credential_support_images)" || fail 'public credential inventory failed'
sealed_credential_images="$(env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; kind_credential_support_images' _ "$COMMON")" ||
  fail 'sealed credential inventory failed'
[[ "$sealed_credential_images" == "${public_credential_images//quay.io\/jetstack/registry.example.invalid\/oci-approved\/jetstack}" ]] ||
  fail 'sealed credential inventory did not select exactly the approved Harbor references'
missing_credential_index=0
while IFS='|' read -r missing_credential_source missing_credential_alias; do
  missing_credential_index=$((missing_credential_index + 1))
  : >"$CALLS"
  expect_failure "missing-sealed-credential-$missing_credential_index" env \
    KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
    KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
    KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
    KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
    KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
    MISSING_CREDENTIAL_SOURCE="$missing_credential_source" \
    ROOT="$ROOT" COMMON="$COMMON" CALLS="$CALLS" bash -seu <<'BASH'
  fail() { printf '[sealed-credential-test] ERROR: %s\n' "$*" >&2; exit 1; }
  record() { printf '%s\n' "$1" >>"$CALLS"; }
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  docker() {
    record "docker:$*"
    case "${1:-} ${2:-}" in
      'image inspect') [ "${3:-}" != "$MISSING_CREDENTIAL_SOURCE" ] ;;
      'image tag') ;;
      *) fail "unexpected sealed Docker invocation: $*" ;;
    esac
  }
  kind() { record "kind:$*"; fail 'missing dependency reached Kind'; }
  log() { :; }
  prepare_kind_credential_support_images
BASH
  grep -Fq "exact credential fixture image was not preloaded: $missing_credential_source" \
    "$FIXTURE/missing-sealed-credential-$missing_credential_index.out" ||
    fail 'sealed missing-image guard did not identify its exact dependency'
  [ "$(tail -n 1 "$CALLS")" = "docker:image inspect $missing_credential_source" ] ||
    fail 'sealed missing-image guard continued after the failed inspection'
  if grep -Eq '^docker:pull |^kind:' "$CALLS"; then
    fail 'sealed missing-image guard attempted a public pull or cluster load'
  fi
  if grep -Fq " $missing_credential_alias" "$CALLS"; then
    fail 'sealed missing-image guard assigned an alias to an absent image'
  fi
done <<<"$sealed_credential_images"
[ "$missing_credential_index" -eq 3 ] || fail 'credential preload rejection inventory changed'

# Preparation and loading must propagate the real tuple validator's failure
# even if every image inspection would succeed. No cached image permits a
# partial or substituted platform tuple to select an image delivery mode.
for credential_operation in prepare_kind_credential_support_images load_kind_credential_support_images; do
  for invalid_agent in '' 'registry.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
    : >"$CALLS"
    env \
      KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
      KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
      KIND_AGENT_SANDBOX_IMAGE="$invalid_agent" \
      KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
      KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
      CREDENTIAL_OPERATION="$credential_operation" COMMON="$COMMON" CALLS="$CALLS" bash -seu <<'BASH'
    # shellcheck source=scripts/ci/verify/kind/common.sh
    source "$COMMON"
    docker() { printf 'docker:%s\n' "$*" >>"$CALLS"; }
    kind() { printf 'kind:%s\n' "$*" >>"$CALLS"; }
    log() { :; }
    wait_for_kind_api_after_image_load() { printf 'wait-api\n' >>"$CALLS"; }
    status=0
    "$CREDENTIAL_OPERATION" || status=$?
    [ "$status" -eq 2 ] || exit 98
BASH
    [ ! -s "$CALLS" ] || fail 'invalid tuple performed a credential image operation'
  done
done

# Every large image import is separated by an API recovery gate. This keeps a
# temporarily starved control plane from accumulating four back-to-back imports.
: >"$CALLS"
docker() {
  case "${1:-} ${2:-}" in
    'image inspect'|'image tag') ;;
    *) fail "unexpected Docker invocation: $*" ;;
  esac
}
kind() { record "kind:$*"; }
wait_for_kind_api_after_image_load() { record wait-api; }
log() { :; }
load_images_into_kind
cat >"$FIXTURE/want-image-load-order" <<EOF
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-dashboard:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-services:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-mesh:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-gateway:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_POSTGRES_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_TEMPORAL_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} localhost/codewire-ci/cert-manager-controller:verified-8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} localhost/codewire-ci/cert-manager-webhook:verified-f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} localhost/codewire-ci/cert-manager-cainjector:verified-da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985
wait-api
EOF
if [ -n "${KIND_INGRESS_CONTROLLER_IMAGE:-}" ] \
    && [ -n "${KIND_INGRESS_CERTGEN_IMAGE:-}" ] \
    && [ -n "${KIND_AGENT_SANDBOX_IMAGE:-}" ] \
    && [ -n "${KIND_WORKSPACE_IMAGE:-}" ] \
    && [ -n "${KIND_DIND_IMAGE:-}" ]; then
  cat >>"$FIXTURE/want-image-load-order" <<EOF
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CONTROLLER_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CERTGEN_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_AGENT_SANDBOX_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_WORKSPACE_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_DIND_LOCAL_IMAGE}
wait-api
EOF
fi
cmp -s "$FIXTURE/want-image-load-order" "$CALLS" || {
  diff -u "$FIXTURE/want-image-load-order" "$CALLS" >&2 || true
  fail 'Kind image imports are not separated by API recovery gates'
}

# The source-built image is imported once, with the same API recovery gate.
(
  : >"$CALLS"
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci
  source_alias="localhost/codewire-ci/workspace:source-$(printf '%064d' 3)"
  python3() {
    [ "$*" = "$ROOT/scripts/ci/verify/workspace-image-artifact.py reuse $ROOT $ROOT/.tmp/codewire-workspace-image-verification.json" ] ||
      fail 'image loading used a noncanonical source receipt'
    printf '%s\n' "$source_alias"
  }
  load_images_into_kind
  [ "$(grep -Fc "kind:load docker-image --name $KIND_CLUSTER_NAME $source_alias" "$CALLS")" -eq 1 ] ||
    fail 'Kind did not import its exact source-built workspace once'
  awk -v image="$source_alias" '
    index($0, image) { getline; if ($0 != "wait-api") exit 1; found = 1 }
    END { if (!found) exit 1 }
  ' "$CALLS" || fail 'source image import omitted API recovery'
)

# Forgejo CI names only the five approved Harbor platform manifests. They must
# already exist in the private DinD store. The two digest-pinned public
# service dependencies are also side-loaded before the rendered deployment.
: >"$CALLS"
env \
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  ROOT="$ROOT" COMMON="$COMMON" CALLS="$CALLS" FIXTURE="$FIXTURE" bash -seu <<'BASH'
  fail() { printf "[sealed-kind-test] ERROR: %s\n" "$*" >&2; exit 1; }
  record() { printf "%s\n" "$1" >>"$CALLS"; }
  assert_no_public_dind_images() {
    # Admission expressions name allowed images without launching them. Check
    # workload image fields and the runtime configuration instead of CEL text.
    if grep -Eq '^[[:space:]]*(-[[:space:]]+)?(image|SANDBOX_DIND_IMAGE):.*docker[.]io/library/docker:29[.]7[.]1-dind' "$1"; then
      fail 'sealed Kind overlay retained the public DinD image'
    fi
  }
  assert_no_nodeport_roulette() {
    # Every NodePort Service port must be pinned: an auto-allocated port can
    # claim one of the harness's explicit allocations (the derp http/stun
    # roulette that starved coordinator 30090), and apply order decides the
    # loser. This guard fails in seconds instead of one CI leg in N.
    python3 - "$1" <<'PY'
import sys
import yaml

services = 0
ports = 0
with open(sys.argv[1], encoding="utf-8") as handle:
    for document in yaml.safe_load_all(handle):
        if not isinstance(document, dict) or document.get("kind") != "Service":
            continue
        spec = document.get("spec") or {}
        if spec.get("type") != "NodePort":
            continue
        services += 1
        for port in spec.get("ports") or []:
            ports += 1
            if not isinstance(port.get("nodePort"), int):
                print(
                    f"NodePort Service {document['metadata']['name']} leaves "
                    f"port {port.get('port')} to allocation roulette",
                    file=sys.stderr,
                )
                raise SystemExit(1)
if services == 0 or ports == 0:
    print("Kind overlay carries no NodePort Services; the roulette guard is stale", file=sys.stderr)
    raise SystemExit(1)
PY
  }
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  [ "$(kind_workspace_runtime_image)" = "$KIND_WORKSPACE_LOCAL_IMAGE" ] ||
    fail 'sealed workspace input did not resolve to its local alias'
  [ "$(kind_dind_runtime_image)" = "$KIND_DIND_LOCAL_IMAGE" ] ||
    fail 'sealed DinD input did not resolve to its local alias'
  docker() {
    case "${1:-} ${2:-}" in
      'image inspect'|'image tag')
        [[ "$*" != *quay.io/jetstack/* ]] || fail 'sealed image lookup used the public repository'
        ;;
      *) fail "unexpected sealed Docker invocation: $*" ;;
    esac
    record "docker:$*"
  }
  kind() { record "kind:$*"; }
  wait_for_kind_api_after_image_load() { record wait-api; }
  log() { :; }
  prepare_kind_credential_support_images
  load_images_into_kind
  rendered="$(render_ingress_manifest)"
  agent_rendered="$(render_agent_sandbox_manifest)"
  kind_rendered="$(render_kind_overlay_manifest)"
  [ "$(grep -Fc "$KIND_INGRESS_CONTROLLER_LOCAL_IMAGE" "$rendered")" -eq 1 ] ||
    fail 'sealed ingress render does not contain the local controller once'
  [ "$(grep -Fc "$KIND_INGRESS_CERTGEN_LOCAL_IMAGE" "$rendered")" -eq 2 ] ||
    fail 'sealed ingress render does not contain the local certgen twice'
  [ "$(grep -Fc 'imagePullPolicy: Never' "$rendered")" -eq 3 ] ||
    fail 'sealed ingress render does not prohibit registry pulls'
  if grep -Fq 'registry.example.invalid/oci-approved/ingress-nginx/' "$rendered"; then
    fail 'sealed ingress render retained a private registry reference'
  fi
  if grep -Fq 'registry.k8s.io/ingress-nginx/' "$rendered"; then
    fail 'sealed ingress render retained a public registry image'
  fi
  [ "$(grep -Fc "$KIND_AGENT_SANDBOX_LOCAL_IMAGE" "$agent_rendered")" -eq 1 ] ||
    fail 'sealed agent-sandbox render does not contain the local controller once'
  [ "$(grep -Fc 'imagePullPolicy: Never' "$agent_rendered")" -eq 1 ] ||
    fail 'sealed agent-sandbox render does not prohibit registry pulls'
  if grep -Fq 'registry.example.invalid/oci-approved/codewire/' "$agent_rendered"; then
    fail 'sealed agent-sandbox render retained a private registry reference'
  fi
  if grep -Fq 'ghcr.io/noeljackson/agent-sandbox-controller' "$agent_rendered"; then
    fail 'sealed agent-sandbox render retained the public registry image'
  fi
  [ "$(grep -Fc "$KIND_DIND_LOCAL_IMAGE" "$kind_rendered")" -eq 1 ] ||
    fail 'sealed Kind overlay does not contain the local DinD alias once'
  [ "$(grep -Fc 'SANDBOX_IMAGE_CACHE: disabled' "$kind_rendered")" -eq 1 ] ||
    fail 'sealed Kind overlay does not disable the public-image cache'
  if grep -Eq 'SANDBOX_(FULL_WARM_PROFILES|WARM_POOL_WORKSPACE_IMAGE)' "$kind_rendered"; then
    fail 'sealed Kind overlay retained removed shared warm-pool configuration'
  fi
  [ "$(grep -Fc "$KIND_POSTGRES_LOCAL_IMAGE" "$kind_rendered")" -eq 2 ] ||
    fail 'sealed Kind overlay does not contain the local Postgres alias twice'
  [ "$(grep -Fc "$KIND_TEMPORAL_LOCAL_IMAGE" "$kind_rendered")" -eq 1 ] ||
    fail 'sealed Kind overlay does not contain the local Temporal alias once'
  [ "$(grep -A1 -F "image: $KIND_POSTGRES_LOCAL_IMAGE" "$kind_rendered" | grep -Fc 'imagePullPolicy: Never')" -eq 2 ] ||
    fail 'sealed Kind overlay permits a Postgres registry pull'
  [ "$(grep -A1 -F "image: $KIND_TEMPORAL_LOCAL_IMAGE" "$kind_rendered" | grep -Fc 'imagePullPolicy: Never')" -eq 1 ] ||
    fail 'sealed Kind overlay permits a Temporal registry pull'
  if grep -Eq 'image: (postgres:17-alpine|temporalio/auto-setup:1.29.0)' "$kind_rendered"; then
    fail 'sealed Kind overlay retained a mutable support-image reference'
  fi
  assert_no_public_dind_images "$kind_rendered"
  grep -Fq "c.image == '$DEFAULT_KIND_DIND_IMAGE'" "$kind_rendered" ||
    fail 'sealed Kind overlay changed the image-cache admission pin'
  # Every NodePort Service port in the harness topology must be pinned: an
  # auto-allocated port can claim one of the explicit allocations (the
  # ingress controller's unpinned NodePort pair starved coordinator 30090 on
  # one apply order), and allocation order decides the loser. Cover the
  # vendored ingress manifest, the e2e overlay render, and both local-kind
  # overlay renders so this fails in seconds instead of one CI leg in N.
  kubectl kustomize "$ROOT/deployments/k8s/overlays/local-kind" \
    >"$FIXTURE/local-kind-overlay.yaml"
  kubectl kustomize "$ROOT/deployments/k8s/overlays/local-kind-static" \
    >"$FIXTURE/local-kind-static-overlay.yaml"
  for topology in \
      "$ROOT/tests/e2e/kind/vendor/ingress-nginx-deploy.yaml" \
      "$kind_rendered" \
      "$FIXTURE/local-kind-overlay.yaml" \
      "$FIXTURE/local-kind-static-overlay.yaml"; do
    assert_no_nodeport_roulette "$topology" ||
      fail "NodePort roulette guard accepted ${topology}"
  done
  unpinned="$FIXTURE/ingress-unpinned-nodeport.yaml"
  python3 - "$ROOT/tests/e2e/kind/vendor/ingress-nginx-deploy.yaml" "$unpinned" <<'PY'
import sys
text = open(sys.argv[1], encoding="utf-8").read()
pin = "    nodePort: 30446\n"
if text.count(pin) != 1:
    raise SystemExit("ingress controller nodePort pin moved; the roulette guard fixture is stale")
open(sys.argv[2], "w", encoding="utf-8").write(text.replace(pin, "", 1))
PY
  if (assert_no_nodeport_roulette "$unpinned") >"$FIXTURE/unpinned-nodeport.out" 2>&1; then
    fail 'NodePort roulette guard accepted an unpinned Service port'
  fi
  grep -Fq 'leaves port 80 to allocation roulette' \
    "$FIXTURE/unpinned-nodeport.out" ||
    fail 'NodePort roulette guard did not identify the unpinned port'

  # Both actual pull surfaces must still fail even though the pinned admission
  # expression above is permitted. Use the real render for the config fixture.
  python3 - "$kind_rendered" "$KIND_DIND_LOCAL_IMAGE" "$DEFAULT_KIND_DIND_IMAGE" <<'PY'
from pathlib import Path
import sys

rendered, local_dind, public_dind = sys.argv[1:]
text = Path(rendered).read_text()
config = f"  SANDBOX_DIND_IMAGE: {local_dind}\n"
if text.count(config) != 1:
    raise SystemExit("sealed DinD config fixture occurrence mismatch")
Path(rendered + ".public-config").write_text(
    text.replace(config, f"  SANDBOX_DIND_IMAGE: {public_dind}\n")
)
Path(rendered + ".public-workload").write_text(
    text + "\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: unsealed-dind-fixture\n"
    + "spec:\n  containers:\n  - image: " + public_dind + "\n    name: dind\n"
)
Path(rendered + ".public-init").write_text(
    text + "\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: unsealed-dind-init-fixture\n"
    + "spec:\n  initContainers:\n  - image: " + public_dind + "\n    name: dind"
    + "\n  containers:\n  - name: fixture\n    image: codewire-services:e2e\n"
)
PY
  for surface in config workload init; do
    if (assert_no_public_dind_images "${kind_rendered}.public-${surface}") \
        >"${kind_rendered}.public-${surface}.out" 2>&1; then
      fail "sealed Kind overlay accepted a public DinD ${surface}"
    fi
    grep -Fq 'sealed Kind overlay retained the public DinD image' \
      "${kind_rendered}.public-${surface}.out" ||
      fail "public DinD ${surface} did not fail at the image guard"
  done
  if grep -Fq 'ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff' "$kind_rendered"; then
    fail 'sealed Kind overlay retained the public workspace image'
  fi
BASH

# The exact approved repository references, not merely matching digests under
# public names, must be both inspected and assigned their unchanged aliases.
while IFS='|' read -r credential_source credential_alias; do
  grep -Fq "docker:image inspect $credential_source" "$CALLS" ||
    fail 'sealed credential source was not proven in the runner-preloaded store'
  grep -Fq "docker:image tag $credential_source $credential_alias" "$CALLS" ||
    fail 'sealed credential source was not assigned its unchanged local alias'
done <<<"$sealed_credential_images"

grep -E '^kind:load docker-image|^wait-api$' "$CALLS" \
  >"$FIXTURE/sealed-image-load-order"
cat >"$FIXTURE/want-sealed-image-load-order" <<EOF
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-dashboard:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-services:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-mesh:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} codewire-gateway:e2e
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_POSTGRES_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_TEMPORAL_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} localhost/codewire-ci/cert-manager-controller:verified-8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} localhost/codewire-ci/cert-manager-webhook:verified-f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} localhost/codewire-ci/cert-manager-cainjector:verified-da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CONTROLLER_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_INGRESS_CERTGEN_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_AGENT_SANDBOX_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_WORKSPACE_LOCAL_IMAGE}
wait-api
kind:load docker-image --name ${KIND_CLUSTER_NAME} ${KIND_DIND_LOCAL_IMAGE}
wait-api
EOF
cmp -s "$FIXTURE/want-sealed-image-load-order" "$FIXTURE/sealed-image-load-order" || {
  diff -u "$FIXTURE/want-sealed-image-load-order" \
    "$FIXTURE/sealed-image-load-order" >&2 || true
  fail 'sealed Kind image imports are not separated by API recovery gates'
}

# Runtime observation accepts only the local aliases in sealed mode, requires
# the workspace in rendered templates, validates the configured optional DinD
# input, and rejects pull failures without an unrelated-service allowlist.
env \
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  ROOT="$ROOT" COMMON="$COMMON" bash -seu <<'BASH'
  fail() { printf "[sealed-supply-chain-test] ERROR: %s\n" "$*" >&2; exit 1; }
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  service_account_json='{"automountServiceAccountToken":false}'
  pods_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{initContainers:[],containers:[{image:$workspace},{image:$dind},{image:"postgres:17-alpine"}]}}]}')"
  templates_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{podTemplate:{spec:{containers:[{image:$workspace},{image:$dind}]}}}}]}')"
  events_json='{"items":[]}'
  configured_dind="$KIND_DIND_LOCAL_IMAGE"
  kubectl() {
    case "$*" in
      '-n dev-sandboxes get serviceaccount/codewire-sandbox -o json')
        printf '%s\n' "$service_account_json"
        ;;
      '-n codewire-e2e get configmap/codewire-config -o jsonpath={.data.SANDBOX_DIND_IMAGE}')
        printf '%s' "$configured_dind"
        ;;
      'get pods -A -o json') printf '%s\n' "$pods_json" ;;
      'get sandboxtemplates -A -o json') printf '%s\n' "$templates_json" ;;
      'get events -A -o json') printf '%s\n' "$events_json" ;;
      *) fail "unexpected kubectl invocation: $*" ;;
    esac
  }
  log() { :; }

  assert_sandbox_supply_chain

  accepted_templates_json="$templates_json"
  templates_json='{"items":[]}'
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'post-cleanup empty templates were accepted as positive runtime provenance'
  fi
  templates_json="$(jq \
    '.items[0].spec.podTemplate.spec.containers += [{image:"ghcr.io/codewiresh/workspace:unaccepted"}]' \
    <<<"$accepted_templates_json")"
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime accepted an unapproved template image alongside the accepted workspace'
  fi
  templates_json="$accepted_templates_json"

  pods_json="$(jq -cn \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{containers:[{image:"ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff"},{image:$dind}]}}]}')"
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime accepted a public workspace reference'
  fi

  pods_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{containers:[{image:$workspace},{image:$dind}]}}]}')"
  templates_json="$(jq -cn --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    '{items:[{spec:{image:$workspace}}]}')"
  assert_sandbox_supply_chain ||
    fail 'sealed runtime rejected a template where optional DinD is inactive'

  configured_dind='docker.io/library/docker:29.7.1-dind@sha256:e8faad5a8dc5279dff929afc5449f2791736912fff9f99351d742db2fad01b4c'
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime accepted a substituted configured DinD input'
  fi
  configured_dind="$KIND_DIND_LOCAL_IMAGE"

  templates_json="$(jq -cn \
    --arg workspace "$KIND_WORKSPACE_LOCAL_IMAGE" \
    --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{spec:{images:[$workspace,$dind]}}]}')"
  events_json="$(jq -cn --arg dind "$KIND_DIND_LOCAL_IMAGE" \
    '{items:[{reason:"ImagePullBackOff",message:("failed to pull " + $dind),metadata:{namespace:"dev-sandboxes"},involvedObject:{name:"workspace"}}]}')"
  if assert_sandbox_supply_chain >/dev/null 2>&1; then
    fail 'sealed runtime ignored a DinD pull failure'
  fi
BASH

# A partial or substituted sealed-image tuple must fail before any nested
# cluster action. The public source remains pinned by its multi-arch index,
# while the approved runner input is the independently verified amd64 child.
expect_failure partial-platform-images env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE='' \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Harbor digests' \
  "$FIXTURE/partial-platform-images.out" ||
  fail 'partial sealed platform tuple did not explain its rejection'

expect_failure partial-workspace-only env \
  KIND_INGRESS_CONTROLLER_IMAGE='' \
  KIND_INGRESS_CERTGEN_IMAGE='' \
  KIND_AGENT_SANDBOX_IMAGE='' \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Harbor digests' \
  "$FIXTURE/partial-workspace-only.out" ||
  fail 'workspace-only sealed tuple did not explain its rejection'

expect_failure substituted-agent-image env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE='registry.example.invalid/oci-approved/codewire/agent-sandbox-controller@sha256:555146af2337dd5d8baf0844d7f5de9a3cd8fc7b032b85756ae244bc2583fb41' \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Harbor digests' \
  "$FIXTURE/substituted-agent-image.out" ||
  fail 'agent-sandbox index substitution did not explain its rejection'

expect_failure substituted-workspace-image env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE='registry.example.invalid/oci-approved/codewire/workspace@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  KIND_DIND_IMAGE="$SEALED_DIND_IMAGE" \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Harbor digests' \
  "$FIXTURE/substituted-workspace-image.out" ||
  fail 'workspace digest substitution did not explain its rejection'

expect_failure substituted-dind-image env \
  KIND_INGRESS_CONTROLLER_IMAGE="$SEALED_CONTROLLER_IMAGE" \
  KIND_INGRESS_CERTGEN_IMAGE="$SEALED_CERTGEN_IMAGE" \
  KIND_AGENT_SANDBOX_IMAGE="$SEALED_AGENT_IMAGE" \
  KIND_WORKSPACE_IMAGE="$SEALED_WORKSPACE_IMAGE" \
  KIND_DIND_IMAGE='registry.example.invalid/oci-approved/docker/dind@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  bash -seuc 'source "$1"; validate_sealed_kind_images' _ "$COMMON"
grep -Fq 'sealed Kind inputs must match the five approved Harbor digests' \
  "$FIXTURE/substituted-dind-image.out" ||
  fail 'DinD digest substitution did not explain its rejection'

grep -Fq "docker:image inspect $SEALED_CONTROLLER_IMAGE" "$CALLS" ||
  fail 'sealed controller was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image inspect $SEALED_CERTGEN_IMAGE" "$CALLS" ||
  fail 'sealed certgen was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_CONTROLLER_IMAGE localhost/codewire-ci/ingress-nginx-controller:verified-5c2a1b6c03c4d18ecf14685d21a32bf6763a022f6f8cc07e9578f6cd5eca6180" "$CALLS" ||
  fail 'sealed controller was not assigned its disposable Kind reference'
grep -Fq "docker:image tag $SEALED_CERTGEN_IMAGE localhost/codewire-ci/ingress-kube-webhook-certgen:verified-334191231352856e1ec0c3e50f966edb59ec94a51906453d09f5820789e8b053" "$CALLS" ||
  fail 'sealed certgen was not assigned its disposable Kind reference'
grep -Fq "docker:image inspect $SEALED_AGENT_IMAGE" "$CALLS" ||
  fail 'sealed agent-sandbox controller was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_AGENT_IMAGE localhost/codewire-ci/agent-sandbox-controller:verified-6081ae66b4134ebc6b170d965741b8dae09442ec74563b6c1ac999c366dac125" "$CALLS" ||
  fail 'sealed agent-sandbox controller was not assigned its disposable Kind reference'
grep -Fq "docker:image inspect $SEALED_WORKSPACE_IMAGE" "$CALLS" ||
  fail 'sealed workspace was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_WORKSPACE_IMAGE localhost/codewire-ci/workspace:verified-cf91240f0706a5b3da81485fbf87d65973b18d4f1067f630bc5fd513b38d1510" "$CALLS" ||
  fail 'sealed workspace was not assigned its disposable Kind reference'
grep -Fq "docker:image inspect $SEALED_DIND_IMAGE" "$CALLS" ||
  fail 'sealed DinD was not proven in the runner-preloaded Docker store'
grep -Fq "docker:image tag $SEALED_DIND_IMAGE localhost/codewire-ci/docker-dind:verified-66fd272fc375aad4c8fa06351c414e15bffe8cb015c171e1b8a8efe36a72cc1e" "$CALLS" ||
  fail 'sealed DinD was not assigned its disposable Kind reference'

grep -Fq "KIND_INGRESS_CONTROLLER_IMAGE: $SEALED_CONTROLLER_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved ingress controller'
grep -Fq "KIND_INGRESS_CERTGEN_IMAGE: $SEALED_CERTGEN_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved ingress cert generator'
grep -Fq "KIND_AGENT_SANDBOX_IMAGE: $SEALED_AGENT_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved agent-sandbox controller'
grep -Fq "KIND_WORKSPACE_IMAGE: $SEALED_WORKSPACE_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the Forgejo-proven workspace image'
grep -Fq "KIND_DIND_IMAGE: $SEALED_DIND_IMAGE" \
  "$ROOT/.gitea/workflows/ci.yaml" || fail 'Forgejo CI does not select the approved Docker DinD image'
if grep -Fq 'nexus-system-cluster.example.invalid/oci-approved/' \
    "$ROOT/.gitea/workflows/ci.yaml"; then
  fail 'Forgejo CI still uses the Nexus recovery alias for an approved Kind input'
fi

# The CI gate shards the retained suites across four matrix legs, each with its
# own cluster and a 45-minute ceiling; Required verification aggregates the one
# matrix job, so every shard must be green.
edge_kind_block="$(awk '
  $0 == "  edge-kind:" { selected=1; next }
  selected && /^  [a-z][a-z-]*:$/ { exit }
  selected { print }
' "$ROOT/.gitea/workflows/ci.yaml")"
[ -n "$edge_kind_block" ] || fail 'ci.yaml lost the edge-kind job'
for shard_contract in \
    'name: Edge / Kind verification (${{ matrix.shard.slug }})' \
    'timeout-minutes: 45' \
    'fail-fast: true' \
    'slug: environment' \
    'suites: runtime-acceptance' \
    'slug: dashboard' \
    'suites: dashboard-browser' \
    'slug: workspace' \
    'suites: workspace-services final-fencing credentials' \
    'slug: edge' \
    'suites: edge-contract integrated' \
    'KIND_CLUSTER_NAME: codewire-e2e-ci-${{ github.run_id }}-${{ matrix.shard.slug }}' \
    'scripts/ci/verify/kind-e2e.sh shard "${suites[@]}"' \
    'CLUSTER: codewire-e2e-ci-${{ github.run_id }}-${{ matrix.shard.slug }}' \
    'CODEWIRE_KIND_PROFILE_ROOT: ${{ runner.temp }}/kind-profiles' \
    'scripts/ci/verify/kind-e2e.sh down || true'; do
  grep -Fq "$shard_contract" <<<"$edge_kind_block" ||
    fail "Kind shard matrix is missing: $shard_contract"
done
# Edge static verification runs once, in the edge leg; the browser host
# dependencies belong only to the dashboard leg.
grep -Fq "contains(needs.verification-selection.outputs.selection, '|edge_kind|') && matrix.shard.slug == 'edge' }}" \
  <<<"$edge_kind_block" || fail 'Edge static verification is not pinned to the edge shard'
[ "$(grep -Fc "matrix.shard.slug == 'dashboard'" <<<"$edge_kind_block")" -eq 3 ] ||
  fail 'browser host dependencies and the failure upload are not pinned to the dashboard shard'
# Sandbox supply-chain provenance requires a live product workspace: every
# workspace-service fixture self-cleans, so no shard may invoke it standalone.
# It runs only nested inside the TTL acceptance (pinned above against
# reconciler-ttl-smoke.rs).
if grep -Fq 'suites: workspace-services final-fencing sandbox-supply-chain' <<<"$edge_kind_block"; then
  fail 'a shard invokes sandbox-supply-chain standalone; it needs a live product workspace'
fi
grep -Fq '.args(["suite", "sandbox-supply-chain"])' \
  "$ROOT/crates/codewire-orchestration/src/bin/reconciler-ttl-smoke.rs" ||
  fail 'TTL acceptance no longer nests the sandbox supply-chain observation'
required_block="$(awk '
  $0 == "  required-verification:" { selected=1; next }
  selected && /^  [a-z][a-z-]*:$/ { exit }
  selected { print }
' "$ROOT/.gitea/workflows/ci.yaml")"
grep -Fq '      - edge-kind' <<<"$required_block" ||
  fail 'Required verification does not aggregate the Kind shard matrix'
grep -Fq 'VERIFICATION_EDGE_KIND_RESULT: ${{ needs.edge-kind.result }}' \
  "$ROOT/.gitea/workflows/ci.yaml" ||
  fail 'Required verification does not consume the aggregated shard result'

# Restore the production API recovery implementation after the load-order spy.
# shellcheck source=scripts/ci/verify/kind/common.sh
source "$COMMON"

# A remote DinD job joins the exact Kind network, receives an internal
# kubeconfig, and starts loopback-only forwarding for the existing host-port
# contracts. A local Docker caller remains untouched.
: >"$CALLS"
(
  HOSTNAME=remote-job
  HOME="$FIXTURE/remote-home"
  KUBECONFIG="$FIXTURE/remote-kubeconfig"
  docker() {
    # shellcheck disable=SC2016 # Match the literal Go-template CLI argument.
    case "$*" in
      'container inspect remote-job') return 0 ;;
      "inspect --format {{range \$name, \$_ := .NetworkSettings.Networks}}{{println \$name}}{{end}} ${KIND_CLUSTER_NAME}-control-plane")
        printf 'kind\n'
        ;;
      'network connect kind remote-job') record 'network-connect:kind:remote-job' ;;
      *) fail "unexpected remote Docker invocation: $*" ;;
    esac
  }
  kind() {
    if [ "$*" != "get kubeconfig --internal --name $KIND_CLUSTER_NAME" ]; then
      fail "unexpected remote Kind invocation: $*"
    fi
    printf 'apiVersion: v1\ncurrent-context: kind-%s\n' "$KIND_CLUSTER_NAME"
  }
  start_remote_dind_kind_forwarding() { record "forward:$1"; }
  log() { record "log:$*"; }
  configure_remote_dind_kind_network
  grep -Fqx "current-context: kind-${KIND_CLUSTER_NAME}" "$KUBECONFIG" ||
    fail 'remote DinD kubeconfig did not use the internal Kind rendering'
)
cat >"$FIXTURE/want-remote-dind" <<EOF
network-connect:kind:remote-job
forward:${KIND_CLUSTER_NAME}-control-plane
log:remote DinD Kind API and host-port topology configured
EOF
cmp -s "$FIXTURE/want-remote-dind" "$CALLS" || {
  diff -u "$FIXTURE/want-remote-dind" "$CALLS" >&2 || true
  fail 'remote DinD Kind network adaptation changed'
}

: >"$CALLS"
(
  HOSTNAME=local-host
  docker() {
    record "docker:$*"
    return 1
  }
  log() { record "log:$*"; }
  configure_remote_dind_kind_network
)
cat >"$FIXTURE/want-local-docker" <<'EOF'
docker:container inspect local-host
log:local Docker topology detected; retaining Kind host-port kubeconfig
EOF
cmp -s "$FIXTURE/want-local-docker" "$CALLS" ||
  fail 'local Docker topology no longer bypasses remote DinD adaptation'

# A transient API refusal after image import is retried, but a control plane
# that never recovers fails closed at the fixed 60-second boundary.
: >"$CALLS"
(
  attempts=0
  kubectl() {
    attempts=$((attempts + 1))
    record "probe:${attempts}:$*"
    [ "$attempts" -ge 3 ]
  }
  sleep() { record "sleep:$1"; }
  log() { record "log:$*"; }
  wait_for_kind_api_after_image_load
)
cat >"$FIXTURE/want-api-recovery" <<EOF
log:checking Kind API after image import
probe:1:--context kind-${KIND_CLUSTER_NAME} --request-timeout=1s get --raw=/readyz
sleep:1
probe:2:--context kind-${KIND_CLUSTER_NAME} --request-timeout=1s get --raw=/readyz
sleep:1
probe:3:--context kind-${KIND_CLUSTER_NAME} --request-timeout=1s get --raw=/readyz
log:Kind API ready after image import
EOF
cmp -s "$FIXTURE/want-api-recovery" "$CALLS" || {
  diff -u "$FIXTURE/want-api-recovery" "$CALLS" >&2 || true
  fail 'Kind API recovery did not retain its bounded retry contract'
}

: >"$CALLS"
if (
  kubectl() { record probe; return 1; }
  sleep() { :; }
  capture_kind_control_plane_state() { record diagnostic; }
  wait_for_kind_api_after_image_load
) >"$FIXTURE/api-unavailable.out" 2>&1; then
  fail 'permanently unavailable Kind API unexpectedly succeeded'
fi
[ "$(grep -c '^probe$' "$CALLS")" -eq 60 ] ||
  fail 'Kind API failure did not exhaust the fixed retry boundary'
[ "$(grep -c '^diagnostic$' "$CALLS")" -eq 1 ] ||
  fail 'Kind API failure did not capture one value-blind diagnostic'
grep -Fq 'did not become ready within 60 seconds after image import' \
  "$FIXTURE/api-unavailable.out" ||
  fail 'Kind API failure did not explain the bounded recovery failure'

# A cluster becomes rerunnable only after controller, credential, workspace/
# file, and ordinary Temporal prerequisites pass, before final fencing.
: >"$CALLS"
deploy_agent_sandbox() { record deploy-agent; }
kind_credential_bootstrap_smoke() { record credential-bootstrap; }
kind_credential_native_smoke() { record credential-native; }
workspace_service_smokes() { record workspace-services; }
temporal_workflow_smoke() { record temporal-workflow; }
mark_retained_cluster_prepared() { record prepared-marker; }
temporal_fencing_smoke() { record temporal-fencing; }
deploy_agent_sandbox_and_smoke
cat >"$FIXTURE/want-prepared-order" <<'EOF'
deploy-agent
credential-bootstrap
credential-native
workspace-services
temporal-workflow
prepared-marker
temporal-fencing
EOF
cmp -s "$FIXTURE/want-prepared-order" "$CALLS" ||
  fail 'prepared marker does not guard the final-fencing boundary'

# Retained validation rejects implicit naming, missing clusters, the wrong
# current context, missing markers, and incompatible marker versions.
RUN_DIR="$FIXTURE/retained-run"
mkdir -p "$RUN_DIR"
KIND_CLUSTER_NAME=retained-fixture
KIND_CLUSTER_NAME_EXPLICIT=0
expect_failure implicit-cluster validate_retained_cluster
grep -Fq 'explicit non-empty KIND_CLUSTER_NAME' "$FIXTURE/implicit-cluster.out" ||
  fail 'implicit cluster rejection was not decisive'

FAKE_CLUSTERS=other-cluster
FAKE_CONTEXT=kind-retained-fixture
FAKE_MARKER_VERSION="$KIND_E2E_COMPATIBILITY_VERSION"
FAKE_MARKER_CLUSTER="$KIND_CLUSTER_NAME"
FAKE_MARKER_WORKSPACE="$(kind_workspace_runtime_image)"
FAKE_SCOPED_MARKER=1
FAKE_LEGACY_MARKER=0
FAKE_RETAINED_EXPORT_FAIL=0
FAKE_RETAINED_REACHABLE=1
HOSTNAME=retained-local-host
docker() {
  case "$*" in
    'container inspect retained-local-host') return 1 ;;
    *) fail "unexpected retained local Docker invocation: $*" ;;
  esac
}
kind() {
  case "$*" in
    'get clusters') printf '%s\n' "$FAKE_CLUSTERS" ;;
    'get kubeconfig --name retained-fixture')
      [ "$FAKE_RETAINED_EXPORT_FAIL" = 0 ] || return 42
      printf 'apiVersion: v1\ncurrent-context: kind-retained-fixture\nserver: https://127.0.0.1:6443\n'
      ;;
    *) fail "unexpected fake kind invocation: $*" ;;
  esac
}
fake_marker_read() {
  # $1 = marker present (1/0), $2 = full kubectl arguments
  if [ "$1" != 1 ]; then
    printf 'NotFound\n' >&2
    return 1
  fi
  case "$2" in
    *compatibility_version*) printf '%s' "$FAKE_MARKER_VERSION" ;;
    *cluster-name*) printf '%s' "$FAKE_MARKER_CLUSTER" ;;
    *workspace-image*) printf '%s' "$FAKE_MARKER_WORKSPACE" ;;
    *) fail "unexpected fake marker field: $2" ;;
  esac
}
kubectl() {
  local scoped_marker
  scoped_marker="configmap/$(kind_e2e_prepared_configmap)"
  case "$*" in
    'config current-context') printf '%s\n' "$FAKE_CONTEXT" ;;
    *'cluster-info'*)
      [ "$FAKE_RETAINED_REACHABLE" = 1 ] &&
        grep -Fqx 'server: https://127.0.0.1:6443' "$KUBECONFIG"
      ;;
    *"${scoped_marker} "*)
      fake_marker_read "$FAKE_SCOPED_MARKER" "$*"
      ;;
    *"configmap/${KIND_E2E_PREPARED_CONFIGMAP} "*)
      fake_marker_read "$FAKE_LEGACY_MARKER" "$*"
      ;;
    *'get deployment/'*) printf '1' ;;
    *'get crd/sandboxclaims.extensions.agents.x-k8s.io'*) return 0 ;;
    *"exec deploy/postgres -- psql "*"UPDATE oidc_access_tokens SET expires_at"*"at_kind_connect_oidc_codewire_api"*)
      printf '%s\n' "${FAKE_RENEWED_BEARER-1}" ;;
    *) fail "unexpected fake kubectl invocation: $*" ;;
  esac
}

# The prepared marker is scoped to its own cluster name so parallel shard
# clusters and successive local clusters can never alias one marker.
[ "$(kind_e2e_prepared_configmap)" = codewire-kind-e2e-prepared-retained-fixture ] ||
  fail 'prepared marker is not scoped to the cluster name'
(
  KIND_CLUSTER_NAME=shard_One
  [ "$(kind_e2e_prepared_configmap)" = codewire-kind-e2e-prepared-shard-one ] ||
    fail 'prepared marker scoping does not sanitize to a ConfigMap name'
)
: >"$CALLS"
(
  # Restore the production definitions replaced by the earlier order spies.
  # shellcheck source=scripts/ci/verify/kind/common.sh
  source "$COMMON"
  kubectl() { record "$*"; cat >/dev/null; }
  kubectl_apply() { record "apply:$*"; cat >/dev/null; }
  kind_workspace_runtime_image() { printf 'workspace:fixture\n'; }
  mark_retained_cluster_prepared
)
grep -Fq 'create configmap codewire-kind-e2e-prepared-retained-fixture' "$CALLS" ||
  fail 'prepared marker create is not cluster-scoped'
grep -Fq -- '--from-literal=cluster-name=retained-fixture' "$CALLS" ||
  fail 'prepared marker lost its exact cluster binding'
grep -Fq -- '--from-literal=workspace-image=workspace:fixture' "$CALLS" ||
  fail 'prepared marker lost its workspace binding'
grep -Fq -- '--from-literal=compatibility_version=1' "$CALLS" ||
  fail 'prepared marker lost its version binding'

KIND_CLUSTER_NAME_EXPLICIT=1
expect_failure missing-cluster validate_retained_cluster
grep -Fq 'does not exist' "$FIXTURE/missing-cluster.out" ||
  fail 'missing cluster rejection was not decisive'

FAKE_CLUSTERS=$KIND_CLUSTER_NAME
FAKE_CONTEXT=codewire-dev
expect_failure wrong-context validate_retained_cluster
grep -Fq 'does not match retained Kind context' "$FIXTURE/wrong-context.out" ||
  fail 'wrong context rejection was not decisive'

FAKE_CONTEXT=kind-retained-fixture
FAKE_SCOPED_MARKER=0
FAKE_LEGACY_MARKER=0
expect_failure missing-marker validate_retained_cluster
grep -Fq 'is unprepared' "$FIXTURE/missing-marker.out" || {
  sed -n '1,80p' "$FIXTURE/missing-marker.out" >&2
  fail 'missing marker rejection was not decisive'
}

# A marker written before the name was cluster-scoped still satisfies the
# readback through the legacy name; its cluster-name field remains the binding.
FAKE_LEGACY_MARKER=1
validate_retained_cluster >"$FIXTURE/legacy-accepted.out"
grep -Fq 'accepted at compatibility version' "$FIXTURE/legacy-accepted.out" ||
  fail 'legacy prepared marker was not accepted through the fallback'
grep -Fq 'renewed the seeded synthetic product bearer' "$FIXTURE/legacy-accepted.out" ||
  fail 'retained validation did not renew the seeded synthetic product bearer'
# A retained cluster whose seed lacks the synthetic product bearer is refused.
FAKE_RENEWED_BEARER=''
expect_failure missing-bearer validate_retained_cluster
grep -Fq 'lacks the seeded synthetic product bearer' "$FIXTURE/missing-bearer.out" ||
  fail 'a retained cluster without the seeded bearer was not refused'
unset FAKE_RENEWED_BEARER

FAKE_SCOPED_MARKER=1
FAKE_LEGACY_MARKER=0
FAKE_MARKER_VERSION=0
expect_failure incompatible-marker validate_retained_cluster
grep -Fq 'marker is incompatible' "$FIXTURE/incompatible-marker.out" ||
  fail 'incompatible marker rejection was not decisive'

FAKE_RETAINED_EXPORT_FAIL=1
expect_failure retained-export-failed validate_retained_cluster
grep -Fq 'failed to pin kubeconfig' "$FIXTURE/retained-export-failed.out" ||
  fail 'failed retained kubeconfig export was not decisive'
FAKE_RETAINED_EXPORT_FAIL=0
FAKE_RETAINED_REACHABLE=0
expect_failure retained-api-unreachable validate_retained_cluster
grep -Fq 'is not reachable' "$FIXTURE/retained-api-unreachable.out" ||
  fail 'unreachable retained API was not rejected'
FAKE_RETAINED_REACHABLE=1

mkdir -p "$FIXTURE/bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"$FIXTURE/bin/temporal-fencing-smoke"
chmod +x "$FIXTURE/bin/temporal-fencing-smoke"
CARGO_CI_DIR="$FIXTURE/bin"
FAKE_MARKER_VERSION="$KIND_E2E_COMPATIBILITY_VERSION"
FAKE_MARKER_WORKSPACE=stale-workspace
expect_failure stale-workspace-marker validate_retained_cluster
grep -Fq 'workspace image does not match' "$FIXTURE/stale-workspace-marker.out" ||
  fail 'stale retained workspace was not decisively rejected'
FAKE_MARKER_WORKSPACE="$(kind_workspace_runtime_image)"
(
  CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci
  python3() { return 42; }
  expect_failure missing-retained-workspace-receipt validate_retained_cluster
)
validate_retained_cluster >"$FIXTURE/accepted.out"
grep -Fq 'accepted at compatibility version' "$FIXTURE/accepted.out" ||
  fail 'compatible retained cluster was not accepted'

# The cluster-workspace readback prefers the cluster-scoped marker and falls
# back to the legacy unscoped name written by earlier harnesses.
[ "$(KIND_RETAINED_USE_CLUSTER_WORKSPACE=1 kind_workspace_runtime_image)" = "$FAKE_MARKER_WORKSPACE" ] ||
  fail 'cluster workspace readback did not use the scoped marker'
FAKE_SCOPED_MARKER=0
FAKE_LEGACY_MARKER=1
[ "$(KIND_RETAINED_USE_CLUSTER_WORKSPACE=1 kind_workspace_runtime_image)" = "$FAKE_MARKER_WORKSPACE" ] ||
  fail 'cluster workspace readback did not use the legacy marker fallback'
FAKE_LEGACY_MARKER=0
if KIND_RETAINED_USE_CLUSTER_WORKSPACE=1 kind_workspace_runtime_image \
    >"$FIXTURE/missing-readback.out" 2>&1; then
  fail 'missing cluster workspace readback unexpectedly succeeded'
fi
FAKE_SCOPED_MARKER=1

# A provenance probe nested inside retained runtime acceptance owns a separate
# private kubeconfig. Its exit must not remove the parent suite's active file.
parent_kubeconfig="$RETAINED_KUBECONFIG"
[ -f "$parent_kubeconfig" ] || fail 'retained parent kubeconfig was not created'
[ "$(stat -c '%a' "$parent_kubeconfig")" = 600 ] ||
  fail 'retained parent kubeconfig is not private'
(
  trap retained_suite_cleanup EXIT
  validate_retained_cluster
  [ "$RETAINED_KUBECONFIG" != "$parent_kubeconfig" ] ||
    fail 'nested retained suite reused the parent kubeconfig'
  [ "$(stat -c '%a' "$RETAINED_KUBECONFIG")" = 600 ] ||
    fail 'retained child kubeconfig is not private'
  printf '%s\n' "$RETAINED_KUBECONFIG" >"$FIXTURE/child-kubeconfig-path"
) >"$FIXTURE/nested-retained.out"
child_kubeconfig="$(<"$FIXTURE/child-kubeconfig-path")"
[ ! -e "$child_kubeconfig" ] || fail 'retained child did not remove its own kubeconfig'
[ -f "$parent_kubeconfig" ] || fail 'retained child removed its parent kubeconfig'
[ "$KUBECONFIG" = "$parent_kubeconfig" ] || fail 'retained child displaced the parent context'

# Compose the real remote bootstrap and nested retained validation. The
# external endpoint belongs to the sibling DinD daemon, so a child that drops
# the parent's internal endpoint must fail even though the parent stays live.
if (
  HOSTNAME=remote-retained-job
  KIND_CLUSTER_NAME=remote-retained-fixture
  KIND_CLUSTER_NAME_EXPLICIT=1
  RUN_DIR="$FIXTURE/remote-retained-run"
  mkdir -p "$RUN_DIR"
  export KUBECONFIG="$RUN_DIR/parent-kubeconfig"
  CALLS="$RUN_DIR/calls"
  : >"$CALLS"
  remote_phase=bootstrap
  docker() {
    # shellcheck disable=SC2016 # Match the literal Go-template CLI argument.
    case "$*" in
      'container inspect remote-retained-job') return 0 ;;
      "inspect --format {{range \$name, \$_ := .NetworkSettings.Networks}}{{println \$name}}{{end}} ${KIND_CLUSTER_NAME}-control-plane")
        [ "$remote_phase" = bootstrap ] || fail 'nested retained suite inspected network topology'
        printf 'kind\n'
        ;;
      'network connect kind remote-retained-job')
        [ "$remote_phase" = bootstrap ] || fail 'nested retained suite reconnected its parent network'
        record network-connect
        ;;
      *) fail "unexpected composed remote Docker invocation: $*" ;;
    esac
  }
  kind() {
    local server
    case "$*" in
      'get clusters') printf '%s\n' "$KIND_CLUSTER_NAME"; return ;;
      "get kubeconfig --internal --name $KIND_CLUSTER_NAME")
        server="https://${KIND_CLUSTER_NAME}-control-plane:6443"
        ;;
      "get kubeconfig --name $KIND_CLUSTER_NAME")
        server='https://127.0.0.1:6443'
        ;;
      *) fail "unexpected composed remote Kind invocation: $*" ;;
    esac
    printf 'apiVersion: v1\ncurrent-context: kind-%s\nserver: %s\n' \
      "$KIND_CLUSTER_NAME" "$server"
  }
  kubectl() {
    case "$*" in
      'config current-context') sed -n 's/^current-context: //p' "$KUBECONFIG" ;;
      *'cluster-info'*)
        grep -Fqx "server: https://${KIND_CLUSTER_NAME}-control-plane:6443" "$KUBECONFIG"
        ;;
      *"configmap/${KIND_E2E_PREPARED_CONFIGMAP}"*"compatibility_version"*)
        printf '%s' "$KIND_E2E_COMPATIBILITY_VERSION"
        ;;
      *"configmap/${KIND_E2E_PREPARED_CONFIGMAP}"*"cluster-name"*)
        printf '%s' "$KIND_CLUSTER_NAME"
        ;;
      *"configmap/${KIND_E2E_PREPARED_CONFIGMAP}"*"workspace-image"*)
        kind_workspace_runtime_image
        ;;
      *'get deployment/'*) printf '1' ;;
      *'get crd/sandboxclaims.extensions.agents.x-k8s.io'*) return 0 ;;
      *"exec deploy/postgres -- psql "*"UPDATE oidc_access_tokens SET expires_at"*"at_kind_connect_oidc_codewire_api"*)
        printf '1\n' ;;
      *) fail "unexpected composed remote kubectl invocation: $*" ;;
    esac
  }
  start_remote_dind_kind_forwarding() {
    [ "$remote_phase" = bootstrap ] || fail 'nested retained suite restarted parent forwarders'
    record forwarder-start
  }
  stop_remote_dind_kind_forwarding() { fail 'nested retained suite stopped parent forwarding'; }
  acquire_kind_host_lock() { fail 'nested provenance suite reacquired the host lock'; }
  build_images_and_smokes() { fail 'nested provenance suite rebuilt images'; }
  create_cluster() { fail 'nested provenance suite recreated its cluster'; }
  deploy_overlay() { fail 'nested provenance suite redeployed its cluster'; }
  dump_cluster_state() { record failure-dump; }
  assert_sandbox_supply_chain() {
    [ "$KUBECONFIG" != "$remote_parent_kubeconfig" ] ||
      fail 'remote retained child reused its parent kubeconfig'
    [ "$(stat -c '%a' "$KUBECONFIG")" = 600 ] ||
      fail 'remote retained child kubeconfig is not private'
    grep -Fqx "server: https://${KIND_CLUSTER_NAME}-control-plane:6443" "$KUBECONFIG" ||
      fail 'remote retained child lost its internal API endpoint'
    printf '%s\n' "$KUBECONFIG" >"$RUN_DIR/child-kubeconfig-path"
    record provenance
  }
  configure_remote_dind_kind_network || exit $?
  remote_parent_kubeconfig="$KUBECONFIG"
  remote_parent_content="$(<"$remote_parent_kubeconfig")"
  [ "$(stat -c '%a' "$remote_parent_kubeconfig")" = 600 ] ||
    fail 'remote parent kubeconfig is not private'
  kubectl --context "kind-$KIND_CLUSTER_NAME" cluster-info --request-timeout=10s ||
    fail 'remote parent did not reach its internal API'
  remote_phase=retained
  (
    # A fresh child dispatcher reinitializes these ownership variables.
    REMOTE_DIND_JOB_CONTAINER=""
    REMOTE_DIND_KIND_NETWORK=""
    REMOTE_DIND_FORWARDER_PID=""
    RETAINED_KUBECONFIG=""
    run_retained_sandbox_supply_chain_suite
  ) || exit $?
  remote_child_kubeconfig="$(<"$RUN_DIR/child-kubeconfig-path")"
  [ ! -e "$remote_child_kubeconfig" ] || fail 'remote child leaked its owned kubeconfig'
  [ -f "$remote_parent_kubeconfig" ] || fail 'remote child removed its parent kubeconfig'
  [ "$(<"$remote_parent_kubeconfig")" = "$remote_parent_content" ] ||
    fail 'remote child changed its parent kubeconfig content'
  [ "$KUBECONFIG" = "$remote_parent_kubeconfig" ] ||
    fail 'remote child displaced its parent context'
  kubectl --context "kind-$KIND_CLUSTER_NAME" cluster-info --request-timeout=10s ||
    fail 'remote child made the parent API unreachable'
  printf '%s\n' network-connect forwarder-start provenance | cmp -s - "$CALLS" ||
    fail 'remote retained child changed bootstrap ownership or skipped provenance'
) >"$FIXTURE/remote-nested-retained.out" 2>&1; then
  :
else
  sed -n '1,120p' "$FIXTURE/remote-nested-retained.out" >&2
  fail 'remote parent bootstrap did not preserve reachability through nested retained validation'
fi

# Runtime acceptance propagates the explicit cluster to its nested provenance
# check. Use a synthetic smoke executable; this fixture never starts a runtime.
cat >"$FIXTURE/bin/reconciler-ttl-smoke" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf 'ttl-cluster:%s\n' "${KIND_CLUSTER_NAME:?}"
EOF
chmod +x "$FIXTURE/bin/reconciler-ttl-smoke"
rust_reconciler_ttl_e2e >"$FIXTURE/ttl-wrapper.out"
grep -Fxq 'ttl-cluster:retained-fixture' "$FIXTURE/ttl-wrapper.out" ||
  fail 'TTL wrapper did not propagate its explicit Kind cluster'

# The two retained capabilities validate their cluster before their real
# assertion, with no image build, deployment, cluster recreation, or deletion.
(
  validate_retained_cluster() { record validate; }
  assert_sandbox_supply_chain() { record provenance; }
  rust_reconciler_ttl_e2e() { record ttl; }
  require_tool() { :; }
  acquire_kind_host_lock() { record acquire-lock; }
  build_images_and_smokes() { fail 'retained acceptance rebuilt images'; }
  create_cluster() { fail 'retained acceptance recreated its cluster'; }
  deploy_overlay() { fail 'retained acceptance redeployed its cluster'; }
  docker() { fail "retained acceptance invoked Docker: $*"; }
  kind() { fail "retained acceptance invoked Kind after validation: $*"; }
  log() { :; }
  RETAINED_KUBECONFIG=""
  : >"$CALLS"
  (run_retained_sandbox_supply_chain_suite)
  (run_retained_runtime_acceptance_suite)
)
printf '%s\n' validate provenance acquire-lock validate ttl | cmp -s - "$CALLS" ||
  fail 'retained runtime/provenance suites did not preserve validation-before-proof order'

# A failed prerequisite or proof must remain a failure, without falling through
# to green or acquiring ownership of the retained cluster's lifecycle.
for retained_function in run_retained_sandbox_supply_chain_suite \
    run_retained_runtime_acceptance_suite; do
  failed_steps=(validate proof)
  if [ "$retained_function" = run_retained_runtime_acceptance_suite ]; then
    failed_steps+=(lock)
  fi
  for failed_step in "${failed_steps[@]}"; do
    : >"$CALLS"
    if (
      validate_retained_cluster() {
        record validate
        [ "$failed_step" != validate ] || return 41
      }
      assert_sandbox_supply_chain() { record proof; return 42; }
      rust_reconciler_ttl_e2e() { record proof; return 42; }
      require_tool() { :; }
      acquire_kind_host_lock() {
        record acquire-lock
        [ "$failed_step" != lock ] || return 40
      }
      stop_gateway_port_forward() { :; }
      dump_cluster_state() { record dump; }
      kind() { record "kind:$*"; }
      docker() { record "docker:$*"; }
      log() { record "log:$*"; }
      RETAINED_KUBECONFIG=""
      "$retained_function"
    ) >"$FIXTURE/${retained_function}-${failed_step}.out" 2>&1; then
      fail "$retained_function accepted a failed $failed_step step"
    else
      retained_status=$?
    fi
    expected_status=42
    [ "$failed_step" != validate ] || expected_status=41
    [ "$failed_step" != lock ] || expected_status=40
    [ "$retained_status" -eq "$expected_status" ] ||
      fail "$retained_function lost the $failed_step failure status"
    if [ "$failed_step" != proof ] && grep -Fxq proof "$CALLS"; then
      fail "$retained_function ran its proof after a failed $failed_step prerequisite"
    fi
    if [ "$failed_step" != lock ]; then
      grep -Fxq dump "$CALLS" || fail "$retained_function did not diagnose its failure"
    fi
    if grep -Eq '^(kind:|docker:)|suite green' "$CALLS"; then
      fail "$retained_function claimed green or changed its retained runtime after failure"
    fi
  done
done

# A retained-suite failure dumps state but never deletes its cluster, even when
# KEEP_KIND_CLUSTER is unset or zero.
: >"$CALLS"
validate_retained_cluster() { :; }
temporal_fencing_smoke() { return 42; }
stop_gateway_port_forward() { :; }
dump_cluster_state() { record dump; }
log() { record "log:$*"; }
kind() { record "kind:$*"; }
KEEP_KIND_CLUSTER=0
RETAINED_KUBECONFIG=""
if (run_retained_final_fencing_suite); then
  fail 'failing retained final-fencing suite unexpectedly succeeded'
fi
grep -Fxq dump "$CALLS" || fail 'retained failure did not dump cluster state'
if grep -Fq 'delete cluster' "$CALLS"; then
  fail 'retained suite tried to delete its cluster'
fi

printf '[test-kind-e2e-suites] dispatcher, order, prerequisites, and cleanup passed\n'
