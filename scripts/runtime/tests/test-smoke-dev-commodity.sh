#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-commodity-smoke-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"

readonly SENSITIVE_SENTINEL="doctor-failure-sensitive-sentinel"

cleanup() {
  rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT

fail() {
  printf 'dev commodity smoke tests: %s\n' "$*" >&2
  exit 1
}

assert_static_contract() {
  bash -n "$SMOKE"
  awk '/^run_tailnet_doctor\(\)/,/^}/' "$SMOKE" \
    | rg -F 'capture_tailnet_doctor_failure_diagnostics' >/dev/null || \
    fail "tailnet doctor no longer captures safe allocator diagnostics"
  rg -F 'rust gateway UDP peer relay allocation diagnostic' "$SMOKE" >/dev/null || \
    fail "safe allocator diagnostic marker is missing"
  if awk '/^capture_tailnet_doctor_failure_diagnostics\(\)/,/^}/' "$SMOKE" \
    | rg -F 'capture_container_log' >/dev/null; then
    fail "tailnet doctor failure diagnostics must not capture full container logs"
  fi
}

run_safe_diagnostic_case() {
  local output="$TEST_TMP/output"
  local error="$TEST_TMP/error"
  local case_dir="$TEST_TMP/case"
  local captured="$case_dir/gateway-tailnet-allocator-doctor-failure.log"

  mkdir -p "$case_dir"
  (
    source <(sed '$d' "$SMOKE")
    TMPDIR_SMOKE="$case_dir"
    ENV_ID="test-environment"
    GATEWAY_POD_NAME=""
    SANDBOX_NAMESPACE="test-namespace"
    SMOKE_KEEP_ENV=1
    kubectl_dev() {
      if [[ "$*" == *" get pod "* ]]; then
        printf '%s\n' '{"items":[{"metadata":{"name":"gateway-test"}}]}'
        return 0
      fi
      if [[ "$*" == *" logs "* ]]; then
        printf '%s\n' 'doctor-failure-sensitive-sentinel'
        printf '%s\n' 'outcome=retry_scheduled path=peer_relay peer_count=1 queued_count=0 in_flight_count=0 attempt_count=2 failure_count=1 rust gateway UDP peer relay allocation diagnostic'
        return 0
      fi
      return 97
    }
    capture_tailnet_doctor_failure_diagnostics
    [[ "$GATEWAY_POD_NAME" == "gateway-test" ]]
  ) >"$output" 2>"$error"

  [[ -f "$captured" ]] || fail "safe diagnostic output was not captured"
  grep -F 'outcome=retry_scheduled' "$captured" >/dev/null || \
    fail "safe allocator outcome was not captured"
  grep -F 'path=peer_relay' "$captured" >/dev/null || \
    fail "safe allocator path was not captured"
  if grep -RF -- "$SENSITIVE_SENTINEL" "$output" "$error" "$captured" >/dev/null; then
    fail "safe diagnostic path emitted an unfiltered log value"
  fi
}

assert_static_contract
run_safe_diagnostic_case

printf 'dev commodity smoke safe diagnostic tests: OK\n'
