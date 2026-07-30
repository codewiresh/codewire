#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
WORKFLOW="$ROOT/.gitea/workflows/runtime-dev-commodity-smoke.yaml"
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
  rg -F 'retain_environment:' "$WORKFLOW" >/dev/null || \
    fail "named workflow does not expose retained-environment diagnosis"
  rg -F 'christopherhx/gitea-upload-artifact@8818363695ca2d5782c64f6453273341374767b7' \
    "$WORKFLOW" >/dev/null || \
    fail "named workflow does not pin its failure-evidence uploader"
  if awk '/^capture_tailnet_doctor_failure_diagnostics\(\)/,/^}/' "$SMOKE" \
    | rg -F 'capture_container_log' >/dev/null; then
    fail "tailnet doctor failure diagnostics must not capture full container logs"
  fi
}

run_safe_diagnostic_case() {
  local output="$TEST_TMP/output"
  local error="$TEST_TMP/error"
  local case_dir="$TEST_TMP/case"
  local artifact_dir="$TEST_TMP/artifact"
  local captured="$case_dir/gateway-tailnet-allocator-doctor-failure.log"
  local captured_json="$case_dir/gateway-tailnet-allocator-doctor-failure.jsonl"

  mkdir -p "$case_dir"
  (
    source <(sed '$d' "$SMOKE")
    TMPDIR_SMOKE="$case_dir"
    ENV_ID="test-environment"
    GATEWAY_POD_NAME=""
    SANDBOX_NAMESPACE="test-namespace"
    SMOKE_KEEP_ENV=1
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    kubectl_dev() {
      if [[ "$*" == *" get pod "* ]]; then
        printf '%s\n' '{"items":[{"metadata":{"name":"gateway-test"}}]}'
        return 0
      fi
      if [[ "$*" == *" logs "* ]]; then
        printf '%s\n' '{"timestamp":"2026-07-30T12:44:08Z","level":"INFO","fields":{"message":"unrelated gateway log","value":"doctor-failure-sensitive-sentinel"},"target":"codewire_gateway"}'
        printf '%s\n' '{"timestamp":"2026-07-30T12:44:09Z","level":"INFO","fields":{"message":"rust gateway UDP peer relay allocation diagnostic","outcome":"retry_scheduled","path":"peer_relay","peer_count":1,"queued_count":0,"in_flight_count":0,"attempt_count":2,"failure_count":1},"target":"codewire_gateway::tailnet"}'
        return 0
      fi
      return 97
    }
    capture_tailnet_doctor_failure_diagnostics
    [[ "$GATEWAY_POD_NAME" == "gateway-test" ]]
  ) >"$output" 2>"$error"

  [[ -f "$captured" ]] || fail "safe diagnostic output was not captured"
  [[ -f "$captured_json" ]] || fail "raw JSON diagnostic output was not captured"
  jq -e '.fields.outcome == "retry_scheduled" and .fields.attempt_count == 2' \
    "$captured_json" >/dev/null || fail "representative tracing JSON was not preserved"
  cmp "$captured" "$artifact_dir/$(basename "$captured")" >/dev/null || \
    fail "normalized allocator evidence was not staged for artifact upload"
  cmp "$captured_json" "$artifact_dir/$(basename "$captured_json")" >/dev/null || \
    fail "raw allocator JSON was not staged for artifact upload"
  grep -F 'outcome=retry_scheduled' "$captured" >/dev/null || \
    fail "safe allocator outcome was not captured"
  grep -F 'path=peer_relay' "$captured" >/dev/null || \
    fail "safe allocator path was not captured"
  if grep -RF -- "$SENSITIVE_SENTINEL" "$output" "$error" "$captured" "$captured_json" \
    "$artifact_dir" >/dev/null; then
    fail "safe diagnostic path emitted an unfiltered log value"
  fi
}

run_environment_artifact_case() {
  local artifact_dir="$TEST_TMP/environment-artifact"

  (
    source <(sed '$d' "$SMOKE")
    ENV_ID="test-environment-id"
    SMOKE_NAME="test-environment-name"
    SMOKE_KEEP_ENV=1
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    record_environment_artifact
  )

  jq -e '
      .environment_id == "test-environment-id"
      and .environment_name == "test-environment-name"
      and .retained == true
    ' "$artifact_dir/environment.json" >/dev/null || \
    fail "retained environment identity was not staged for explicit cleanup"
}

assert_static_contract
run_safe_diagnostic_case
run_environment_artifact_case

printf 'dev commodity smoke safe diagnostic tests: OK\n'
