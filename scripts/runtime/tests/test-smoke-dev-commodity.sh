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
  rg -F 'packet_diagnostics:' "$WORKFLOW" >/dev/null || \
    fail "named workflow does not expose packet diagnostics"
  rg -F "always() && inputs.packet_diagnostics == 'true'" "$WORKFLOW" >/dev/null || \
    fail "packet diagnostics do not have an always-run cleanup guard"
  rg -F 'environment-cleanup.json' "$WORKFLOW" >/dev/null || \
    fail "packet diagnostics do not preserve cleanup evidence"
  awk '/name: Verify packet-diagnostic environment cleanup/,/name: Upload value-blind/' \
    "$WORKFLOW" | rg -F 'env rm --yes "$environment_id"' >/dev/null || \
    fail "packet diagnostic cleanup does not delete the exact environment"
  awk '/name: Verify packet-diagnostic environment cleanup/,/name: Upload value-blind/' \
    "$WORKFLOW" | rg -F 'env list --output json' >/dev/null || \
    fail "packet diagnostic cleanup does not verify authenticated absence"
  rg -F 'christopherhx/gitea-upload-artifact@8818363695ca2d5782c64f6453273341374767b7' \
    "$WORKFLOW" >/dev/null || \
    fail "named workflow does not pin its failure-evidence uploader"
  awk '/^start_peer_relay_packet_diagnostics\(\)/,/^}/' "$SMOKE" \
    | rg -F 'tcpdump -i any -Q inout -nn -tttt -l -s 48' >/dev/null || \
    fail "packet diagnostics do not inspect the actual host-network namespace"
  if awk '/^start_peer_relay_packet_diagnostics\(\)/,/^}/' "$SMOKE" \
    | rg -e '(^|[[:space:]])(-A|-X|-XX|-w)([[:space:]]|$)' >/dev/null; then
    fail "packet diagnostics must not capture packet payloads or pcap files"
  fi
  rg -F 'local peer-relay packet capture unavailable; continuing doctor' \
    "$SMOKE" >/dev/null || \
    fail "packet capture startup failure still suppresses the doctor traffic"
  rg -F 'peer-relay-packet-capture.json' "$SMOKE" >/dev/null || \
    fail "packet capture startup status is not preserved"
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

run_packet_header_summary_case() {
  local case_dir="$TEST_TMP/packet-headers"
  local raw="$case_dir/raw.log"
  local route="$case_dir/route.json"
  local summary="$case_dir/summary.json"
  local staged="$case_dir/staged.log"

  mkdir -p "$case_dir"
  printf '%s\n' \
    '2026-07-30 16:12:01.123456 eth0 Out IP 10.0.0.10.50123 > 192.0.2.35.41641: UDP, length 148' \
    '2026-07-30 16:12:01.223456 eth0 In IP 192.0.2.35.41641 > 10.0.0.10.50123: UDP, length 92' \
    '2026-07-30 16:12:01.323456 eth0 Out IP 10.0.0.10.50123 > 192.0.2.35.41641: UDP, length 148' \
    "payload $SENSITIVE_SENTINEL" >"$raw"
  jq -n '{
    destination: "192.0.2.35",
    interface: "eth0",
    source: "10.0.0.10",
    gateway: "10.0.0.1"
  }' >"$route"

  (
    source <(sed '$d' "$SMOKE")
    summarize_peer_relay_packet_headers \
      "$raw" "192.0.2.35" "41641" "$route" "$summary" "$staged"
  )

  jq -e '
    .relay == {ip: "192.0.2.35", port: 41641, protocol: "UDP"}
    and .route.interface == "eth0"
    and .route.source == "10.0.0.10"
    and .packets == {outbound: 2, inbound: 1}
  ' "$summary" >/dev/null || fail "packet header summary is incorrect"
  grep -F 'direction=outbound' "$staged" >/dev/null || \
    fail "outbound packet header was not staged"
  grep -F 'direction=inbound' "$staged" >/dev/null || \
    fail "inbound packet header was not staged"
  if grep -F "$SENSITIVE_SENTINEL" "$staged" "$summary" >/dev/null; then
    fail "packet diagnostic staged non-header input"
  fi
}

run_packet_capture_startup_failure_case() {
  local case_dir="$TEST_TMP/packet-capture-startup"
  local bin_dir="$case_dir/bin"
  local artifact_dir="$case_dir/artifact"
  local runtime_dir="$case_dir/runtime"
  local status_file="$artifact_dir/peer-relay-packet-capture.json"

  mkdir -p "$bin_dir" "$artifact_dir" "$runtime_dir"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf '"'"'%s\n'"'"' '"'"'[{"dst":"192.0.2.35","dev":"eth0","prefsrc":"198.51.100.157","gateway":"172.31.1.1"}]'"'"'' \
    >"$bin_dir/ip"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf '"'"'%s\n'"'"' '"'"'tcpdump: any: You do not have permission to perform this capture'"'"' >&2' \
    "printf '%s\\n' 'diagnostic context $SENSITIVE_SENTINEL' >&2" \
    'exit 1' \
    >"$bin_dir/tcpdump"
  chmod +x "$bin_dir/ip" "$bin_dir/tcpdump"

  (
    source <(sed '$d' "$SMOKE")
    PATH="$bin_dir:$PATH"
    TMPDIR_SMOKE="$runtime_dir"
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    SMOKE_PACKET_DIAGNOSTICS=1
    SMOKE_KEEP_ENV=1
    EXPECTED_TAILNET_PATH_TRANSPORT=peer_relay
    EXPECTED_TAILNET_PEER_RELAY_ENDPOINT=192.0.2.35:41641
    start_peer_relay_packet_diagnostics
    [[ "$SMOKE_PACKET_CAPTURE_UNAVAILABLE" == "1" ]] || \
      fail "packet capture startup failure did not remain externally observable"
  )

  jq -e '
    .state == "unavailable"
    and .failure_class == "permission_denied"
    and .exit_code == 1
    and .payload_captured == false
  ' "$status_file" >/dev/null || \
    fail "packet capture startup failure was not classified safely"
  if grep -F "$SENSITIVE_SENTINEL" "$status_file" >/dev/null; then
    fail "packet capture status retained raw startup stderr"
  fi
}

assert_static_contract
run_safe_diagnostic_case
run_environment_artifact_case
run_packet_header_summary_case
run_packet_capture_startup_failure_case

printf 'dev commodity smoke safe diagnostic tests: OK\n'
