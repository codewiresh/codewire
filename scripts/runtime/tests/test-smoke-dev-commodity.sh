#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
WRAPPER="$ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh"
CANDIDATE="$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh"
mkdir -p "$ROOT/.tmp"
TEST_TMP="$(mktemp -d "$ROOT/.tmp/codewire-dev-commodity-smoke-tests.XXXXXX")"
chmod 0700 "$TEST_TMP"
NO_LIVE_BIN="$TEST_TMP/no-live-bin"
NO_LIVE_LOG="$TEST_TMP/no-live-command.log"
mkdir -p "$NO_LIVE_BIN"
cat >"$NO_LIVE_BIN/kubectl" <<'EOF'
#!/usr/bin/env bash
printf 'kubectl %s\n' "$*" >>"${NO_LIVE_LOG:?}"
exit 98
EOF
chmod 0755 "$NO_LIVE_BIN/kubectl"
export NO_LIVE_LOG PATH="$NO_LIVE_BIN:$PATH"

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
  local application_secret_smoke application_secret_exec host_key_smoke normalized_smoke pod_shape

  bash -n "$SMOKE"
  bash -n "$WRAPPER"
  bash -n "$CANDIDATE"
  for required in \
    CODEWIRE_SERVER_URL \
    EXPECTED_CODEWIRE_DEV_SERVER_URL \
    KUBE_CONTEXT \
    CODEWIRE_SERVER_NAMESPACE \
    SANDBOX_NAMESPACE \
    EXPECTED_NODE \
    EXPECTED_TAILNET_PEER_RELAY_ENDPOINT \
    EXPECTED_UDP_RELAY_BIND_ADDRS \
    EXPECTED_UDP_RELAY_ALLOCATOR_URL \
    EXPECTED_TAILNET_DIRECT_UDP_LB_IP \
    EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE \
    EXPECTED_RUNTIME_TRANSPORT_REGION; do
    grep -Fq "$required=\"\${$required:-}\"" "$WRAPPER" ||
      fail "CI wrapper gives $required a committed topology default"
  done
  grep -Fq 'SMOKE_SKIP_KUBE="${SMOKE_SKIP_KUBE:-0}"' "$WRAPPER" ||
    fail "CI wrapper does not expose the application-only boundary"
  grep -Fq 'SMOKE_TAILNET_DOCTOR_TIMEOUT="${SMOKE_TAILNET_DOCTOR_TIMEOUT:-180}"' "$WRAPPER" ||
    fail "CI wrapper outer doctor budget is smaller than the concurrent probe horizon"
  grep -Fq 'if [[ "$SMOKE_SKIP_KUBE" != "1" ]]; then' "$WRAPPER" ||
    fail "CI wrapper does not guard Kubernetes setup"
  grep -Fq 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then trap cleanup EXIT;' "$SMOKE" ||
    fail "source smoke installs live cleanup traps outside its executable entrypoint"
  candidate_run_smoke="$(awk '/^run_smoke\(\)/,/^}/' "$CANDIDATE")"
  grep -Fq 'EXPECTED_RUNTIME_NODE_MIN_EPHEMERAL_GIB:-400' "$CANDIDATE" ||
    fail "candidate smoke no longer accepts nominal 500 GB runtime nodes"
  for required in \
    EXPECTED_TAILNET_PATH_TRANSPORT \
    EXPECTED_TAILNET_PEER_RELAY_ENDPOINT \
    EXPECTED_UDP_RELAY_BIND_ADDRS \
    EXPECTED_UDP_RELAY_ALLOCATOR_URL \
    EXPECTED_TAILNET_DIRECT_UDP_LB_IP \
    EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE \
    EXPECTED_RUNTIME_TRANSPORT_REGION; do
    grep -Fq "export $required" <<<"$candidate_run_smoke" ||
      fail "candidate smoke does not export $required to the verifier"
  done
  grep -Fq '[[ "$CODEWIRE_SERVER_URL" == "$EXPECTED_CODEWIRE_DEV_SERVER_URL"' \
    "$SMOKE" || fail "smoke no longer checks its externally configured dev endpoint"
  normalized_smoke="$(sed -E ':join; /\\$/ { N; s/\\\n[[:space:]]*/ /; b join; }' "$SMOKE")"
  if rg -i 'kubectl_dev[^#]*(secret|gateway_secret)' <<<"$normalized_smoke" >/dev/null; then
    fail "runtime smoke reads Kubernetes Secret resources instead of proving their use through workload behavior"
  fi
  # #2460: the workspace daemon hosts SSH and the tailnet. The Pod shape
  # proves an identity-free daemon binding over TLS and that no gateway
  # object exists; nothing inspects a gateway Pod.
  pod_shape="$(awk '/^assert_pod_shape\(\)/,/^}/' "$SMOKE")"
  for binding in 'assert_no_gateway_objects' 'CODEWIRE_WORKSPACE_BINDING_URL' \
      '.name == "orchestration-internal-roots"' '.readOnly == true' \
      'codewire-orchestration-workspace-binding.${CODEWIRE_SERVER_NAMESPACE}.svc.cluster.local:8087'; do
    rg -F -- "$binding" <<<"$pod_shape" >/dev/null ||
      fail "workspace access shape is missing: $binding"
  done
  if rg -e 'gateway_pod_json|gateway_deploy_json|GATEWAY_POD_NAME' "$SMOKE" >/dev/null; then
    fail "runtime smoke still inspects a gateway Pod or Deployment"
  fi
  awk '/^assert_no_gateway_objects\(\)/,/^}/' "$SMOKE" |
    rg -F 'codewire.sh/type=gateway' >/dev/null ||
    fail "no-gateway check no longer selects gateway objects by label"
  # The host key is the one the platform recorded for the current
  # generation: trusted only through the block `cw setup ssh` writes, whose
  # one trust source is `cw ssh known-hosts`, never first use; a changed key
  # is refused; stop and start rotate it. A user's own command line and an
  # SFTP-mode scp run over that same block.
  host_key_smoke="$(awk '/^user_ssh_config\(\)/,/^run_ssh_smoke\(\)/' "$SMOKE")"
  for binding in 'setup ssh --ssh-config-file "$config"' 'ssh -F "$config"' '"cw-cloud-$ENV_ID" "$@"' \
      'env CODEWIRE_SERVER_URL="$CODEWIRE_SERVER_URL"' 'user_ssh "printf' \
      'StrictHostKeyChecking=yes' 'GlobalKnownHostsFile=/dev/null' \
      'UserKnownHostsFile=$pinned' 'run_user_ssh_journey' \
      'user_ssh_as "cw-$ENV_ID"' 'did not run through the managed Host cw-* block' \
      "printf a && printf b | tr b B; exit 7" 'cmp -s "$up" "$down"' \
      'expect_host_key_refused forged' 'expect_host_key_refused previous-generation' \
      'the recorded host key did not rotate across stop and start'; do
    rg -F -- "$binding" <<<"$host_key_smoke" >/dev/null ||
      fail "host-key smoke is missing: $binding"
  done
  if rg -F 'accept-new' <<<"$host_key_smoke" >/dev/null; then
    fail "host-key smoke trusts a key on first use"
  fi
  if rg -F 'KnownHostsCommand=' <<<"$host_key_smoke" >/dev/null; then
    fail "host-key smoke hand-builds the block's KnownHostsCommand"
  fi
  application_secret_smoke="$(awk '/^run_application_secrets_smoke\(\)/,/^}/' "$SMOKE")"
  rg -F 'run_application_secret_exec "$guest_script" "$phase" "$phase_deadline"' <<<"$application_secret_smoke" >/dev/null ||
    fail "application-secret smoke no longer proves the live managed exec path"
  application_secret_exec="$(awk '/^run_application_secret_exec\(\)/,/^}/' "$SMOKE")"
  rg -F 'cw_with_timeout "$timeout_seconds" run --no-tty' <<<"$application_secret_exec" >/dev/null ||
    fail "application-secret helper no longer launches the live managed exec path"
  rg -F 'remaining=$((deadline - $(seconds_now)))' <<<"$application_secret_exec" >/dev/null ||
    fail "application-secret helper lost its remaining phase budget"
  rg -F '((timeout_seconds <= remaining)) || timeout_seconds="$remaining"' <<<"$application_secret_exec" >/dev/null ||
    fail "application-secret helper lost its remaining phase budget cap"
  [[ "$(rg -c 'start_application_restart_witness APP_SECRET_ALL_HASHES_' <<<"$application_secret_smoke")" == 2 ]] ||
    fail "all-scope application smoke no longer starts a witness before both source restarts"
  rg -F 'wait_for_application_restart_witness_termination "$phase"' <<<"$application_secret_smoke" >/dev/null ||
    fail "all-scope application smoke no longer requires exact old session termination"
  restart_witness="$(awk '/^application_restart_witness_guest\(\)/,/^run_application_secret_pty\(\)/' "$SMOKE")"
  rg -F 'cw_with_timeout 30 run --no-tty --output json --in "$ENV_ID"' <<<"$restart_witness" >/dev/null ||
    fail "restart witness no longer captures the durable session identity from public JSON launch output"
  rg -F 'cw_with_timeout 30 logs "$ENV_ID" --session "$session_id" --raw' <<<"$restart_witness" >/dev/null ||
    fail "restart witness no longer binds its ready receipt to exact-session public logs"
  [[ "$(rg -F -c 'cw_with_timeout 30 ls "$ENV_ID" --output json' <<<"$restart_witness")" == 2 ]] ||
    fail "restart witness no longer checks exact-session readiness and termination through public session lists"
  for terminal_state in Stopped Exited Failed Interrupted; do
    rg -F "\$state == \"$terminal_state\"" <<<"$restart_witness" >/dev/null ||
      fail "restart witness no longer recognizes terminal session state $terminal_state"
  done
  if rg -e 'APP_RESTART_WITNESS_PID|kill -0|stop_application_restart_witness' <<<"$restart_witness" >/dev/null; then
    fail "restart witness reverted to host attachment/PID termination proof"
  fi
  awk '/^create_application_workspace_marker\(\)/,/^}/' "$SMOKE" |
    rg -F 'head -c 32 /dev/urandom' >/dev/null ||
    fail "all-scope application marker is no longer guest-randomized"
  awk '/^run_tailnet_doctor\(\)/,/^}/' "$SMOKE" \
    | rg -F 'capture_tailnet_doctor_failure_diagnostics' >/dev/null || \
    fail "tailnet doctor no longer captures safe allocator diagnostics"
  awk '/^run_tailnet_doctor\(\)/,/^}/' "$SMOKE" \
    | rg -F 'capture_tailnet_client_failure_diagnostics "$stdout"' >/dev/null || \
    fail "tailnet doctor no longer captures safe client diagnostics"
  if awk '/^run_tailnet_doctor\(\)/,/^}/' "$SMOKE" \
    | rg -F '"$stdout" >&2' >/dev/null; then
    fail "tailnet doctor failure still prints the unfiltered client report"
  fi
  rg -F 'workspace daemon UDP peer relay allocation diagnostic' "$SMOKE" >/dev/null || \
    fail "safe allocator diagnostic marker is missing"
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
  awk '/^env_is_running\(\)/,/^}/' "$SMOKE" \
    | rg -F 'fail_if_workspace_crashloop' >/dev/null || \
    fail "environment wait no longer classifies the workspace daemon's CrashLoopBackOff"
  rg -F 'classify_coco_rest_isolation_result' "$SMOKE" >/dev/null || \
    fail "confidential REST-isolation smoke no longer preserves a classified result"
  if rg -F 'coco-rest-disabled-ok' "$SMOKE" >/dev/null; then
    fail "confidential REST-isolation smoke still discards cw run evidence through a pipe"
  fi
  rg -F '"http://127.0.0.1:8006/cdh/resource/\$resource_path" 2>/dev/null' \
    "$SMOKE" >/dev/null || \
    fail "confidential REST-isolation probe can interleave curl diagnostics with its marker"
}

run_coco_rest_isolation_classifier_case() {
  local name="$1"
  local command_exit="$2"
  local stdout_content="$3"
  local stderr_content="$4"
  local expected_status="$5"
  local expected_curl_exit="$6"
  local expected_evidence_source="$7"
  local case_dir="$TEST_TMP/coco-rest-isolation-$name"

  mkdir -p "$case_dir"
  (
    set --
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    TMPDIR_SMOKE="$case_dir/runtime"
    SMOKE_ARTIFACT_DIR="$case_dir/artifact"
    mkdir -p "$TMPDIR_SMOKE" "$SMOKE_ARTIFACT_DIR"
    chmod 0700 "$TMPDIR_SMOKE" "$SMOKE_ARTIFACT_DIR"

    local_stdout="$TMPDIR_SMOKE/coco-rest-isolation.stdout"
    local_stderr="$TMPDIR_SMOKE/coco-rest-isolation.stderr"
    printf '%s' "$stdout_content" >"$local_stdout"
    printf '%s' "$stderr_content" >"$local_stderr"
    chmod 0600 "$local_stdout" "$local_stderr"

    classify_coco_rest_isolation_result \
      "$command_exit" "$local_stdout" "$local_stderr"
    [[ "$COCO_REST_ISOLATION_STATUS" == "$expected_status" ]] || \
      fail "$name classified as $COCO_REST_ISOLATION_STATUS, expected $expected_status"
    [[ "$COCO_REST_ISOLATION_CURL_EXIT" == "$expected_curl_exit" ]] || \
      fail "$name curl exit was ${COCO_REST_ISOLATION_CURL_EXIT:-null}, expected ${expected_curl_exit:-null}"
    [[ "$COCO_REST_ISOLATION_EVIDENCE_SOURCE" == "$expected_evidence_source" ]] || \
      fail "$name evidence source was $COCO_REST_ISOLATION_EVIDENCE_SOURCE, expected $expected_evidence_source"

    record_coco_rest_isolation_receipt "$command_exit"
    [[ "$(stat -c '%a' "$COCO_REST_ISOLATION_RECEIPT")" == "600" ]] || \
      fail "$name receipt is not mode 0600"
    jq -e \
      --arg status "$expected_status" \
      --argjson command_exit "$command_exit" \
      --arg curl_exit "$expected_curl_exit" \
      --arg evidence_source "$expected_evidence_source" '
        .schema == "codewire.coco-rest-isolation/v1"
        and .status == $status
        and .commandExit == $command_exit
        and .curlExit == (if $curl_exit == "" then null else ($curl_exit | tonumber) end)
        and .evidenceSource == $evidence_source
        and .rawOutputCapturedPrivately == true
      ' "$COCO_REST_ISOLATION_RECEIPT" >/dev/null || \
      fail "$name structural receipt is incomplete"
  )
}

run_coco_rest_isolation_classifier_cases() {
  run_coco_rest_isolation_classifier_case \
    passed 0 \
    $'coco_rest_isolation_v1 status=passed curl_exit=7\n' \
    $'Launched session test\n' \
    passed 7 guest_marker
  run_coco_rest_isolation_classifier_case \
    listener-present 1 \
    $'coco_rest_isolation_v1 status=listener_present curl_exit=0\n' \
    $'Error: session exited with code 24\n' \
    listener_present 0 guest_marker
  run_coco_rest_isolation_classifier_case \
    unexpected-transport 1 \
    $'coco_rest_isolation_v1 status=inconclusive_transport curl_exit=28\n' \
    $'Error: session exited with code 25\n' \
    inconclusive_transport 28 guest_marker
  run_coco_rest_isolation_classifier_case \
    listener-terminal-status 1 '' \
    $'Error: session exited with code 24\n' \
    listener_present 0 cli_terminal_status
  run_coco_rest_isolation_classifier_case \
    inconclusive-terminal-status 1 '' \
    $'Error: session exited with code 25\n' \
    inconclusive_transport '' cli_terminal_status
  run_coco_rest_isolation_classifier_case \
    output-missing 0 '' \
    $'Launched session test\n' \
    output_missing '' none
  run_coco_rest_isolation_classifier_case \
    output-malformed 0 \
    $'curl diagnostic interleaved with structural output\n' \
    $'Launched session test\n' \
    output_malformed '' none
  run_coco_rest_isolation_classifier_case \
    command-failed 1 '' \
    $'AttachSession transport interrupted\n' \
    command_failed '' none
  run_coco_rest_isolation_classifier_case \
    duplicate-marker 0 \
    $'coco_rest_isolation_v1 status=passed curl_exit=7\ncoco_rest_isolation_v1 status=passed curl_exit=7\n' \
    '' command_failed '' none
}

run_workspace_crashloop_fail_fast_case() {
  local case_dir="$TEST_TMP/workspace-crashloop"
  local error="$case_dir/error"

  mkdir -p "$case_dir"
  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    TMPDIR_SMOKE="$case_dir"
    SMOKE_SKIP_KUBE=0
    SMOKE_COLLECT_FAILURE_DIAGNOSTICS=1
    ENV_ID="test-environment-id"
    SANDBOX_NAMESPACE="test-sandboxes"
    cw() {
      printf '%s\n' '{"state": "provisioning", "error_reason": null}'
    }
    kubectl_dev() {
      jq -n --arg sentinel "$SENSITIVE_SENTINEL" '{
        items: [{
          metadata: {name: "workspace-test", annotations: {unsafe: $sentinel}},
          status: {
            containerStatuses: [{
              name: "workspace",
              restartCount: 3,
              state: {waiting: {reason: "CrashLoopBackOff", message: $sentinel}}
            }]
          }
        }]
      }'
    }
    collect_failure_diagnostics() {
      [[ "$1" == "workspace-crashloop" ]]
    }
    env_is_running
  ) >/dev/null 2>"$error"; then
    fail "environment wait accepted a workspace daemon CrashLoopBackOff"
  fi

  grep -Fq \
    'workspace daemon container entered CrashLoopBackOff while environment state=provisioning (restart_count=3)' \
    "$error" || fail "workspace daemon CrashLoopBackOff was not classified immediately"
  if grep -Fq "$SENSITIVE_SENTINEL" "$error"; then
    fail "workspace CrashLoopBackOff classifier emitted an unfiltered status message"
  fi
}

run_doctor_outer_timeout_receipt_case() {
  local case_dir="$TEST_TMP/doctor-outer-timeout"
  local artifact_dir="$case_dir/artifact"
  local receipt="$case_dir/tailnet-doctor-timeout.json"
  local artifact_receipt="$artifact_dir/tailnet-doctor-timeout.json"
  local error="$case_dir/error"

  mkdir -p "$case_dir"
  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    TMPDIR_SMOKE="$case_dir"
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    SMOKE_DERP_FALLBACK=1
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    SMOKE_TAILNET_DIRECT_WAIT=20s
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    SMOKE_TAILNET_PEER_TIMEOUT=30s
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    SMOKE_TAILNET_DOCTOR_TIMEOUT=180
    SMOKE_PACKET_CAPTURE_UNAVAILABLE=0
    EXPECTED_TAILNET_PATH_TRANSPORT=direct_udp
    CODEWIRE_SERVER_URL=https://codewire-dev.example.invalid
    ENV_ID=test-environment
    CW_BIN=/does/not/run
    start_peer_relay_packet_diagnostics() { :; }
    stop_peer_relay_packet_diagnostics() { :; }
    capture_tailnet_doctor_failure_diagnostics() { :; }
    timeout() { return 124; }
    run_tailnet_doctor
  ) >/dev/null 2>"$error"; then
    fail "outer doctor timeout unexpectedly succeeded"
  fi

  [[ -s "$receipt" && -s "$artifact_receipt" ]] ||
    fail "outer doctor timeout did not preserve both structural receipts"
  cmp "$receipt" "$artifact_receipt" >/dev/null ||
    fail "staged outer doctor timeout receipt diverged"
  jq -e '
    .schema == "codewire.tailnet-doctor-timeout/v1"
    and .status == "outer_timeout"
    and .exitCode == 124
    and .expectedTransport == "direct_udp"
    and .directWait == "20s"
    and .peerTimeout == "30s"
    and .outerTimeout == "180"
    and .forcedDerp == true
    and .reportPresent == false
  ' "$receipt" >/dev/null || fail "outer doctor timeout receipt is incomplete"
  grep -Fq 'tailnet doctor exceeded its outer timeout' "$error" ||
    fail "outer doctor timeout failure was not classified"
}

run_application_only_boundary_case() {
  local fake_bin="$TEST_TMP/application-only-bin"
  local kubectl_log="$TEST_TMP/application-only-kubectl.log"
  local output="$TEST_TMP/application-only-help.out"

  mkdir -p "$fake_bin"
  cat >"$fake_bin/kubectl" <<'EOF'
#!/usr/bin/env bash
printf 'unexpected kubectl invocation\n' >>"${APPLICATION_ONLY_KUBECTL_LOG:?}"
exit 99
EOF
  chmod 0755 "$fake_bin/kubectl"

  APPLICATION_ONLY_KUBECTL_LOG="$kubectl_log" \
    PATH="$fake_bin:$PATH" \
    CODEWIRE_SERVER_URL=https://dev.example.invalid \
    EXPECTED_CODEWIRE_DEV_SERVER_URL=https://dev.example.invalid \
    "$WRAPPER" --only application-secrets-all-scopes --help >"$output"

  [[ ! -e "$kubectl_log" ]] ||
    fail "application-only wrapper invoked kubectl"
  grep -Fq 'Usage:' "$output" ||
    fail "application-only wrapper did not reach the source-owned smoke"

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    declare SMOKE_SKIP_KUBE=1 SMOKE_SKIP_SSH=0 SMOKE_DERP_FALLBACK=0 \
      SMOKE_PEER_RELAY_MATRIX=0 SMOKE_SSH_CONNECT_TIMEOUT=1
    run_tailnet_doctor() { :; }
    require_cmd() { :; }
    run_ssh_transport_smoke() { :; }
    run_host_key_smoke() { :; }
    kubectl_dev() {
      fail "application-only smoke used Kubernetes"
    }
    run_ssh_smoke
  )
}

run_missing_server_namespace_case() {
  local stdout="$TEST_TMP/missing-server-namespace.out"
  local stderr="$TEST_TMP/missing-server-namespace.err"

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export SMOKE_SKIP_KUBE=0
    export CODEWIRE_SERVER_NAMESPACE=""
    run_kube_assertions
  ) >"$stdout" 2>"$stderr"; then
    fail "Kubernetes assertions accepted an empty Codewire server namespace"
  fi

  grep -Fq 'CODEWIRE_SERVER_NAMESPACE is required for Kubernetes assertions' "$stderr" ||
    fail "empty Codewire server namespace did not fail at the namespace boundary"
  [[ ! -s "$stdout" ]] ||
    fail "empty Codewire server namespace emitted unexpected standard output"
}

run_docker_socket_contract_cases() {
  local case_dir="$TEST_TMP/docker-socket-contract"
  local accepted="$case_dir/accepted.json"
  local disk_backed="$case_dir/disk-backed.json"
  local missing_probe="$case_dir/missing-probe.json"
  local disabled="$case_dir/disabled.json"

  mkdir -p "$case_dir"
  jq -n '{
    spec: {
      volumes: [
        {name: "workspace", emptyDir: {}},
        {name: "docker-sock", emptyDir: {medium: "Memory"}}
      ],
      containers: [
        {
          name: "workspace",
          volumeMounts: [{name: "docker-sock", mountPath: "/var/run/docker"}],
          readinessProbe: {
            exec: {command: ["sh", "-ec", "test -f /codewire/run/daemon/ready && docker version --format '\''{{.Server.Version}}'\'' >/dev/null"]},
            periodSeconds: 2,
            timeoutSeconds: 2,
            failureThreshold: 3,
            successThreshold: 1
          }
        },
        {
          name: "dind",
          volumeMounts: [{name: "docker-sock", mountPath: "/var/run/docker"}]
        }
      ]
    }
  }' >"$accepted"
  jq '(.spec.volumes[] | select(.name == "docker-sock") | .emptyDir) = {}' \
    "$accepted" >"$disk_backed"
  jq 'del(.spec.containers[] | select(.name == "workspace") | .readinessProbe)' \
    "$accepted" >"$missing_probe"
  jq -n '{
    spec: {
      volumes: [{name: "workspace", emptyDir: {}}],
      containers: [{name: "workspace", volumeMounts: []}]
    }
  }' >"$disabled"

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export EXPECTED_DOCKER_MODE=guest-dind
    assert_docker_socket_contract "$accepted"
  ) || fail "guest-memory Docker socket contract was rejected"

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export EXPECTED_DOCKER_MODE=guest-dind
    assert_docker_socket_contract "$disk_backed"
  ) >/dev/null 2>&1; then
    fail "disk-backed Docker socket contract was accepted"
  fi

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export EXPECTED_DOCKER_MODE=guest-dind
    assert_docker_socket_contract "$missing_probe"
  ) >/dev/null 2>&1; then
    fail "Docker socket contract without a workspace connection probe was accepted"
  fi

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export EXPECTED_DOCKER_MODE=none
    assert_docker_socket_contract "$disabled"
  ) || fail "Docker-disabled socket contract was rejected"
}

run_explicit_isolation_tier_case() {
  local case_dir="$TEST_TMP/isolation-tier"
  local args_file="$case_dir/cw-args"

  mkdir -p "$case_dir"
  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    declare TMPDIR_SMOKE="$case_dir" SMOKE_NAME="isolation-contract" \
      SMOKE_IMAGE="workspace" SMOKE_CPU="2000" SMOKE_MEMORY="4096" \
      SMOKE_DISK="10" SMOKE_TTL="2h" SMOKE_ISOLATION_TIER="confidential" \
      SMOKE_KEEP_ENV=1
    cw() {
      printf '%s\n' "$@" >"$args_file"
      printf '{"id": "11111111-1111-4111-8111-111111111111"}\n'
    }
    create_environment
  ) >/dev/null 2>&1 || fail "explicit confidential isolation tier was rejected"

  awk '
    previous == "--isolation" && $0 == "confidential" { found = 1 }
    { previous = $0 }
    END { exit found ? 0 : 1 }
  ' "$args_file" || fail "environment create did not request confidential isolation explicitly"
  # Without its own document the smoke reads no codewire.yaml.
  [[ "$(sed -n '1,2p' "$args_file" | paste -sd ' ')" == "create --no-file" ]] ||
    fail "environment create without a document may read a codewire.yaml"
}

run_resize_guest_case() {
  local case_dir="$1" after_nproc="$2" after_mem_kib="$3" existing_env="${4:-}"

  mkdir -p "$case_dir"
  rm -f -- "$case_dir/probe-count" "$case_dir/resize-args"
  (
    # The smoke parses its positional options when sourced.
    set --
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    declare TMPDIR_SMOKE="$case_dir" ENV_ID="11111111-1111-4111-8111-111111111111" \
      SMOKE_EXISTING_ENV_ID="$existing_env" SMOKE_TIMEOUT_SECONDS=60 \
      SMOKE_RESIZE_GUEST_CPU_DELTA=1000 SMOKE_RESIZE_GUEST_MEMORY_DELTA=2048
    cw() {
      [[ "$*" == "info 11111111-1111-4111-8111-111111111111 --output json" ]] || return 97
      printf '{"cpu_millicores":1000,"memory_mb":2048}\n'
    }
    cw_with_timeout() {
      shift
      printf '%s\n' "$@" >"$case_dir/resize-args"
      jq -n '{operation: {state: "completed", applied_mode: "restart", pod_replaced: true,
        last_applied_resources: {cpu_millicores: 2000, memory_mb: 4096, disk_gb: 10}}}'
    }
    run_cw_session_script() {
      local count=0
      [[ ! -f "$case_dir/probe-count" ]] || count="$(<"$case_dir/probe-count")"
      printf '%s\n' "$((count + 1))" >"$case_dir/probe-count"
      printf 'unrelated login banner\n'
      if ((count == 0)); then
        printf 'guest_compute_v1 nproc=4 memtotal_kib=4061436\n'
      else
        printf 'guest_compute_v1 nproc=%s memtotal_kib=%s\n' "$after_nproc" "$after_mem_kib"
      fi
    }
    wait_environment() { :; }
    wait_for_cw_run() { :; }
    run_resize_guest_smoke
  )
}

run_resize_guest_truth_cases() {
  local case_dir="$TEST_TMP/resize-guest"
  local error="$case_dir/error"

  mkdir -p "$case_dir"
  # #2266 replay: the operation completed, but the guest kept its boot size.
  if run_resize_guest_case "$case_dir/defect" 4 4061436 >/dev/null 2>"$error"; then
    fail "resize guest truth accepted a memory resize that never reached the guest"
  fi
  grep -Fq 'the memory limit is not backed by guest RAM (#2266)' "$error" ||
    fail "resize guest truth did not name the unbacked memory limit"

  run_resize_guest_case "$case_dir/replaced" 5 6158588 >/dev/null 2>"$error" ||
    fail "resize guest truth rejected a replacement VM that grew: $(<"$error")"
  for expected in 2000m 4096MB --allow-restart --force --yes; do
    grep -Fxq -- "$expected" "$case_dir/replaced/resize-args" ||
      fail "resize guest truth did not request $expected"
  done
  [[ "$(<"$case_dir/replaced/probe-count")" == 2 ]] ||
    fail "resize guest truth did not probe the guest before and after"

  if run_resize_guest_case "$case_dir/existing" 5 6158588 existing-env >/dev/null 2>"$error"; then
    fail "resize guest truth resized a kept environment"
  fi
  grep -Fq 'run it on a fresh disposable environment' "$error" ||
    fail "resize guest truth did not explain the kept-environment refusal"
  [[ ! -e "$case_dir/existing/resize-args" ]] ||
    fail "resize guest truth reached the resize command for a kept environment"

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    assert_resize_guest_truth 4061436 2 4061436 2048 3000 2048
  ) >/dev/null 2>"$error"; then
    fail "resize guest truth accepted a CPU limit above the guest CPU count"
  fi
  grep -Fq 'the CPU limit is not backed by guest vCPUs (#2266)' "$error" ||
    fail "resize guest truth did not name the unbacked CPU limit"
}

run_confidential_preview_response_cases() {
  local case_dir="$TEST_TMP/confidential-preview-response"
  local headers="$case_dir/headers"
  local body="$case_dir/body"
  local token="codewire-preview-private-marker"

  mkdir -p "$case_dir"
  printf '%s\r\n' \
    'HTTP/2 302' \
    'location: https://codewire-dev.example/sign-in?redirect_uri=%2F' \
    'x-codewire-service: codewire-orchestration' >"$headers"
  printf '%s\n' '<a href="/sign-in">Found</a>.' >"$body"

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    validate_confidential_preview_response 302 "$headers" "$body" "$token"
  ) || fail "valid confidential preview sign-in boundary was rejected"

  printf '%s\n' "$token" >"$body"
  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    validate_confidential_preview_response 302 "$headers" "$body" "$token"
  ); then
    fail "confidential preview accepted an unauthenticated app-content leak"
  fi

  printf '%s\n' '<a href="/sign-in">Found</a>.' >"$body"
  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    validate_confidential_preview_response 200 "$headers" "$body" "$token"
  ); then
    fail "confidential preview accepted a non-redirect response"
  fi
}
run_safe_diagnostic_case() {
  local output="$TEST_TMP/output"
  local error="$TEST_TMP/error"
  local case_dir="$TEST_TMP/case"
  local artifact_dir="$TEST_TMP/artifact"
  local captured="$case_dir/daemon-tailnet-allocator-doctor-failure.log"
  local captured_json="$case_dir/daemon-tailnet-allocator-doctor-failure.jsonl"

  mkdir -p "$case_dir"
  (
    source "$SMOKE"
    TMPDIR_SMOKE="$case_dir"
    ENV_ID="test-environment"
    # shellcheck disable=SC2034 # Consumed by the sourced diagnostic helper.
    POD_NAME="workspace-test"
    SANDBOX_NAMESPACE="test-namespace"
    SMOKE_KEEP_ENV=1
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    kubectl_dev() {
      if [[ "$*" == *" logs workspace-test -c workspace "* ]]; then
        printf '%s\n' '{"timestamp":"2026-07-30T12:44:08Z","level":"INFO","fields":{"message":"unrelated daemon log","value":"doctor-failure-sensitive-sentinel"},"target":"codewire_workspace_access"}'
        printf '%s\n' '{"timestamp":"2026-07-30T12:44:09Z","level":"INFO","fields":{"message":"workspace daemon UDP peer relay allocation diagnostic","outcome":"retry_scheduled","path":"peer_relay","peer_count":1,"queued_count":0,"in_flight_count":0,"attempt_count":2,"failure_count":1},"target":"codewire_workspace_access::peer_relay"}'
        return 0
      fi
      return 97
    }
    capture_tailnet_doctor_failure_diagnostics
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

run_safe_client_diagnostic_case() {
  local case_dir="$TEST_TMP/client-diagnostic"
  local artifact_dir="$case_dir/artifact"
  local doctor_json="$case_dir/doctor.json"
  local captured="$artifact_dir/client-tailnet-peer-relay.json"

  mkdir -p "$case_dir"
  jq -n --arg sentinel "$SENSITIVE_SENTINEL" '{
    environment_id: $sentinel,
    server_url: $sentinel,
    expect: "udp_relay",
    direct: {
      environment_id: $sentinel,
      server_url: $sentinel,
      forced_derp: false,
      direct_wait: "5s",
      stages: [{
        name: "path",
        status: "fail",
        detail: $sentinel,
        duration_ms: 5001
      }],
      peer: {
        id: $sentinel,
        preferred_derp: 1,
        endpoints: [$sentinel],
        addresses: [$sentinel]
      },
      direct_path: {
        ready: true,
        transport: "derp",
        endpoint: $sentinel,
        derp_region_id: 1,
        error: $sentinel
      },
      final_path: {
        ready: true,
        transport: "derp",
        endpoint: $sentinel,
        derp_region_id: 1,
        error: $sentinel
      },
      peer_relay: {
        state: "negotiating",
        derp_disco_received: 2,
        notifications_opened: 2,
        notifications_unknown_peer: 1,
        notifications_received: 1,
        notification_actions: 1,
        notification_no_actions: 0,
        relay_disco_sent: 3,
        relay_disco_send_failures: 0,
        relay_disco_received: 0,
        relay_drops: 0,
        relay_unmatched: 0,
        relay_wg_sent: 0,
        relay_wg_received: 0
      }
    },
    forced_derp: null
  }' >"$doctor_json"

  (
    source "$SMOKE"
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    capture_tailnet_client_failure_diagnostics "$doctor_json"
  )

  jq -e '
    .schema == "codewire-tailnet-peer-relay-diagnostic-v1"
    and .stages == [{
      name: "path",
      status: "fail",
      duration_ms: 5001
    }]
    and .direct_path == {
      ready: true,
      transport: "derp",
      derp_region_id: 1
    }
    and .final_path == {
      ready: true,
      transport: "derp",
      derp_region_id: 1
    }
    and .peer_relay == {
      state: "negotiating",
      derp_disco_received: 2,
      notifications_opened: 2,
      notifications_unknown_peer: 1,
      notifications_received: 1,
      notification_actions: 1,
      notification_no_actions: 0,
      relay_disco_sent: 3,
      relay_disco_send_failures: 0,
      relay_disco_received: 0,
      relay_drops: 0,
      relay_unmatched: 0,
      relay_wg_sent: 0,
      relay_wg_received: 0
    }
  ' "$captured" >/dev/null || fail "client diagnostic whitelist is incorrect"
  if grep -F "$SENSITIVE_SENTINEL" "$captured" >/dev/null; then
    fail "client diagnostic retained a sensitive value"
  fi
  if jq -e 'has("environment_id") or has("server_url") or has("peer")' \
      "$captured" >/dev/null; then
    fail "client diagnostic retained identity or server fields"
  fi

  jq '.direct' "$doctor_json" >"$case_dir/inner-only.json"
  if (
    source "$SMOKE"
    SMOKE_ARTIFACT_DIR="$case_dir/inner-only-artifact"
    capture_tailnet_client_failure_diagnostics "$case_dir/inner-only.json"
  ); then
    fail "client diagnostic accepted the obsolete inner-only report shape"
  fi
  [[ ! -e "$case_dir/inner-only-artifact/client-tailnet-peer-relay.json" ]] || \
    fail "invalid client diagnostic left a misleading artifact"

  : >"$case_dir/empty.json"
  if (
    source "$SMOKE"
    SMOKE_ARTIFACT_DIR="$case_dir/empty-artifact"
    capture_tailnet_client_failure_diagnostics "$case_dir/empty.json"
  ); then
    fail "client diagnostic accepted a missing doctor report"
  fi
}

run_environment_artifact_case() {
  local artifact_dir="$TEST_TMP/environment-artifact"

  (
    source "$SMOKE"
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

run_kubernetes_failure_artifact_case() {
  local case_dir="$TEST_TMP/kubernetes-failure"
  local runtime_dir="$case_dir/runtime"
  local artifact_dir="$case_dir/artifact"
  local manifest="$artifact_dir/kubernetes-failure-manifest.json"

  mkdir -p "$runtime_dir" "$artifact_dir"
  (
    source "$SMOKE"
    TMPDIR_SMOKE="$runtime_dir"
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    SMOKE_COLLECT_FAILURE_DIAGNOSTICS=1
    SMOKE_FAILURE_DIAGNOSTICS_CAPTURED=0
    SMOKE_KEEP_ENV=1
    ENV_ID="test-environment-id"
    CLAIM_NAME=""
    SANDBOX_NAMESPACE="test-sandboxes"
    KUBE_CONTEXT="test-context"
    kubectl() {
      return 0
    }
    maybe_default_kubeconfig() {
      return 0
    }
    select_kube_context_best_effort() {
      return 0
    }
    kubectl_dev() {
      case "$*" in
        *"version --client"*)
          return 0
          ;;
        *" get sandboxclaim -l "*)
          printf '%s\n' "{\"items\":[{\"metadata\":{\"name\":\"claim-one\",\"generation\":7,\"annotations\":{\"unsafe\":\"$SENSITIVE_SENTINEL\"}},\"spec\":{\"warmPoolRef\":{\"name\":\"pool-one\"},\"env\":[{\"name\":\"TOKEN\",\"value\":\"$SENSITIVE_SENTINEL\"}]},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"False\",\"reason\":\"SandboxPending\",\"message\":\"$SENSITIVE_SENTINEL\",\"observedGeneration\":7}]}}]}"
          ;;
        *" get sandboxclaim claim-one "*)
          printf '%s\n' "{\"metadata\":{\"name\":\"claim-one\"},\"spec\":{\"warmPoolRef\":{\"name\":\"pool-one\"},\"env\":[{\"name\":\"TOKEN\",\"value\":\"$SENSITIVE_SENTINEL\"}]},\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"False\",\"reason\":\"SandboxPending\",\"message\":\"$SENSITIVE_SENTINEL\"}]}}"
          ;;
        *" get sandboxwarmpool pool-one "*)
          printf '%s\n' '{"metadata":{"name":"pool-one","generation":3},"spec":{"replicas":0,"sandboxTemplateRef":{"name":"template-one"}},"status":{"replicas":0,"readyReplicas":0}}'
          ;;
        *" get sandboxtemplate template-one "*)
          printf '%s\n' "{\"metadata\":{\"name\":\"template-one\",\"annotations\":{\"unsafe\":\"$SENSITIVE_SENTINEL\"}},\"spec\":{\"podTemplate\":{\"spec\":{\"containers\":[{\"env\":[{\"value\":\"$SENSITIVE_SENTINEL\"}]}]}}}}"
          ;;
        *" get pod "*" -o wide"*)
          printf '%s\n' "raw wide output $SENSITIVE_SENTINEL"
          ;;
        *" get pod "*" -o json"*)
          printf '%s\n' "{\"items\":[{\"metadata\":{\"name\":\"pod-one\",\"annotations\":{\"unsafe\":\"$SENSITIVE_SENTINEL\"}},\"spec\":{\"runtimeClassName\":\"commodity\",\"containers\":[{\"name\":\"workspace\",\"image\":\"registry.invalid/$SENSITIVE_SENTINEL\",\"env\":[{\"value\":\"$SENSITIVE_SENTINEL\"}]}]},\"status\":{\"phase\":\"Pending\",\"conditions\":[{\"type\":\"PodScheduled\",\"status\":\"False\",\"reason\":\"Unschedulable\",\"message\":\"$SENSITIVE_SENTINEL\"}],\"containerStatuses\":[{\"name\":\"workspace\",\"ready\":false,\"restartCount\":2,\"imageID\":\"\",\"state\":{\"waiting\":{\"reason\":\"ImagePullBackOff\",\"message\":\"$SENSITIVE_SENTINEL\"}}}]}}]}"
          ;;
        *" describe pod "*)
          printf '%s\n' "raw describe output $SENSITIVE_SENTINEL"
          ;;
        *" get events "*" -o json"*)
          printf '%s\n' "{\"items\":[{\"involvedObject\":{\"kind\":\"Pod\",\"name\":\"pod-one\"},\"type\":\"Warning\",\"reason\":\"FailedScheduling\",\"reportingController\":\"default-scheduler\",\"count\":2,\"firstTimestamp\":\"2026-08-03T12:00:00Z\",\"lastTimestamp\":\"2026-08-03T12:01:00Z\",\"message\":\"0/1 nodes available: $SENSITIVE_SENTINEL\"},{\"involvedObject\":{\"kind\":\"Secret\",\"name\":\"unrelated\"},\"type\":\"Warning\",\"reason\":\"Unsafe\",\"message\":\"$SENSITIVE_SENTINEL\"}]}"
          ;;
        *" get events "*)
          printf '%s\n' "raw event output $SENSITIVE_SENTINEL"
          ;;
        *" logs "*)
          printf '%s\n' "raw container log $SENSITIVE_SENTINEL"
          ;;
        *)
          printf '%s\n' "unexpected kubectl invocation $SENSITIVE_SENTINEL" >&2
          return 97
          ;;
      esac
    }

    collect_failure_diagnostics failure
  )

  jq -e '
    .schema == "codewire-kubernetes-failure-manifest-v1"
    and .failure_label == "failure"
    and .data_contract == "allowlisted-structured-fields-only"
    and (.files | length) == 4
    and ([.files[].path] | unique | length) == 4
    and ([.files[].bytes | select(. > 0)] | length) == 4
  ' "$manifest" >/dev/null || fail "Kubernetes failure manifest is incomplete"
  jq -e '
    .read_state == "available"
    and .count == 1
    and .claims[0].name == "claim-one"
    and .claims[0].claim_shadow == "pool-one"
    and .claims[0].conditions[0] == {
      type: "Ready",
      status: "False",
      reason: "SandboxPending",
      observed_generation: 7
    }
  ' "$artifact_dir/kubernetes-failure/claim.json" >/dev/null || \
    fail "claim readiness summary is incomplete"
  jq -e '
    .name == "pool-one"
    and .template == "template-one"
    and .desired_replicas == 0
    and .current_replicas == 0
    and .ready_replicas == 0
  ' "$artifact_dir/kubernetes-failure/claim-shadow.json" >/dev/null || \
    fail "claim-shadow summary is incomplete"
  jq -e '
    .pods[0].phase == "Pending"
    and .pods[0].node_assigned == false
    and .pods[0].runtime_class_configured == true
    and .pods[0].conditions[0].reason == "Unschedulable"
    and .pods[0].containers[0].state == {
      state: "waiting",
      reason: "ImagePullBackOff"
    }
  ' "$artifact_dir/kubernetes-failure/pods.json" >/dev/null || \
    fail "pod scheduling and image summary is incomplete"
  jq -e '
    (.events | length) == 1
    and .events[0].object_name == "pod-one"
    and .events[0].reason == "FailedScheduling"
    and .events[0].reporting_controller == "default-scheduler"
    and .events[0].message_class == "scheduling"
  ' "$artifact_dir/kubernetes-failure/events.json" >/dev/null || {
    jq . "$artifact_dir/kubernetes-failure/events.json" >&2 || true
    fail "bounded event summary is incomplete"
  }
  rg -F "$SENSITIVE_SENTINEL" "$runtime_dir/kube-diagnostics-failure" >/dev/null || \
    fail "synthetic raw diagnostic did not exercise sensitive input"
  if rg -F "$SENSITIVE_SENTINEL" "$artifact_dir" >/dev/null; then
    fail "Kubernetes failure artifact retained non-allowlisted content"
  fi
}

run_packet_header_summary_case() {
  local case_dir="$TEST_TMP/packet-headers"
  local raw="$case_dir/raw.log"
  local route="$case_dir/route.json"
  local summary="$case_dir/summary.json"
  local staged="$case_dir/staged.log"

  mkdir -p "$case_dir"
  printf '%s\n' \
    '2026-07-30 16:12:01.123456 eth0 Out IP 192.0.2.10.50123 > 192.0.2.20.41641: UDP, length 148' \
    '2026-07-30 16:12:01.223456 eth0 In IP 192.0.2.20.41641 > 192.0.2.10.50123: UDP, length 92' \
    '2026-07-30 16:12:01.323456 eth0 Out IP 192.0.2.10.50123 > 192.0.2.20.41641: UDP, length 148' \
    "payload $SENSITIVE_SENTINEL" >"$raw"
  jq -n '{
    destination: "192.0.2.20",
    interface: "eth0",
    source: "192.0.2.10",
    gateway: "192.0.2.1"
  }' >"$route"

  (
    source "$SMOKE"
    summarize_peer_relay_packet_headers \
      "$raw" "192.0.2.20" "41641" "$route" "$summary" "$staged"
  )

  jq -e '
    .relay == {ip: "192.0.2.20", port: 41641, protocol: "UDP"}
    and .route.interface == "eth0"
    and .route.source == "192.0.2.10"
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
    'printf '"'"'%s\n'"'"' '"'"'[{"dst":"192.0.2.20","dev":"eth0","prefsrc":"192.0.2.10","gateway":"192.0.2.1"}]'"'"'' \
    >"$bin_dir/ip"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'printf '"'"'%s\n'"'"' '"'"'tcpdump: any: You do not have permission to perform this capture'"'"' >&2' \
    "printf '%s\\n' 'diagnostic context $SENSITIVE_SENTINEL' >&2" \
    'exit 1' \
    >"$bin_dir/tcpdump"
  chmod +x "$bin_dir/ip" "$bin_dir/tcpdump"

  (
    source "$SMOKE"
    PATH="$bin_dir:$PATH"
    TMPDIR_SMOKE="$runtime_dir"
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    SMOKE_PACKET_DIAGNOSTICS=1
    SMOKE_KEEP_ENV=1
    EXPECTED_TAILNET_PATH_TRANSPORT=peer_relay
    EXPECTED_TAILNET_PEER_RELAY_ENDPOINT=192.0.2.20:41641
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

run_packet_diagnostic_phase_order_case() {
  local output="$TEST_TMP/packet-diagnostic-phase-order"

  (
    source "$SMOKE"
    SMOKE_ONLY_PHASES=(kube doctor)
    run_kube_assertions() {
      printf 'kube-ready\n'
    }
    run_tailnet_doctor() {
      printf 'doctor\n'
    }
    run_selected_phases
  ) >"$output" 2>/dev/null

  printf 'kube-ready\ndoctor\n' | cmp - "$output" >/dev/null || \
    fail "packet diagnostic phases do not execute workspace readiness before the doctor"
}

write_admin_oauth_fixture() {
  local config_dir="$1"

  mkdir -p "$config_dir"
  chmod 0700 "$config_dir"
  printf '{}\n' >"$config_dir/config.json"
  printf '{}\n' >"$config_dir/credentials.json"
  chmod 0600 "$config_dir/config.json" "$config_dir/credentials.json"
}

write_admin_oauth_cw_fixture() {
  local cw_bin="$1"

  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'case "$*" in' \
    '*" whoami --output json")' \
    '  printf '\''%s\n'\'' '\''{"id":"admin-id","email":"admin@example.com","email_verified":false,"is_admin":false}'\''' \
    '  ;;' \
    '*" org current")' \
    '  printf '\''%s\n'\'' '\''ID: admin-org'\''' \
    '  ;;' \
    '*" ls --output json")' \
    '  printf '\''%s\n'\'' '\''[]'\''' \
    '  ;;' \
    '*) exit 97 ;;' \
    'esac' >"$cw_bin"
  chmod +x "$cw_bin"
}

run_admin_oauth_contract_cases() {
  local case_dir="$TEST_TMP/admin-oauth"
  local config_dir="$case_dir/config"
  local cw_bin="$case_dir/cw"
  local error="$case_dir/error"

  mkdir -p "$case_dir"
  write_admin_oauth_fixture "$config_dir"
  write_admin_oauth_cw_fixture "$cw_bin"

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export CODEWIRE_SERVER_URL="https://codewire-dev.example"
    export EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
    export CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$config_dir"
    export EXPECTED_CODEWIRE_ADMIN_EMAIL="admin@example.com"
    export SMOKE_AUTH_MODE="admin-oidc"
    export SMOKE_TMP_PARENT="$case_dir/tmp-success"
    export CW_BIN="$cw_bin"
    unset CODEWIRE_API_KEY CODEWIRE_DEV_SMOKE_API_KEY
    prepare_cli
    [[ "$CW_CONFIG_DIR" == "$config_dir" ]]
    [[ -z "${CODEWIRE_API_KEY+x}" ]]
  ) >/dev/null 2>"$error" || {
    sed 's/[[:cntrl:]]//g' "$error" >&2 || true
    fail "valid saved admin OIDC contract was rejected"
  }

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export CODEWIRE_SERVER_URL="https://codewire-dev.example"
    export EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
    export CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$config_dir"
    export SMOKE_AUTH_MODE="admin-oidc"
    export SMOKE_TMP_PARENT="$case_dir/tmp-api-key"
    export CW_BIN="$cw_bin"
    export CODEWIRE_API_KEY="cw_forbidden"
    prepare_cli
  ) >/dev/null 2>"$error"; then
    fail "admin OIDC mode accepted an inherited API key"
  fi
  grep -F -- '--admin-oidc refuses inherited API keys' "$error" >/dev/null || \
    fail "admin OIDC inherited-key refusal was not explicit"

  chmod 0644 "$config_dir/credentials.json"
  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source "$SMOKE"
    export CODEWIRE_SERVER_URL="https://codewire-dev.example"
    export EXPECTED_CODEWIRE_DEV_SERVER_URL="$CODEWIRE_SERVER_URL"
    export CODEWIRE_ADMIN_OAUTH_CONFIG_DIR="$config_dir"
    export SMOKE_AUTH_MODE="admin-oidc"
    export SMOKE_TMP_PARENT="$case_dir/tmp-mode"
    export CW_BIN="$cw_bin"
    unset CODEWIRE_API_KEY CODEWIRE_DEV_SMOKE_API_KEY
    prepare_cli
  ) >/dev/null 2>"$error"; then
    fail "admin OIDC mode accepted a non-private credential file"
  fi
  grep -F 'must be mode 0600' "$error" >/dev/null || \
    fail "admin OIDC file-mode refusal was not explicit"
}

assert_static_contract
run_coco_rest_isolation_classifier_cases
run_workspace_crashloop_fail_fast_case
run_application_only_boundary_case
run_missing_server_namespace_case
run_docker_socket_contract_cases
run_explicit_isolation_tier_case
run_resize_guest_truth_cases
run_confidential_preview_response_cases
run_safe_diagnostic_case
run_safe_client_diagnostic_case
run_doctor_outer_timeout_receipt_case
run_environment_artifact_case
run_kubernetes_failure_artifact_case
run_packet_header_summary_case
run_packet_capture_startup_failure_case
run_packet_diagnostic_phase_order_case
run_admin_oauth_contract_cases
bash "$ROOT/scripts/runtime/tests/test-smoke-dev-application-secrets.sh"
bash "$ROOT/scripts/runtime/tests/test-provider-ssh-smoke.sh"

[[ ! -e "$NO_LIVE_LOG" ]] || {
  sed -n '1,20p' "$NO_LIVE_LOG" >&2
  fail "hermetic smoke fixtures invoked a live Kubernetes command"
}

printf 'dev commodity smoke safe diagnostic tests: OK\n'
