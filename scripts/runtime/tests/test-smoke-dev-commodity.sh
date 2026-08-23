#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SMOKE="$ROOT/scripts/runtime/dev/smoke-dev-commodity.sh"
WRAPPER="$ROOT/scripts/ci/verify/runtime-dev-commodity-smoke.sh"
CANDIDATE="$ROOT/scripts/runtime/dev/smoke-dev-candidate.sh"
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
  rg -F 'rust gateway UDP peer relay allocation diagnostic' "$SMOKE" >/dev/null || \
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
    source <(sed '$d' "$SMOKE")
    TMPDIR_SMOKE="$case_dir"
    SMOKE_ARTIFACT_DIR="$artifact_dir"
    SMOKE_DERP_FALLBACK=1
    SMOKE_TAILNET_DIRECT_WAIT=20s
    SMOKE_TAILNET_PEER_TIMEOUT=30s
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
    SMOKE_SKIP_KUBE=1 \
    CODEWIRE_SERVER_URL=https://dev.example.invalid \
    EXPECTED_CODEWIRE_DEV_SERVER_URL=https://dev.example.invalid \
    EXPECTED_TAILNET_PEER_RELAY_ENDPOINT=192.0.2.10:41641 \
    EXPECTED_UDP_RELAY_BIND_ADDRS=0.0.0.0:41641 \
    EXPECTED_UDP_RELAY_ALLOCATOR_URL=https://allocator.example.invalid \
    EXPECTED_TAILNET_DIRECT_UDP_LB_IP=192.0.2.11 \
    EXPECTED_TAILNET_DIRECT_UDP_TRANSPORT_ZONE=test-zone \
    EXPECTED_RUNTIME_TRANSPORT_REGION=test-region \
    "$WRAPPER" --help >"$output"

  [[ ! -e "$kubectl_log" ]] ||
    fail "application-only wrapper invoked kubectl"
  grep -Fq 'Usage:' "$output" ||
    fail "application-only wrapper did not reach the source-owned smoke"

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source <(sed '$d' "$SMOKE")
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    declare SMOKE_SKIP_KUBE=1 SMOKE_SKIP_SSH=0 SMOKE_DERP_FALLBACK=0 \
      SMOKE_PEER_RELAY_MATRIX=0 SMOKE_SSH_CONNECT_TIMEOUT=1
    run_tailnet_doctor() { :; }
    require_cmd() { :; }
    run_ssh_transport_smoke() { :; }
    run_gateway_host_key_restart_smoke() {
      fail "application-only smoke attempted a Kubernetes rollout"
    }
    run_ssh_smoke
  )
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
            exec: {command: ["sh", "-ec", "docker version --format '\''{{.Server.Version}}'\'' >/dev/null"]},
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
    source <(sed '$d' "$SMOKE")
    export EXPECTED_DOCKER_MODE=guest-dind
    assert_docker_socket_contract "$accepted"
  ) || fail "guest-memory Docker socket contract was rejected"

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source <(sed '$d' "$SMOKE")
    export EXPECTED_DOCKER_MODE=guest-dind
    assert_docker_socket_contract "$disk_backed"
  ) >/dev/null 2>&1; then
    fail "disk-backed Docker socket contract was accepted"
  fi

  if (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source <(sed '$d' "$SMOKE")
    export EXPECTED_DOCKER_MODE=guest-dind
    assert_docker_socket_contract "$missing_probe"
  ) >/dev/null 2>&1; then
    fail "Docker socket contract without a workspace connection probe was accepted"
  fi

  (
    # shellcheck disable=SC1090 # Intentional dynamic source fixture.
    source <(sed '$d' "$SMOKE")
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
    source <(sed '$d' "$SMOKE")
    # shellcheck disable=SC2034 # Values are consumed by the sourced smoke fixture.
    declare TMPDIR_SMOKE="$case_dir" SMOKE_NAME="isolation-contract" \
      SMOKE_IMAGE="workspace" SMOKE_CPU="2000" SMOKE_MEMORY="4096" \
      SMOKE_DISK="10" SMOKE_TTL="2h" SMOKE_ISOLATION_TIER="confidential" \
      SMOKE_KEEP_ENV=1
    cw() {
      printf '%s\n' "$@" >"$args_file"
      printf 'ID: 11111111-1111-4111-8111-111111111111\n'
    }
    create_environment
  ) >/dev/null 2>&1 || fail "explicit confidential isolation tier was rejected"

  awk '
    previous == "--isolation" && $0 == "confidential" { found = 1 }
    { previous = $0 }
    END { exit found ? 0 : 1 }
  ' "$args_file" || fail "environment create did not request confidential isolation explicitly"
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
    source <(sed '$d' "$SMOKE")
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
    source <(sed '$d' "$SMOKE")
    SMOKE_ARTIFACT_DIR="$case_dir/inner-only-artifact"
    capture_tailnet_client_failure_diagnostics "$case_dir/inner-only.json"
  ); then
    fail "client diagnostic accepted the obsolete inner-only report shape"
  fi
  [[ ! -e "$case_dir/inner-only-artifact/client-tailnet-peer-relay.json" ]] || \
    fail "invalid client diagnostic left a misleading artifact"

  : >"$case_dir/empty.json"
  if (
    source <(sed '$d' "$SMOKE")
    SMOKE_ARTIFACT_DIR="$case_dir/empty-artifact"
    capture_tailnet_client_failure_diagnostics "$case_dir/empty.json"
  ); then
    fail "client diagnostic accepted a missing doctor report"
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

run_kubernetes_failure_artifact_case() {
  local case_dir="$TEST_TMP/kubernetes-failure"
  local runtime_dir="$case_dir/runtime"
  local artifact_dir="$case_dir/artifact"
  local manifest="$artifact_dir/kubernetes-failure-manifest.json"

  mkdir -p "$runtime_dir" "$artifact_dir"
  (
    source <(sed '$d' "$SMOKE")
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
          printf '%s\n' '{"metadata":{"name":"pool-one","generation":3},"spec":{"replicas":1,"sandboxTemplateRef":{"name":"template-one"}},"status":{"replicas":1,"readyReplicas":0}}'
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
    and .claims[0].warm_pool == "pool-one"
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
    and .desired_replicas == 1
    and .current_replicas == 1
    and .ready_replicas == 0
  ' "$artifact_dir/kubernetes-failure/warm-pool.json" >/dev/null || \
    fail "warm-pool readiness summary is incomplete"
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
    source <(sed '$d' "$SMOKE")
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
    source <(sed '$d' "$SMOKE")
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
    source <(sed '$d' "$SMOKE")
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
    fail "packet diagnostic phases do not execute gateway readiness before the doctor"
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
    '*" env list --output json")' \
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
    source <(sed '$d' "$SMOKE")
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
    source <(sed '$d' "$SMOKE")
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
    source <(sed '$d' "$SMOKE")
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
run_application_only_boundary_case
run_docker_socket_contract_cases
run_explicit_isolation_tier_case
run_safe_diagnostic_case
run_safe_client_diagnostic_case
run_doctor_outer_timeout_receipt_case
run_environment_artifact_case
run_kubernetes_failure_artifact_case
run_packet_header_summary_case
run_packet_capture_startup_failure_case
run_packet_diagnostic_phase_order_case
run_admin_oauth_contract_cases

printf 'dev commodity smoke safe diagnostic tests: OK\n'
