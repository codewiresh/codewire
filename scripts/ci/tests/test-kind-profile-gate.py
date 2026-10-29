#!/usr/bin/env python3
"""Named gate regressions with synthetic endpoints and command boundaries."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ProfileGateTests(unittest.TestCase):
    def setUp(self):
        # A synthetic producer is executed in one failure-path case. The host
        # may mount its system temp filesystem noexec; use ignored repo scratch.
        scratch = ROOT / ".tmp"
        scratch.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="kind-profile-gate-", dir=scratch)
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def shell(self, body):
        script = f'''
set -euo pipefail
unset CLUSTER KIND_PROFILE
ROOT={shlex.quote(str(ROOT))}
RUN_DIR={shlex.quote(str(self.directory))}
source "$ROOT/scripts/ci/verify/kind/common.sh"
KIND_PROFILE=1
KIND_CLUSTER_NAME=synthetic-profile
CLUSTER=synthetic-profile
KIND_INGRESS_URL=http://127.0.0.1:60400
KIND_INGRESS_HOST_PORT=60400
KIND_INGRESS_HTTP_HOST_PORT=60400
KIND_INGRESS_TLS_URL=https://localhost:60401
KIND_INGRESS_TLS_HOST_PORT=60401
KIND_ORCHESTRATION_URL=http://127.0.0.1:60402
KIND_ORCHESTRATION_HTTP_URL=http://127.0.0.1:60402
KIND_COORDINATOR_DIRECT_URL=http://127.0.0.1:60403
KIND_COORDINATOR_DIRECT_HOST_PORT=60403
KIND_COORDINATOR_HOST_PORT=60403
KIND_TEMPORAL_ADDRESS=http://127.0.0.1:60404
KIND_TEMPORAL_FRONTEND_URL=http://127.0.0.1:60404
KIND_PROFILE_ARTIFACT_DIR="$RUN_DIR/artifacts"
kind_profile_verify_node() {{ :; }}
kind_profile_verify_artifacts() {{ :; }}
log() {{ :; }}
{body}
'''
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, env=os.environ.copy(), timeout=300)

    def test_remote_dind_forwarder_receives_all_saved_host_ports(self):
        fixture = self.directory / "capture-forwarder.py"
        arguments = self.directory / "forwarder-arguments.json"
        fixture.write_text(f'''import json, os, signal, sys
from pathlib import Path
Path({str(arguments)!r}).write_text(json.dumps({{"argv": sys.argv[1:], "pid": os.getpid()}}))
print("remote DinD Kind loopback forwarder ready", flush=True)
signal.pause()
''')
        result = self.shell(f'''
KIND_INGRESS_HTTP_HOST_PORT=60400
KIND_INGRESS_TLS_HOST_PORT=60401
KIND_TEMPORAL_HOST_PORT=60404
KIND_ORCHESTRATION_HOST_PORT=60402
KIND_COORDINATOR_HOST_PORT=60403
KIND_POSTGRES_HOST_PORT=60405
python3() {{ exec {shlex.quote(sys.executable)} -u {shlex.quote(str(fixture))} "$@"; }}
trap stop_remote_dind_kind_forwarding EXIT
start_remote_dind_kind_forwarding synthetic-profile-control-plane
stop_remote_dind_kind_forwarding
trap - EXIT
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        captured = json.loads(arguments.read_text())
        self.assertEqual(captured["argv"], [
            "-u", str(ROOT / "scripts/ci/verify/kind/forward-remote-dind-ports.py"),
            "--target", "synthetic-profile-control-plane",
            "--forward", "60400:80", "--forward", "60401:443",
            "--forward", "60404:30733", "--forward", "60402:30084",
            "--forward", "60403:30090", "--forward", "60405:30432",
        ])
        with self.assertRaises(ProcessLookupError):
            os.kill(captured["pid"], 0)

    def test_old_and_canonical_endpoint_selectors_have_one_assignment(self):
        pairs = (("KIND_INGRESS_HOST_PORT", "KIND_INGRESS_HTTP_HOST_PORT", "60400"),
                 ("KIND_COORDINATOR_DIRECT_HOST_PORT", "KIND_COORDINATOR_HOST_PORT", "60403"),
                 ("KIND_ORCHESTRATION_HTTP_URL", "KIND_ORCHESTRATION_URL", "http://127.0.0.1:60402"),
                 ("KIND_TEMPORAL_FRONTEND_URL", "KIND_TEMPORAL_ADDRESS", "http://127.0.0.1:60404"))
        for canonical, legacy, port in pairs:
            for selection in ({canonical: port}, {legacy: port},
                              {canonical: port, legacy: port},
                              {canonical: port, legacy: "60499" if port.isdigit() else "http://127.0.0.1:60499"}):
                with self.subTest(selection=selection):
                    environment = os.environ.copy()
                    for key in ("CLUSTER", "KIND_PROFILE", *(key for pair in pairs for key in pair[:2])):
                        environment.pop(key, None)
                    environment.update(selection)
                    script = f'''
set -euo pipefail
ROOT={shlex.quote(str(ROOT))}
RUN_DIR={shlex.quote(str(self.directory))}
source "$ROOT/scripts/ci/verify/kind/common.sh"
printf '%s:%s' "${{{canonical}}}" "${{{legacy}}}"
'''
                    result = subprocess.run(["bash", "-c", script], capture_output=True,
                                            text=True, env=environment, timeout=300)
                    conflict = len(selection) == 2 and len(set(selection.values())) == 2
                    self.assertEqual(result.returncode, 2 if conflict else 0, result.stderr)
                    self.assertEqual(result.stdout, "" if conflict else f"{port}:{port}")

    def test_archive_import_failure_stops_before_support_import(self):
        result = self.shell('''
kind() { echo "$*" >>"$RUN_DIR/calls"; return 32; }
wait_for_kind_api_after_image_load() { echo unexpected-wait >>"$RUN_DIR/calls"; }
if load_images_into_kind; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 32, result.stderr)
        self.assertEqual(len((self.directory / "calls").read_text().splitlines()), 1)

    def test_control_plane_failure_stops_before_support_import(self):
        result = self.shell('''
kind() { echo "$*" >>"$RUN_DIR/calls"; }
wait_for_kind_api_after_image_load() { return 38; }
if load_images_into_kind; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 38, result.stderr)
        self.assertEqual(len((self.directory / "calls").read_text().splitlines()), 1)

    def test_all_four_overlay_origins_use_saved_ingress(self):
        result = self.shell('''
kubectl() {
  cat <<'EOF'
FRONTEND_URL: http://127.0.0.1:8090
PUBLIC_OIDC_ISSUER_URL: http://127.0.0.1:8090
public: http://127.0.0.1:8090
browser: http://127.0.0.1:8090
image: postgres:17-alpine
image: postgres:17-alpine
image: temporalio/auto-setup:1.29.0
internal: http://codewire-orchestration:8084
EOF
}
render_kind_overlay_manifest
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        content = (self.directory / "codewire-kind-overlay.yaml").read_text()
        self.assertEqual(content.count("http://127.0.0.1:60400"), 4)
        self.assertNotIn("http://127.0.0.1:8090", content)
        self.assertIn("http://codewire-orchestration:8084", content)

    def test_origin_inventory_drift_fails_without_emitting_path(self):
        result = self.shell('''
kubectl() { echo 'FRONTEND_URL: http://127.0.0.1:8090'; }
if render_kind_overlay_manifest; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")

    def test_credential_renderer_propagates_failure(self):
        result = self.shell('''
python3() { return 42; }
if render_kind_credential_fixture_patch; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout, "")

    def test_credential_fixture_uses_saved_ingress(self):
        result = self.shell("render_kind_credential_fixture_patch")
        self.assertEqual(result.returncode, 0, result.stderr)
        content = (self.directory / "credential-fixture-patch.yaml").read_text()
        self.assertIn("value: http://127.0.0.1:60400", content)
        self.assertNotIn("http://127.0.0.1:8090", content)

    def test_existing_legacy_cluster_is_never_replaced(self):
        result = self.shell('''
KIND_PROFILE=0
kind() {
  [ "$*" = 'get clusters' ] || { echo mutation >"$RUN_DIR/mutation"; return 99; }
  echo synthetic-profile
}
if create_cluster; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.directory / "mutation").exists())

    def test_failed_precondition_cleanup_does_not_delete_uncreated_node(self):
        result = self.shell('''
KEEP_KIND_CLUSTER=0
KIND_CREATED_BY_TRANSACTION=0
delete_owned_kind_cluster() { echo deletion >"$RUN_DIR/deletion"; }
cleanup
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.directory / "deletion").exists())

    def test_shard_suite_traps_preserve_owner_forwarding_and_context_custody(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                (self.directory / "forwarding").unlink(missing_ok=True)
                result = self.shell(f'''
unset CLUSTER
source "$ROOT/scripts/ci/verify/kind-e2e.sh"
KIND_PROFILE=1
KIND_CREATED_BY_TRANSACTION=1
run_kind_up() {{
  KEEP_KIND_CLUSTER=1
  export KUBECONFIG="$RUN_DIR/owner-context"
  printf owner >"$KUBECONFIG"
  trap cleanup EXIT
}}
run_retained_final_fencing_suite() {{
  trap retained_suite_cleanup EXIT
  RETAINED_KUBECONFIG="$RUN_DIR/suite-context"
  export KUBECONFIG="$RETAINED_KUBECONFIG"
  printf suite >"$KUBECONFIG"
  bash -c 'test -z "${{KIND_SHARD_TRANSACTION+x}}"'
  {"return 42" if failure else ":"}
}}
run_retained_runtime_acceptance_suite() {{
  [ "$KUBECONFIG" = "$RUN_DIR/owner-context" ]
  [ ! -e "$RUN_DIR/suite-context" ]
  trap retained_suite_cleanup EXIT
  RETAINED_KUBECONFIG="$RUN_DIR/second-context"
  printf second >"$RETAINED_KUBECONFIG"
}}
dump_cluster_state() {{ :; }}
stop_remote_dind_kind_forwarding() {{ printf stopped >"$RUN_DIR/forwarding"; }}
delete_owned_kind_cluster() {{ printf deletion >"$RUN_DIR/deletion"; }}
dispatch_kind_e2e shard final-fencing runtime-acceptance
''')
                self.assertEqual(result.returncode, 42 if failure else 0, result.stderr)
                self.assertEqual((self.directory / "forwarding").read_text(), "stopped")
                self.assertTrue((self.directory / "owner-context").exists())
                self.assertFalse((self.directory / "suite-context").exists())
                self.assertFalse((self.directory / "second-context").exists())
                self.assertFalse((self.directory / "deletion").exists())

    def test_shard_cleanup_refuses_uncreated_and_replaced_nodes(self):
        for created, observed in ((0, "4" * 64), (1, "5" * 64)):
            with self.subTest(created=created):
                (self.directory / "forwarding").unlink(missing_ok=True)
                result = self.shell(f'''
KIND_PROFILE=0
KEEP_KIND_CLUSTER=0
KIND_SHARD_TRANSACTION=1
KIND_CREATED_BY_TRANSACTION={created}
KIND_TRANSACTION_NODE_ID={"4" * 64}
RETAINED_KUBECONFIG="$RUN_DIR/suite-context"
printf suite >"$RETAINED_KUBECONFIG"
dump_cluster_state() {{ :; }}
stop_remote_dind_kind_forwarding() {{ printf stopped >"$RUN_DIR/forwarding"; }}
docker() {{ printf '%s\\n' {observed}; }}
kind() {{ printf deletion >"$RUN_DIR/deletion"; }}
trap retained_suite_cleanup EXIT
exit 42
''')
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertFalse((self.directory / "suite-context").exists())
                self.assertFalse((self.directory / "deletion").exists())
                self.assertEqual((self.directory / "forwarding").read_text(), "stopped")

    def test_shard_context_removal_failure_still_stops_owner_forwarding(self):
        result = self.shell('''
KEEP_KIND_CLUSTER=1
KIND_SHARD_TRANSACTION=1
RETAINED_KUBECONFIG="$RUN_DIR/suite-context"
printf suite >"$RETAINED_KUBECONFIG"
rm() { return 51; }
dump_cluster_state() { :; }
stop_remote_dind_kind_forwarding() { printf stopped >"$RUN_DIR/forwarding"; }
trap retained_suite_cleanup EXIT
exit 42
''')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual((self.directory / "forwarding").read_text(), "stopped")
        self.assertTrue((self.directory / "suite-context").exists())

    def test_docker_failure_cannot_start_a_create_transaction(self):
        result = self.shell('''
KIND_PROFILE=0
require_kind_host_ports_available() { :; }
kind() {
  [ "$*" = 'get clusters' ] || { echo mutation >"$RUN_DIR/mutation"; return 99; }
}
docker() { return 37; }
if create_cluster; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertFalse((self.directory / "mutation").exists())

    def test_second_port_check_failure_stops_before_cluster_creation(self):
        result = self.shell('''
KIND_PROFILE=0
KIND_CLUSTER_NAME_EXPLICIT=1
source "$ROOT/scripts/ci/verify/kind/suites/up.sh"
observations=0
require_tool() { :; }
prepare_kind_temp_runtime() { :; }
acquire_kind_host_lock() { :; }
kind() {
  [ "$*" = 'get clusters' ] || { echo mutation >"$RUN_DIR/mutation"; return 99; }
}
require_kind_host_ports_available() {
  observations=$((observations + 1))
  [ "$observations" = 1 ] || return 47
}
ingress_path_drift_check() { :; }
build_images_and_smokes() { :; }
docker() { echo mutation >"$RUN_DIR/mutation"; return 99; }
cleanup() {
  printf '%s:%s\\n' "$observations" "$KIND_CREATED_BY_TRANSACTION" >"$RUN_DIR/final-state"
}
set +e
(
  set -e
  run_kind_up
  exit 90
)
status=$?
set -e
[ "$(cat "$RUN_DIR/final-state")" = 2:0 ] || exit 91
exit "$status"
''')
        self.assertEqual(result.returncode, 47, result.stderr)
        self.assertFalse((self.directory / "mutation").exists())

    def test_failed_create_never_adopts_a_node_now_visible_by_name(self):
        result = self.shell('''
KIND_PROFILE=0
require_kind_host_ports_available() { :; }
kind() {
  case "$*" in
    'get clusters') return 0 ;;
    'create cluster '*) return 39 ;;
    *) return 99 ;;
  esac
}
docker() {
  if [ "$1" = container ]; then
    echo unexpected-adoption >"$RUN_DIR/adoption"
    printf '%064d\\n' 1
  fi
}
if create_cluster; then exit 90; else status=$?; fi
[ "$KIND_CREATED_BY_TRANSACTION" = 0 ] || exit 91
exit "$status"
''')
        self.assertEqual(result.returncode, 39, result.stderr)
        self.assertFalse((self.directory / "adoption").exists())

    def test_fixture_isolation_preserves_parent_profile_and_lock(self):
        source = (ROOT / "scripts/ci/verify/run-product-verification.sh").read_text()
        helper = source.split("isolate_kind_fixture_environment() {", 1)[1]
        helper = "isolate_kind_fixture_environment() {" + helper.split("\nrun_policy_core()", 1)[0]
        script = 'set -euo pipefail\n' + helper + '''
CLUSTER=synthetic-profile
KIND_PROFILE=1
KEEP_KIND_CLUSTER=1
KUBECONFIG=synthetic-private-context
CARGO_CI_DIR=synthetic-private-smokes
exec 7>operation.lock
flock 7
KIND_PROFILE_LOCK_FD=7
(
  isolate_kind_fixture_environment
  [ -z "${CLUSTER+x}${KIND_PROFILE+x}${KIND_PROFILE_LOCK_FD+x}${KEEP_KIND_CLUSTER+x}${KUBECONFIG+x}${CARGO_CI_DIR+x}" ]
)
[ "$CLUSTER" = synthetic-profile ]
[ "$KEEP_KIND_CLUSTER" = 1 ]
[ "$KUBECONFIG" = synthetic-private-context ]
[ "$KIND_PROFILE_LOCK_FD" = 7 ]
if flock -n operation.lock true; then exit 90; fi
'''
        result = subprocess.run(["bash", "-c", script], cwd=self.directory,
                                env=os.environ.copy(), capture_output=True,
                                text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nested_publication_reuses_and_preserves_inherited_lock(self):
        result = self.shell('''
KIND_HOST_LOCK_TIMEOUT_SECONDS=1
KIND_BUILD_PUBLICATION_LOCK_FILE="$RUN_DIR/publication.lock"
install -m 0600 /dev/null "$KIND_BUILD_PUBLICATION_LOCK_FILE"
exec 7<>"$KIND_BUILD_PUBLICATION_LOCK_FILE"
flock 7
KIND_BUILD_PUBLICATION_LOCK_FD=7
acquire_kind_build_publication_lock
release_kind_build_publication_lock
[ "$KIND_BUILD_PUBLICATION_LOCK_FD" = 7 ]
if flock -n "$KIND_BUILD_PUBLICATION_LOCK_FILE" true; then exit 90; fi
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_publication_refuses_an_inherited_descriptor_for_another_inode(self):
        result = self.shell('''
KIND_BUILD_PUBLICATION_LOCK_FILE="$RUN_DIR/publication.lock"
install -m 0600 /dev/null "$KIND_BUILD_PUBLICATION_LOCK_FILE"
install -m 0600 /dev/null "$RUN_DIR/other.lock"
exec 7<>"$RUN_DIR/other.lock"
KIND_BUILD_PUBLICATION_LOCK_FD=7
if acquire_kind_build_publication_lock; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_publication_refuses_multiply_linked_lock_before_building(self):
        result = self.shell('''
KIND_BUILD_PUBLICATION_LOCK_FILE="$RUN_DIR/publication.lock"
install -m 0600 /dev/null "$KIND_BUILD_PUBLICATION_LOCK_FILE"
ln "$KIND_BUILD_PUBLICATION_LOCK_FILE" "$RUN_DIR/alias.lock"
if acquire_kind_build_publication_lock; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_missing_first_runtime_dependency_cannot_be_overwritten(self):
        result = self.shell('''
KIND_CLUSTER_NAME_EXPLICIT=1
kind_profile_lock() { :; }
use_kind_profile_smokes() { :; }
kind() { echo synthetic-profile; }
kubectl() {
  case "$*" in
    'config current-context') echo kind-synthetic-profile ;;
  esac
}
require_available_deployment() {
  echo "$2" >>"$RUN_DIR/dependencies"
  [ "$2" != postgres ] || return 45
}
if validate_retained_cluster_identity; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 45, result.stderr)
        self.assertEqual((self.directory / "dependencies").read_text(), "postgres\n")

    def test_missing_idp_deployment_stops_before_later_healthy_reads(self):
        result = self.shell('''
kubectl() {
  case "$*" in
    *'get configmap codewire-config'*) echo "$KIND_INGRESS_URL" ;;
    *'get deployment/codewire-idp'*) return 46 ;;
    *) echo unexpected-later-read >"$RUN_DIR/later" ;;
  esac
}
if assert_kind_idp_topology; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 46, result.stderr)
        self.assertFalse((self.directory / "later").exists())

    def test_cert_manager_first_rollout_failure_cannot_be_overwritten(self):
        result = self.shell('''
kubectl_apply() { cat >/dev/null; }
kubectl() {
  case "$*" in
    'config current-context') echo kind-synthetic-profile ;;
    *'rollout status'*)
      echo "$*" >>"$RUN_DIR/rollouts"
      case "$*" in
        *'deployment/cert-manager --timeout='*) return 47 ;;
      esac
      ;;
  esac
}
if deploy_kind_credential_cert_manager; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 47, result.stderr)
        self.assertEqual(len((self.directory / "rollouts").read_text().splitlines()), 1)

    def test_sandbox_apply_failure_cannot_mark_runtime_ready(self):
        result = self.shell('''
render_agent_sandbox_manifest() { echo synthetic-manifest; }
kubectl_apply() { return 48; }
kubectl() { echo unexpected-later-step >"$RUN_DIR/later"; }
if deploy_agent_sandbox; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 48, result.stderr)
        self.assertFalse((self.directory / "later").exists())

    def credential_diagnostics(self, deployment_command=None, marker=None,
                               pod_command=None, failing_reader=None, failure=None):
        fixture_command = ["/codewire-kind-fixtures/credential-service"]
        scenario = {
            "deployment_command": fixture_command if deployment_command is None else deployment_command,
            "marker": ["1"] if marker is None else marker,
            "pod_command": fixture_command if pod_command is None else pod_command,
            "failing_reader": failing_reader,
        }
        (self.directory / "diagnostic-scenario.json").write_text(json.dumps(scenario))
        calls = self.directory / "diagnostic-calls.jsonl"
        calls.write_text("")
        fixture = self.directory / "diagnostic-kubectl.py"
        fixture.write_text('''import json, sys
from pathlib import Path
root = Path(__file__).parent
scenario = json.loads((root / "diagnostic-scenario.json").read_text())
args = sys.argv[1:]
with (root / "diagnostic-calls.jsonl").open("a") as stream:
    stream.write(json.dumps(args) + "\\n")
stage = None
if "get" in args and "deployment/codewire-credential-service" in args:
    stage = "deployment"
elif "get" in args and "pods" in args and "-l" in args:
    stage = "pod-names"
elif "get" in args and "pod/credential-synthetic-abc" in args:
    stage = "pod-identity" if any(".spec.containers" in arg for arg in args) else "status"
elif "logs" in args and "pod/credential-synthetic-abc" in args:
    stage = "previous" if "--previous" in args else "current"
if stage == scenario["failing_reader"] and stage is not None:
    print("private reader error must not be dumped", file=sys.stderr)
    sys.exit(61)
if stage in ("deployment", "pod-identity"):
    command = scenario["deployment_command" if stage == "deployment" else "pod_command"]
    print(json.dumps([command]))
    print(json.dumps(scenario["marker"]))
elif stage == "pod-names":
    print(json.dumps(["credential-synthetic-abc"]))
elif stage == "status":
    print("current reason=Error exit_code=23\\nprevious reason=OOMKilled exit_code=137")
elif stage in ("current", "previous"):
    print(stage + " synthetic credential log")
''')
        finish = "dump_cluster_state" if failure is None else f"trap cleanup EXIT\nexit {failure}"
        result = self.shell(f'''
NS=synthetic-namespace
SANDBOX_NS=synthetic-sandbox
KEEP_KIND_CLUSTER=1
AUTHZ_TMPDIR=
kind() {{ printf '%s\\n' synthetic-profile; }}
kubectl() {{ {shlex.quote(sys.executable)} {shlex.quote(str(fixture))} "$@"; }}
stop_remote_dind_kind_forwarding() {{ :; }}
{finish}
''')
        captured = [json.loads(line) for line in calls.read_text().splitlines()]
        credential_calls = [args for args in captured if
                            "deployment/codewire-credential-service" in args or
                            "pod/credential-synthetic-abc" in args or
                            ("get" in args and "pods" in args and "-l" in args)]
        return result, credential_calls

    def test_synthetic_credential_failure_diagnostics_are_scoped_and_bounded(self):
        result, calls = self.credential_diagnostics()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("current reason=Error exit_code=23", result.stdout)
        self.assertIn("previous reason=OOMKilled exit_code=137", result.stdout)
        self.assertIn("current synthetic credential log", result.stdout)
        self.assertIn("previous synthetic credential log", result.stdout)
        self.assertEqual(len(calls), 6)
        for args in calls:
            self.assertEqual(args[:4], ["--context", "kind-synthetic-profile", "-n", "synthetic-namespace"])
            self.assertIn("--request-timeout=5s", args)
            self.assertNotIn("json", args, "do not read or dump a complete deployment/pod")
        identity_reads = [args for args in calls if any(".command}" in arg for arg in args)]
        self.assertEqual(len(identity_reads), 2)
        for args in identity_reads:
            self.assertIn("CODEWIRE_KIND_CREDENTIAL_FIXTURE", args[-1])
            self.assertIn('].value}', args[-1])
        status = [args for args in calls if any("containerStatuses" in arg for arg in args)]
        self.assertEqual(len(status), 1)
        self.assertIn("lastState.terminated.reason", status[0][-1])
        self.assertIn("lastState.terminated.exitCode", status[0][-1])
        logs = [args for args in calls if "logs" in args]
        self.assertEqual(len(logs), 2)
        for args in logs:
            self.assertIn("--tail=80", args)
            self.assertIn("--limit-bytes=16384", args)
            self.assertEqual(args[args.index("-c") + 1], "credential-service")
        self.assertEqual(sum("--previous" in args for args in logs), 1)

    def test_real_or_unknown_credential_deployment_is_not_logged(self):
        for command, marker in [
            (["/codewire-credential-service"], ["1"]),
            (["/codewire-kind-fixtures/credential-service", "extra"], ["1"]),
            ([], ["1"]),
            (["/codewire-kind-fixtures/credential-service"], []),
            (["/codewire-kind-fixtures/credential-service"], ["0"]),
            (["/codewire-kind-fixtures/credential-service"], ["1", "1"]),
        ]:
            with self.subTest(command=command, marker=marker):
                result, calls = self.credential_diagnostics(command, marker)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 1)
                self.assertNotIn("synthetic credential log", result.stdout)
                self.assertNotIn("exit_code=", result.stdout)

    def test_old_real_pod_is_not_logged_under_a_fixture_deployment(self):
        result, calls = self.credential_diagnostics(pod_command=["/codewire-credential-service"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertNotIn("synthetic credential log", result.stdout)
        self.assertNotIn("exit_code=", result.stdout)

    def test_credential_diagnostic_read_failure_preserves_original_failure(self):
        for stage in ["deployment", "pod-names", "pod-identity", "status", "current", "previous"]:
            with self.subTest(stage=stage):
                result, _ = self.credential_diagnostics(failing_reader=stage, failure=57)
                self.assertEqual(result.returncode, 57, result.stderr)
                self.assertNotIn("private reader error", result.stderr)

    def test_reuse_resolves_workspace_before_runtime_or_support_mutations(self):
        result = self.shell('''
CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci
ROOT="$RUN_DIR/synthetic-checkout"
mkdir -p "$ROOT/scripts/ci/verify"
printf 'raise SystemExit(3)\\n' >"$ROOT/scripts/ci/verify/kind-build-artifacts.py"
printf '#!/usr/bin/env bash\\nexit 0\\n' >"$ROOT/scripts/ci/verify/rehearse-build-local-image.sh"
printf '#!/usr/bin/env bash\\nexit 49\\n' >"$ROOT/scripts/ci/verify/verify-workspace-image.sh"
chmod 0700 "$ROOT/scripts/ci/verify/rehearse-build-local-image.sh" "$ROOT/scripts/ci/verify/verify-workspace-image.sh"
acquire_kind_build_publication_lock() { :; }
prepare_kind_support_images() { echo unexpected-support-mutation >"$RUN_DIR/support"; }
if prepare_kind_profile_runtime_inputs; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 49, result.stderr)
        self.assertFalse((self.directory / "support").exists())

    def prepared_marker(self, nonce, node):
        return self.shell(f'''
KIND_PROFILE_NONCE={"3" * 32}
KIND_PROFILE_SOURCE_HEAD={"1" * 40}
KIND_PROFILE_SOURCE_TREE={"2" * 40}
KIND_PROFILE_IMAGE_MANIFEST="$RUN_DIR/manifest.json"
printf '{{}}\\n' >"$KIND_PROFILE_IMAGE_MANIFEST"
manifest="$(sha256sum "$KIND_PROFILE_IMAGE_MANIFEST" | cut -d' ' -f1)"
validate_retained_cluster_identity() {{ :; }}
kind_workspace_runtime_image() {{ echo workspace:source; }}
docker() {{ echo {"4" * 64}; }}
kubectl() {{
  case "$*" in
    *'exec deploy/postgres -- psql '*UPDATE*at_kind_connect_oidc_codewire_api*) echo 1 ;;
    *'exec deploy/postgres -- psql '*'UPDATE sessions'*ses_contract_user*) printf '1\\n1\\n' ;;
    *'jsonpath='*compatibility_version*) echo 1 ;;
    *'jsonpath='*cluster-name*) echo synthetic-profile ;;
    *'jsonpath='*workspace-image*) echo workspace:source ;;
    *'configmap/codewire-kind-e2e-prepared-synthetic-profile -o json')
      jq -cn --arg nonce '{nonce}' --arg node '{node}' --arg sha "$manifest" \\
        --arg head "$KIND_PROFILE_SOURCE_HEAD" --arg tree "$KIND_PROFILE_SOURCE_TREE" \\
        '{{data: {{"profile-nonce": $nonce, "node-id": $node, "artifact-sha256": $sha,
                  "source-head": $head, "source-tree": $tree}}}}' ;;
    *) return 99 ;;
  esac
}}
validate_retained_cluster
''')

    def test_matching_prepared_marker_is_accepted(self):
        result = self.prepared_marker("3" * 32, "4" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cross_profile_prepared_marker_is_rejected(self):
        result = self.prepared_marker("5" * 32, "4" * 64)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_replacement_node_prepared_marker_is_rejected(self):
        result = self.prepared_marker("3" * 32, "6" * 64)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_named_make_does_not_inject_legacy_origins(self):
        result = subprocess.run(["make", "-n", "kind-watch", "CLUSTER=synthetic-profile"],
                                cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("localhost:4174", result.stdout)
        self.assertNotIn("localhost:8090", result.stdout)

    def test_legacy_make_target_rejects_named_selection_before_effects(self):
        result = subprocess.run(["make", "-n", "up", "CLUSTER=synthetic-profile"],
                                cwd=ROOT, capture_output=True, text=True, timeout=300)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("docker build", result.stdout)


if __name__ == "__main__":
    unittest.main()
