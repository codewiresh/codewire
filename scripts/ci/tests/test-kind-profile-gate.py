#!/usr/bin/env python3
"""Named gate regressions with synthetic endpoints and command boundaries."""
import os
from pathlib import Path
import shlex
import subprocess
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
KIND_INGRESS_TLS_URL=https://localhost:60401
KIND_INGRESS_TLS_HOST_PORT=60401
KIND_ORCHESTRATION_URL=http://127.0.0.1:60402
KIND_COORDINATOR_DIRECT_URL=http://127.0.0.1:60403
KIND_TEMPORAL_ADDRESS=http://127.0.0.1:60404
KIND_PROFILE_ARTIFACT_DIR="$RUN_DIR/artifacts"
kind_profile_verify_node() {{ :; }}
kind_profile_verify_artifacts() {{ :; }}
log() {{ :; }}
{body}
'''
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env=os.environ.copy(), timeout=15)

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

    def test_docker_failure_cannot_start_a_create_transaction(self):
        result = self.shell('''
KIND_PROFILE=0
kind() {
  [ "$*" = 'get clusters' ] || { echo mutation >"$RUN_DIR/mutation"; return 99; }
}
docker() { return 37; }
if create_cluster; then exit 90; else exit "$?"; fi
''')
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertFalse((self.directory / "mutation").exists())

    def test_failed_create_never_adopts_a_node_now_visible_by_name(self):
        result = self.shell('''
KIND_PROFILE=0
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
KUBECONFIG=synthetic-private-context
CARGO_CI_DIR=synthetic-private-smokes
exec 7>operation.lock
flock 7
KIND_PROFILE_LOCK_FD=7
(
  isolate_kind_fixture_environment
  [ -z "${CLUSTER+x}${KIND_PROFILE+x}${KIND_PROFILE_LOCK_FD+x}${KUBECONFIG+x}${CARGO_CI_DIR+x}" ]
)
[ "$CLUSTER" = synthetic-profile ]
[ "$KUBECONFIG" = synthetic-private-context ]
[ "$KIND_PROFILE_LOCK_FD" = 7 ]
if flock -n operation.lock true; then exit 90; fi
'''
        result = subprocess.run(["bash", "-c", script], cwd=self.directory,
                                env=os.environ.copy(), capture_output=True,
                                text=True, timeout=15)
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

    def test_reuse_resolves_workspace_before_runtime_or_support_mutations(self):
        result = self.shell('''
CODEWIRE_KIND_PRODUCT_IMAGE_MODE=build-ci
ROOT="$RUN_DIR/synthetic-checkout"
mkdir -p "$ROOT/scripts/ci/verify"
printf '#!/usr/bin/env bash\\nexit 49\\n' >"$ROOT/scripts/ci/verify/verify-workspace-image.sh"
chmod 0700 "$ROOT/scripts/ci/verify/verify-workspace-image.sh"
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
    *'jsonpath='*compatibility_version*) echo 1 ;;
    *'jsonpath='*cluster-name*) echo synthetic-profile ;;
    *'jsonpath='*workspace-image*) echo workspace:source ;;
    *'-o json')
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
                                cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("nj.example.invalid", result.stdout)

    def test_legacy_make_target_rejects_named_selection_before_effects(self):
        result = subprocess.run(["make", "-n", "up", "CLUSTER=synthetic-profile"],
                                cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("docker build", result.stdout)


if __name__ == "__main__":
    unittest.main()
