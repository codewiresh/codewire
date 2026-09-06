#!/usr/bin/env python3
"""Hermetic credential acceptance guards; no cluster, account or provider I/O."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[3]
HELPERS = ROOT / "scripts/ci/verify/kind/credentials.sh"
SPEC = importlib.util.spec_from_file_location(
    "credential_probe", ROOT / "scripts/ci/verify/kind/credential_probe.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
ENVIRONMENT = "86fb3daa-dde0-4fb4-bf83-6e2399d78a5f"
CREDENTIAL_IMAGES = (
    ("controller", "8615625f29f821542fca5351e3791a21121bf869aa63c72607e0a51e4c233a4a"),
    ("webhook", "f7ad7d3c6dbe73ead365c2324dbe6575b4fc618ed06f0863f250c5eafb35a246"),
    ("cainjector", "da14ecb33386bd53c86d22a7a996e9783da5a09aa4ce9c55e161128fc2632985"),
)


class WorkspaceProbe(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="kind-credential-probe-")
        self.addCleanup(self.scratch.cleanup)
        self.home = Path(self.scratch.name)
        self.token = self.home / "capability"
        self.token.write_text("synthetic-pod-capability", encoding="ascii")
        self.context = Mock()
        self.connection = Mock()
        self.connection.getresponse.return_value.status = 200
        self.connection.getresponse.return_value.read.return_value = b"CWCODEX149 kind"
        self.output = io.StringIO()
        for fixture in (
            patch.object(PROBE, "CODEX_HOME", self.home),
            patch.object(PROBE, "TOKEN", self.token),
            patch.dict(os.environ, {"CODEX_HOME": str(self.home),
                                   "CODEX_CA_CERTIFICATE": PROBE.ROOTS}, clear=True),
            patch.object(PROBE.ssl, "SSLContext", return_value=self.context),
            patch.object(PROBE.http.client, "HTTPSConnection", return_value=self.connection),
            contextlib.redirect_stdout(self.output),
        ):
            fixture.__enter__()
            self.addCleanup(fixture.__exit__, None, None, None)

    def test_success_uses_only_exact_gateway_roots_and_pod_capability(self):
        PROBE.probe(ENVIRONMENT, "success")
        self.context.load_verify_locations.assert_called_once_with(cafile=PROBE.ROOTS)
        PROBE.http.client.HTTPSConnection.assert_called_once_with(
            f"cw-gateway-svc-{ENVIRONMENT}.dev-sandboxes.svc.cluster.local",
            context=self.context, timeout=20)
        request = self.connection.request.call_args
        self.assertEqual(request.args, ("POST", "/v1/responses"))
        self.assertEqual(request.kwargs["headers"]["Authorization"], "Bearer synthetic-pod-capability")
        self.assertNotIn("synthetic-pod-capability", self.output.getvalue())
        self.connection.close.assert_called_once()

    def test_all_denials_require_their_exact_status(self):
        for mode, status in (("unbound", 403), ("revoked", 403), ("missing", 401)):
            with self.subTest(mode=mode):
                self.connection.getresponse.return_value.status = status
                PROBE.probe(ENVIRONMENT, mode)
                self.connection.getresponse.return_value.status = 200
                with self.assertRaises(ValueError):
                    PROBE.probe(ENVIRONMENT, mode)

    def test_missing_identity_does_not_read_capability(self):
        self.token.unlink()
        self.connection.getresponse.return_value.status = 401
        PROBE.probe(ENVIRONMENT, "missing")
        self.assertNotIn("Authorization", self.connection.request.call_args.kwargs["headers"])

    def test_wrong_root_requires_certificate_rejection_not_network_error(self):
        self.token.unlink()
        self.connection.request.side_effect = ssl.SSLCertVerificationError("synthetic")
        PROBE.probe(ENVIRONMENT, "wrong-root")
        self.context.load_verify_locations.assert_not_called()
        self.assertEqual(json.loads(self.output.getvalue()), {"event": "wrong_root_denied"})
        self.connection.request.side_effect = TimeoutError("synthetic")
        with self.assertRaises(TimeoutError):
            PROBE.probe(ENVIRONMENT, "wrong-root")

    def test_untrusted_root_success_cannot_pass(self):
        with self.assertRaises(ValueError):
            PROBE.probe(ENVIRONMENT, "wrong-root")

    def test_trusted_mode_certificate_failure_cannot_pass(self):
        self.connection.request.side_effect = ssl.SSLCertVerificationError("synthetic")
        with self.assertRaises(ssl.SSLCertVerificationError):
            PROBE.probe(ENVIRONMENT, "success")

    def test_provider_material_and_oversize_response_are_rejected(self):
        for payload in (b"CW_KIND_SYNTHETIC_REFRESH_private", b"synthetic-kind-signature",
                        b"x" * (64 * 1024 + 1), b"missing-marker"):
            with self.subTest(size=len(payload)):
                self.connection.getresponse.return_value.read.return_value = payload
                with self.assertRaises(ValueError):
                    PROBE.probe(ENVIRONMENT, "success")
        self.assertEqual(self.output.getvalue(), "")

    def test_invalid_capability_never_reaches_network(self):
        for value in ("", "a b", "a\nb", "x" * (16 * 1024 + 1)):
            self.token.write_text(value, encoding="ascii")
            with self.assertRaises(ValueError):
                PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.assert_not_called()

    def test_provider_auth_file_or_environment_fail_before_network(self):
        (self.home / "auth.json").write_text("synthetic", encoding="ascii")
        with self.assertRaises(ValueError):
            PROBE.probe(ENVIRONMENT, "success")
        (self.home / "auth.json").unlink()
        os.environ["SYNTHETIC_FIXTURE"] = "CW_KIND_SYNTHETIC_REFRESH_private"
        with self.assertRaises(ValueError):
            PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.assert_not_called()

    def test_projection_and_target_are_not_caller_overridable(self):
        for environment, mode in (("not-a-uuid", "success"), (ENVIRONMENT.upper(), "success"),
                                  (ENVIRONMENT, "unknown")):
            with self.assertRaises(ValueError):
                PROBE.probe(environment, mode)
        os.environ["CODEX_CA_CERTIFICATE"] = "/synthetic/other-roots"
        with self.assertRaises(ValueError):
            PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.assert_not_called()


class HarnessGuards(unittest.TestCase):
    def test_bootstrap_cleanup_removes_issuer_before_outputs_and_propagates_failures(self):
        for certificate_status, leaf_status in ((0, 0), (42, 0), (0, 43)):
            result = self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() {
  printf '%%s\\n' "$*" >&2
  case "$*" in
    '-n dev-sandboxes delete certificate/cw-credential-gateway-%s --ignore-not-found=true --cascade=background --wait=true --timeout=120s') return %s ;;
    '-n dev-sandboxes delete secret/cw-credential-gateway-%s configmap/cw-credential-codex-%s --ignore-not-found=true --wait=true --timeout=120s') return %s ;;
    *) return 99 ;;
  esac
}
delete_kind_credential_bootstrap '%s'
''' % (ENVIRONMENT, certificate_status, ENVIRONMENT, ENVIRONMENT, leaf_status, ENVIRONMENT))
            self.assertEqual(result.returncode, certificate_status or leaf_status, result.stderr)
            calls = result.stderr.splitlines()
            self.assertEqual(len(calls), 1 if certificate_status else 2, result.stderr)
            self.assertIn("delete certificate/", calls[0])
            if not certificate_status:
                self.assertIn("delete secret/", calls[1])
        common = (ROOT / "scripts/ci/verify/kind/common.sh").read_text()
        cleanup = common.split("cleanup_environment_resize_smoke() {", 1)[1].split(
            "trap cleanup_environment_resize_smoke EXIT", 1)[0]
        self.assertNotIn('"certificate/cw-credential-gateway-$environment_id"', cleanup)
        self.assertLess(cleanup.index("--cascade=foreground --wait=true"),
                        cleanup.index('delete_kind_credential_bootstrap "$environment_id"'))
        self.assertIn('exit "$status"', cleanup)

    def test_bootstrap_cleanup_rejects_noncanonical_environment_without_io(self):
        for environment in ("", "foreign", ENVIRONMENT.upper()):
            result = self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() { echo unexpected-kubectl >&2; return 99; }
delete_kind_credential_bootstrap '%s'
''' % environment)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(result.stderr, "")

    def test_native_flow_resolves_the_selected_runtime_image_not_a_contract_only_preset(self):
        source = HELPERS.read_text()
        self.assertIn('workspace_image="$(kind_workspace_runtime_image)" || return $?', source)
        self.assertIn('--image "$workspace_image"', source)
        self.assertNotIn('--preset-id preset_contract_1', source)

    def test_missing_image_receipt_fails_before_public_enrollment(self):
        result = self.shell('''
log() { :; }
kind_workspace_runtime_image() { return 42; }
prepare_kind_credential_cli() { echo unexpected-login; return 98; }
kind_credential_cli() { echo unexpected-enrollment; return 99; }
kind_credential_native_smoke
''')
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_terminal_wait_requires_exact_destroyed_state_not_missing_cli_target(self):
        for state, expected in (("destroyed", 0), ("destroying", 1), ("", 1), ("error", 1)):
            result = self.shell('''
NS=codewire-e2e
kind_credential_cli() { echo unexpected-cli-target-resolution >&2; return 98; }
sleep() { :; }
kubectl() {
  [ "$*" = '-n codewire-e2e exec -i deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -v environment=%s -At' ] || return 99
  local query
  query="$(</dev/stdin)"
  [[ "$query" == *"WHERE id = :'environment' AND org_id = 'org_contract_1'"* ]] || return 99
  printf '%%s\\n' '%s'
}
wait_kind_credential_environment '%s' destroyed
''' % (ENVIRONMENT, state, ENVIRONMENT))
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertNotIn("unexpected-cli", result.stderr)

    def test_host_cli_build_selects_its_actual_binary_package(self):
        manifest = tomllib.loads((ROOT / "crates/codewire-cli-bin/Cargo.toml").read_text())
        self.assertIn("cw", [binary["name"] for binary in manifest["bin"]])
        expected = f'cargo build --locked --profile ci -p {manifest["package"]["name"]} --bin cw'
        source = (ROOT / "scripts/ci/verify/kind/common.sh").read_text()
        self.assertEqual(source.count(expected), 1)
        self.assertNotIn("-p codewire-cli --bin cw", source)

    def shell(self, body):
        result = subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\n'
             'validate_sealed_kind_images() { return 1; }\n' + body,
             "kind-credential-fixture", str(HELPERS)],
            env={"PATH": "/usr/bin:/bin", "ROOT": str(ROOT)},
            capture_output=True, text=True, timeout=10,
        )
        return result

    def test_release_mode_never_installs_synthetic_authority(self):
        result = self.shell('''
log() { :; }
docker() { echo unexpected-docker; return 97; }
kubectl() { echo unexpected-kubectl; return 98; }
CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release
start_kind_credential_fixture
kind_credential_native_smoke
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_repeated_source_preserves_exact_support_image_inventory(self):
        result = self.shell('''
expected="$(kind_credential_support_images)"
source "$1"
[ "$(kind_credential_support_images)" = "$expected" ]
''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_support_image_mapping_preserves_exact_digests_and_aliases(self):
        for status, registry in ((1, "quay.io/jetstack"),
                                 (0, "nexus.example.invalid/oci-approved/jetstack")):
            with self.subTest(status=status):
                result = self.shell('''
validate_sealed_kind_images() { return %s; }
kind_credential_support_images
''' % status)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [
                    f"{registry}/cert-manager-{name}@sha256:{digest}|"
                    f"localhost/codewire-ci/cert-manager-{name}:verified-{digest}"
                    for name, digest in CREDENTIAL_IMAGES
                ])

    def test_sealed_prepare_and_load_use_only_preloaded_nexus_references(self):
        result = self.shell('''
exec 3>&1
validate_sealed_kind_images() { return 0; }
KIND_CLUSTER_NAME=synthetic-credential-fixture
log() { :; }
docker() {
  case "$1 $2" in
    'image inspect'|'image tag')
      [[ "$3" == nexus.example.invalid/oci-approved/jetstack/cert-manager-*@sha256:* ]] || return 98
      printf 'docker:%s\\n' "$*" >&3 ;;
    *) echo unexpected-network; return 99 ;;
  esac
}
kind() { printf 'kind:%s\\n' "$*"; }
wait_for_kind_api_after_image_load() { echo wait-api; }
prepare_kind_credential_support_images
load_kind_credential_support_images
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = []
        for name, digest in CREDENTIAL_IMAGES:
            source = f"nexus.example.invalid/oci-approved/jetstack/cert-manager-{name}@sha256:{digest}"
            alias = f"localhost/codewire-ci/cert-manager-{name}:verified-{digest}"
            expected += [f"docker:image inspect {source}", f"docker:image tag {source} {alias}"]
        for name, digest in CREDENTIAL_IMAGES:
            source = f"nexus.example.invalid/oci-approved/jetstack/cert-manager-{name}@sha256:{digest}"
            alias = f"localhost/codewire-ci/cert-manager-{name}:verified-{digest}"
            expected += [f"docker:image inspect {source}",
                         f"kind:load docker-image --name synthetic-credential-fixture {alias}",
                         "wait-api"]
        self.assertEqual(result.stdout.splitlines(), expected)

    def test_invalid_image_tuple_fails_even_when_every_image_is_cached(self):
        for operation in ("kind_credential_support_images", "prepare_kind_credential_support_images",
                          "load_kind_credential_support_images"):
            with self.subTest(operation=operation):
                result = self.shell('''
validate_sealed_kind_images() { return 2; }
docker() { echo unexpected-docker; return 0; }
kind() { echo unexpected-kind; return 0; }
log() { :; }
wait_for_kind_api_after_image_load() { echo unexpected-wait; }
KIND_CLUSTER_NAME=synthetic-credential-fixture
status=0
%s || status=$?
exit "$status"
''' % operation)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_failed_image_inventory_never_performs_partial_prepare_or_load(self):
        for operation in ("prepare_kind_credential_support_images", "load_kind_credential_support_images"):
            for partial in (False, True):
                with self.subTest(operation=operation, partial=partial):
                    result = self.shell('''
kind_credential_support_images() {
  %s
  return 37
}
docker() { echo unexpected-docker; return 0; }
kind() { echo unexpected-kind; return 0; }
log() { :; }
wait_for_kind_api_after_image_load() { echo unexpected-wait; }
KIND_CLUSTER_NAME=synthetic-credential-fixture
status=0
%s || status=$?
exit "$status"
''' % ("printf '%s\\n' 'synthetic-source|synthetic-alias'" if partial else ":", operation))
                    self.assertEqual(result.returncode, 37, result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_certificate_manifest_drift_fails_before_cluster_access(self):
        result = self.shell('''
sha256sum() { printf '%064d  synthetic-manifest\\n' 0; }
kubectl() { echo unexpected-kubectl; return 98; }
deploy_kind_credential_cert_manager
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("differs from its reviewed render", result.stderr)
        self.assertNotIn("unexpected-kubectl", result.stdout)

    def test_wrong_image_profile_and_promotability_fail_before_provisioning(self):
        for profile, promotable in (("release", "false"), ("ci", "true"), ("", "false")):
            result = self.shell('''
docker() {
  case "$4" in
    *build.profile*) echo '%s' ;;
    *promotable*) echo '%s' ;;
    *) return 99 ;;
  esac
}
kubectl() { echo unexpected-kubectl; return 98; }
start_kind_credential_fixture
''' % (profile, promotable))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("exact non-promotable", result.stderr)
            self.assertNotIn("unexpected-kubectl", result.stdout)

    def test_saved_synthetic_login_requires_membership_and_selects_org(self):
        for orgs, expected in (([], 1), ([{"id": "foreign"}], 1),
                               ([{"id": "org_contract_1", "role": "owner"}], 1),
                               ([{"id": "org_contract_2", "role": "owner"},
                                 {"id": "org_contract_1", "role": "member"}], 97)):
            result = self.shell('''
log() { :; }
KIND_INGRESS_URL=http://127.0.0.1:8090
kind_workspace_runtime_image() { printf 'localhost/codewire-ci/workspace:source-synthetic\\n'; }
kind_credential_cli() {
  case "$*" in
    'org list --output json') printf '%%s\\n' '%s' ;;
    'org set org_contract_1') echo selected ;;
    'org current') touch "$KIND_CREDENTIAL_CLI_HOME/org-current"; echo 'ID: org_contract_1' ;;
    *) [ -f "$KIND_CREDENTIAL_CLI_HOME/org-current" ] || return 98; return 97 ;;
  esac
}
kind_credential_native_smoke
''' % json.dumps(orgs))
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(result.stdout, "selected\n" if expected == 97 else "")

    def test_synthetic_cli_store_is_private_fresh_and_not_an_ambient_bearer(self):
        with tempfile.TemporaryDirectory(dir="/dev/shm", prefix="kind-cli-fixture-") as scratch:
            result = self.shell('''
KIND_CREDENTIAL_CLI_HOME='%s'
KIND_INGRESS_URL=http://127.0.0.1:8090
umask 022
prepare_kind_credential_cli
[ "$(stat -c %%a "$KIND_CREDENTIAL_CLI_HOME/cw")" = 700 ]
[ "$(stat -c %%a "$KIND_CREDENTIAL_CLI_HOME/cw/config.json")" = 600 ]
[ "$(stat -c %%a "$KIND_CREDENTIAL_CLI_HOME/cw/credentials.json")" = 600 ]
jq -e '.server_url == "http://127.0.0.1:8090" and (has("default_org") | not)' \
  "$KIND_CREDENTIAL_CLI_HOME/cw/config.json" >/dev/null
jq -e '.issuer == "http://127.0.0.1:8090" and .client_id == "oidc_kind_connect"
  and .access_token == "at_kind_connect_oidc_codewire_api"
  and .refresh_token == "kind-synthetic-refresh-not-issued"
  and .scope == "openid codewire.api"
  and .expires_at_unix > now and .expires_at_unix <= now + 3600' \
  "$KIND_CREDENTIAL_CLI_HOME/cw/credentials.json" >/dev/null
if prepare_kind_credential_cli; then exit 98; fi
env() {
  [ "$1" = -i ] || return 98
  local arg
  for arg in "$@"; do
    case "$arg" in CODEWIRE_API_KEY=*) return 99 ;; esac
  done
}
CARGO_CI_DIR=/synthetic/bin
CODEWIRE_API_KEY=ambient-synthetic-must-not-forward
kind_credential_cli org current
''' % scratch)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

    def test_non_kind_context_cannot_install_certificate_controller(self):
        result = self.shell('''
KIND_E2E_COMMON_LOADED=1 NS=codewire-e2e SANDBOX_NS=dev-sandboxes KIND_CLUSTER_NAME=codewire-e2e
kubectl() { if [ "$*" = "config current-context" ]; then echo unrelated-cluster; else return 98; fi; }
deploy_kind_credential_cert_manager
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("managed disposable Kind context", result.stderr)

    def test_sealed_image_absence_never_pulls(self):
        result = self.shell('''
docker() { if [ "$1" = image ]; then return 1; fi; echo unexpected-network; return 98; }
validate_sealed_kind_images() { return 0; }
prepare_kind_credential_support_images
''')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("was not preloaded", result.stderr)
        self.assertNotIn("unexpected-network", result.stdout)

    def test_sealed_validation_error_is_not_treated_as_local_permission(self):
        result = self.shell('''
docker() { if [ "$1" = image ]; then return 1; fi; echo unexpected-network; return 98; }
validate_sealed_kind_images() { return 2; }
prepare_kind_credential_support_images
''')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("unexpected-network", result.stdout)

    def test_pinned_certificate_render_and_owner_reference(self):
        manifest = ROOT / "tests/e2e/kind/vendor/cert-manager-v1.17.1.yaml"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.assertIn(digest, HELPERS.read_text())
        self.assertIn(digest, (manifest.parent / "cert-manager-README.md").read_text())
        self.assertIn("--enable-certificate-owner-ref=true", manifest.read_text())


if __name__ == "__main__":
    unittest.main()
