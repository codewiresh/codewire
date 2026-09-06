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
    def test_host_cli_build_selects_its_actual_binary_package(self):
        manifest = tomllib.loads((ROOT / "crates/codewire-cli-bin/Cargo.toml").read_text())
        self.assertIn("cw", [binary["name"] for binary in manifest["bin"]])
        expected = f'cargo build --locked --profile ci -p {manifest["package"]["name"]} --bin cw'
        source = (ROOT / "scripts/ci/verify/kind/common.sh").read_text()
        self.assertEqual(source.count(expected), 1)
        self.assertNotIn("-p codewire-cli --bin cw", source)

    def shell(self, body):
        result = subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\n' + body,
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

    def test_explicit_bearer_requires_exact_single_org_without_saved_config(self):
        for orgs, expected in (([], 1), ([{"id": "foreign"}], 1),
                               ([{"id": "org_contract_1"}, {"id": "foreign"}], 1),
                               ([{"id": "org_contract_1"}], 97)):
            result = self.shell('''
log() { :; }
kind_credential_cli() {
  if [ "$*" = 'org list --output json' ]; then
    printf '%%s\\n' '%s'
  else
    [ "$*" != 'org set org_contract_1' ] || return 98
    return 97
  fi
}
kind_credential_native_smoke
''' % json.dumps(orgs))
            self.assertEqual(result.returncode, expected, result.stderr)

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
