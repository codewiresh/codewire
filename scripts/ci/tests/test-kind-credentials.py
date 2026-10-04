#!/usr/bin/env python3
"""Hermetic credential acceptance guards; no cluster, account or provider I/O."""

import contextlib
from datetime import datetime, timezone
import hashlib
import http.client
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
RENEWAL_SPEC = importlib.util.spec_from_file_location(
    "bridge_renewal", ROOT / "scripts/ci/verify/kind/bridge_renewal.py")
RENEWAL = importlib.util.module_from_spec(RENEWAL_SPEC)
RENEWAL_SPEC.loader.exec_module(RENEWAL)
ENVIRONMENT = "86fb3daa-dde0-4fb4-bf83-6e2399d78a5f"
WORKSPACE_UID = "57f35d02-39f9-40ed-b9e1-bc4a64ad3b0e"
GATEWAY_UID = "65d41c9c-510b-4c8a-961d-338a879c1fa4"
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
        self.managed()
        for fixture in (
            patch.object(PROBE, "CODEX_HOME", self.home),
            patch.object(PROBE, "TOKEN", self.token),
            patch.dict(os.environ, {"CODEX_HOME": str(self.home),
                                   "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"}, clear=True),
            patch.object(PROBE.ssl, "SSLContext", return_value=self.context),
            patch.object(PROBE.http.client, "HTTPSConnection", return_value=self.connection),
            contextlib.redirect_stdout(self.output),
        ):
            fixture.__enter__()
            self.addCleanup(fixture.__exit__, None, None, None)

    def managed(self, first_line=None):
        header = PROBE.MANAGED_HEADER.decode() if first_line is None else first_line
        (self.home / "config.toml").write_text(header + "\nmodel_provider = \"codewire_openai\"\n")

    def unselected(self):
        os.environ.pop("CODEX_HOME", None)
        os.environ.pop("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS", None)
        (self.home / "config.toml").unlink(missing_ok=True)

    def test_current_selected_loopback_configuration_needs_no_ca_override(self):
        PROBE.probe(ENVIRONMENT, "success")
        self.context.load_verify_locations.assert_called_once_with(cafile=PROBE.ROOTS)
        self.assertNotIn("CODEX_CA_CERTIFICATE", os.environ)

    def test_initial_unselected_configuration_needs_no_codex_settings(self):
        self.unselected()
        self.connection.getresponse.return_value.status = 403
        PROBE.probe(ENVIRONMENT, "unbound")
        self.context.load_verify_locations.assert_called_once_with(cafile=PROBE.ROOTS)
        self.assertEqual(self.connection.request.call_args.kwargs["headers"]["Authorization"],
                         "Bearer synthetic-pod-capability")

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
                if mode == "revoked":
                    os.environ["CODEX_HOME"] = str(self.home)
                    os.environ["CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"] = "v1:codex"
                    self.managed()
                else:
                    self.unselected()
                self.connection.getresponse.return_value.status = status
                PROBE.probe(ENVIRONMENT, mode)
                self.connection.getresponse.return_value.status = 200
                with self.assertRaises(ValueError):
                    PROBE.probe(ENVIRONMENT, mode)

    def test_missing_identity_does_not_read_capability(self):
        self.unselected()
        self.token.unlink()
        self.connection.getresponse.return_value.status = 401
        PROBE.probe(ENVIRONMENT, "missing")
        self.assertNotIn("Authorization", self.connection.request.call_args.kwargs["headers"])

    def test_wrong_root_requires_certificate_rejection_not_network_error(self):
        self.unselected()
        self.token.unlink()
        self.connection.request.side_effect = ssl.SSLCertVerificationError("synthetic")
        PROBE.probe(ENVIRONMENT, "wrong-root")
        self.context.load_verify_locations.assert_not_called()
        self.assertEqual(json.loads(self.output.getvalue()), {"event": "wrong_root_denied"})
        self.connection.request.side_effect = TimeoutError("synthetic")
        with self.assertRaises(TimeoutError):
            PROBE.probe(ENVIRONMENT, "wrong-root")

    def test_untrusted_root_success_cannot_pass(self):
        self.unselected()
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

    def codewire_login(self, refresh_token=None):
        return json.dumps({
            "auth_mode": "chatgpt", "OPENAI_API_KEY": None,
            "tokens": {"id_token": "e30.e30.synthetic", "access_token": "e30.e30.synthetic",
                       "refresh_token": refresh_token or PROBE.PLACEHOLDER,
                       "account_id": "codewire-kind-synthetic-account"},
            "last_refresh": "2026-10-03T00:00:00Z"})

    def test_codewires_delivered_login_replaces_its_proxy_config(self):
        # Once the daemon delivers Codex's own login it removes config.toml.
        (self.home / "auth.json").write_text(self.codewire_login(), encoding="ascii")
        for config in (True, False):
            with self.subTest(config=config):
                if not config:
                    (self.home / "config.toml").unlink()
                for mode in ("success", "revoked"):
                    self.connection.getresponse.return_value.status = PROBE.MODES[mode]
                    PROBE.probe(ENVIRONMENT, mode)

    def test_a_login_that_is_not_codewires_fails_before_network(self):
        outside = self.home / "outside.json"
        outside.write_text(self.codewire_login(), encoding="ascii")
        for contents in ("synthetic",
                         # The broker's refresh token never leaves Codewire.
                         self.codewire_login("CW_KIND_SYNTHETIC_REFRESH_1"),
                         self.codewire_login("users-own-refresh-token"),
                         None):
            with self.subTest(contents=contents):
                auth = self.home / "auth.json"
                auth.unlink(missing_ok=True)
                if contents is None:
                    auth.symlink_to(outside)
                else:
                    auth.write_text(contents, encoding="ascii")
                with self.assertRaisesRegex(ValueError, "^unexpected-provider-auth-file$"):
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

    def test_selected_probe_requires_exact_current_selection(self):
        for selection in (None, "", "v1:none", "v1:openai", "codex", "v1:codex,openai"):
            with self.subTest(selection=selection), patch.dict(os.environ, clear=True):
                os.environ["CODEX_HOME"] = str(self.home)
                if selection is not None:
                    os.environ["CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"] = selection
                with self.assertRaisesRegex(ValueError, "^projection$"):
                    PROBE.probe(ENVIRONMENT, "success")
        with patch.dict(os.environ, {"CODEX_HOME": "/synthetic/other-home"}):
            with self.assertRaisesRegex(ValueError, "^projection$"):
                PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.assert_not_called()

    def test_identity_free_selection_is_the_daemon_written_config_alone(self):
        os.environ.pop("CODEX_HOME")
        os.environ.pop("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS")
        PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.reset_mock()
        for first_line in ("", "model = \"gpt-5\"", " " + PROBE.MANAGED_HEADER.decode()):
            with self.subTest(first_line=first_line):
                self.managed(first_line)
                with self.assertRaisesRegex(ValueError, "^projection$"):
                    PROBE.probe(ENVIRONMENT, "success")
        # A delivered login removes Codewire's config.toml; absence is fine.
        (self.home / "config.toml").unlink()
        PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.reset_mock()
        outside = self.home / "outside.toml"
        outside.write_text(PROBE.MANAGED_HEADER.decode() + "\n")
        (self.home / "config.toml").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "^projection$"):
            PROBE.probe(ENVIRONMENT, "success")
        self.connection.request.assert_not_called()

    def test_unselected_probe_rejects_stale_client_configuration(self):
        self.unselected()
        for values in ({"CODEX_HOME": str(self.home)},
                       {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"},
                       {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:none"}):
            with self.subTest(values=values), patch.dict(os.environ, values, clear=True):
                with self.assertRaisesRegex(ValueError, "^unexpected-unselected-client$"):
                    PROBE.probe(ENVIRONMENT, "unbound")
        (self.home / "config.toml").write_text("synthetic-stale-client", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "^unexpected-unselected-client$"):
            PROBE.probe(ENVIRONMENT, "unbound")
        self.connection.request.assert_not_called()

    def test_legacy_ca_override_is_rejected_in_selected_and_unselected_modes(self):
        for mode in ("success", "unbound"):
            if mode == "unbound":
                self.unselected()
            for value in ("", PROBE.ROOTS, "/synthetic/other-roots"):
                with self.subTest(mode=mode, value=value), patch.dict(
                        os.environ, {"CODEX_CA_CERTIFICATE": value}):
                    with self.assertRaisesRegex(ValueError, "^projection$"):
                        PROBE.probe(ENVIRONMENT, mode)
        self.connection.request.assert_not_called()

    def test_unselected_probe_retains_provider_leak_rejections(self):
        self.unselected()
        for value in ("CW_KIND_SYNTHETIC_REFRESH_private", "synthetic-kind-signature"):
            with patch.dict(os.environ, {"SYNTHETIC_FIXTURE": value}):
                with self.assertRaisesRegex(ValueError, "^provider-environment-exposure$"):
                    PROBE.probe(ENVIRONMENT, "unbound")
        (self.home / "auth.json").write_text("synthetic", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "^unexpected-provider-auth-file$"):
            PROBE.probe(ENVIRONMENT, "unbound")
        self.assertEqual(self.output.getvalue(), "")
        self.connection.request.assert_not_called()


class HarnessGuards(unittest.TestCase):
    @staticmethod
    def session_events():
        return [
            {"event": "baseline_completed", "codex_processes": 1, "legacy_auth_commands": 0},
            {"event": "projected_token_rotated", "changed": True, "elapsed_ms": 600001},
            {"event": "rotation_turn_completed", "legacy_auth_commands": 0},
            {"event": "broker_retry_completed", "legacy_auth_commands": 0, "elapsed_ms": 12},
            {"event": "broker_retry_exhausted", "legacy_auth_commands": 0, "elapsed_ms": 13},
            {"event": "complete", "turns": 4, "completed": 3, "failed": 1,
             "same_process": True, "token_changed": True},
        ]

    @classmethod
    def rotation_events(cls):
        first = {"event": "bridge_authenticated", "environment_id": ENVIRONMENT,
                 "generation": 2, "workspace_pod_uid": WORKSPACE_UID,
                 "gateway_pod_uid": GATEWAY_UID, "auth_sequence": 1,
                 "workspace_token_changed": False}
        provider = cls.provider_events()
        return [first, provider[0], dict(first, auth_sequence=2, workspace_token_changed=True),
                *provider[1:]]

    def rotation_proof(self, events, session=None):
        directory = tempfile.TemporaryDirectory(prefix="kind-rotation-proof-")
        self.addCleanup(directory.cleanup)
        self.rotation_directory = Path(directory.name)
        path = self.rotation_directory / "session.jsonl"
        path.write_text("\n".join(json.dumps(event) for event in (
            self.session_events() if session is None else session)))
        return self.shell('''
RUN_DIR='%s'
kind_credential_fixture_events() { printf '%%s\\n' '%s'; }
assert_kind_credential_rotation '%s' 2 '%s' '%s' '%s'
''' % (self.rotation_directory, json.dumps(events), ENVIRONMENT, WORKSPACE_UID, GATEWAY_UID, path))

    def rotation_evidence(self):
        paths = list(self.rotation_directory.glob("credential-rotation.*/evidence.json"))
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(paths[0].parent.stat().st_mode & 0o777, 0o700)
        return json.loads(paths[0].read_text())

    def test_rotation_evidence_survives_both_assertion_failures(self):
        for session_failure in (False, True):
            events = self.rotation_events()
            session = self.session_events()
            if session_failure:
                session[0]["codex_processes"] = 2
            else:
                events[2]["workspace_token_changed"] = False
            with self.subTest(session_failure=session_failure):
                result = self.rotation_proof(events, session)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fixture record:", result.stderr)
                self.assertEqual(self.rotation_evidence(), {
                    "expected": {"environment_id": ENVIRONMENT, "generation": 2,
                                 "workspace_pod_uid": WORKSPACE_UID, "gateway_pod_uid": GATEWAY_UID},
                    "events": events,
                })

    def test_rotation_evidence_excludes_unknown_fields_and_malformed_values(self):
        events = self.rotation_events()
        for event in events:
            event["message"] = "synthetic-do-not-save"
            event["unknown_material"] = {"nested": "synthetic-do-not-save"}
        events[0].update(environment_id="synthetic-do-not-save", generation="synthetic-do-not-save",
                         workspace_pod_uid=["synthetic-do-not-save"], gateway_pod_uid=None,
                         auth_sequence=-1, workspace_token_changed="synthetic-do-not-save")
        events[1].update(scenario="synthetic-do-not-save", attempt=1.5,
                         status="synthetic-do-not-save", response_calls=2**53,
                         refresh_calls={"secret": "synthetic-do-not-save"})
        events += [{"event": "synthetic-do-not-save"}, "synthetic-do-not-save"]
        result = self.rotation_proof(events)
        self.assertNotEqual(result.returncode, 0)
        evidence = self.rotation_evidence()
        self.assertNotIn("synthetic-do-not-save", json.dumps(evidence) + result.stdout + result.stderr)
        self.assertEqual(evidence["events"][0], {key: "bridge_authenticated" if key == "event" else None
                                                for key in self.rotation_events()[0]})
        self.assertEqual(evidence["events"][1], {key: "provider_response" if key == "event" else None
                                                for key in self.rotation_events()[1]})
        self.assertEqual(evidence["events"][-2:], [{"event": None}, {"event": None}])
        self.assertTrue(all("message" not in event and "unknown_material" not in event
                            for event in evidence["events"]))

    def test_rotation_evidence_rejects_oversized_transcript(self):
        result = self.rotation_proof([{}] * 4097)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not preserve bounded credential fixture evidence", result.stderr)
        self.assertEqual(list(self.rotation_directory.glob("credential-rotation.*/evidence.json")), [])
        for path in self.rotation_directory.glob("credential-rotation.*/evidence.pending"):
            self.assertEqual(path.read_bytes(), b"")

    def test_rotation_evidence_does_not_overwrite_and_sanitizes_expected_coordinates(self):
        with tempfile.TemporaryDirectory(prefix="kind-rotation-capture-") as directory:
            result = self.shell('''
RUN_DIR='%s'
save_kind_credential_rotation_evidence sensitive sensitive sensitive sensitive <<<'[]'
save_kind_credential_rotation_evidence '%s' 2 '%s' '%s' <<<'[]'
''' % (directory, ENVIRONMENT, WORKSPACE_UID, GATEWAY_UID))
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = [Path(path) for path in result.stdout.splitlines()]
            self.assertEqual(len(set(paths)), 2)
            self.assertEqual(json.loads(paths[0].read_text())["expected"], {
                "environment_id": None, "generation": None,
                "workspace_pod_uid": None, "gateway_pod_uid": None,
            })
            self.assertEqual(json.loads(paths[1].read_text())["expected"]["environment_id"], ENVIRONMENT)

    def test_rotation_evidence_write_failure_cannot_reach_acceptance(self):
        with tempfile.TemporaryDirectory(prefix="kind-rotation-write-") as directory:
            result = self.shell('''
RUN_DIR='%s'
kind_credential_fixture_events() { printf '[]'; }
mktemp() { return 38; }
assert_kind_credential_rotation '%s' 2 '%s' '%s' /not-a-session
''' % (directory, ENVIRONMENT, WORKSPACE_UID, GATEWAY_UID))
            self.assertEqual(result.returncode, 38, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_rotation_collector_failure_cannot_pass_or_emit_evidence(self):
        with tempfile.TemporaryDirectory(prefix="kind-rotation-collector-") as directory:
            result = self.shell('''
RUN_DIR='%s'
kind_credential_fixture_events() { printf '[]'; return 37; }
assert_kind_credential_rotation '%s' 2 '%s' '%s' /not-a-session
''' % (directory, ENVIRONMENT, WORKSPACE_UID, GATEWAY_UID))
            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_rotation_requires_composed_token_time_authentication_and_stock_turn_proof(self):
        result = self.rotation_proof(self.rotation_events())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_initial_unbound_auth_is_not_selected_epoch_evidence(self):
        # A queued source restart legitimately retains its workflow generation.
        # Its old unbound Pod pair must not join the replacement Pod journey.
        for generation in (1, 2):
            events = self.rotation_events()
            first = dict(events[0], generation=generation, workspace_pod_uid=ENVIRONMENT,
                         gateway_pod_uid=ENVIRONMENT)
            for event in events:
                if event["event"] == "bridge_authenticated":
                    event["auth_sequence"] += 1
            with self.subTest(generation=generation):
                result = self.rotation_proof([first, *events])
                self.assertEqual(result.returncode, 0, result.stderr)
                events[2]["workspace_token_changed"] = False
                self.assertNotEqual(self.rotation_proof([first, *events]).returncode, 0)

    def test_identity_or_generation_change_after_selection_cannot_be_filtered_out(self):
        for changes in ({"workspace_pod_uid": ENVIRONMENT}, {"gateway_pod_uid": ENVIRONMENT},
                        {"generation": 3}):
            for position in (1, 2, 4):
                events = self.rotation_events()
                events.insert(position, dict(events[0], **changes))
                sequence = 0
                for event in events:
                    if event["event"] == "bridge_authenticated":
                        sequence += 1
                        event["auth_sequence"] = sequence
                with self.subTest(changes=changes, position=position):
                    # Even a later correct changed-token event cannot hide this.
                    self.assertNotEqual(self.rotation_proof(events).returncode, 0)

    def test_selected_journey_requires_its_own_initial_authentication(self):
        events = self.rotation_events()
        events[0]["workspace_pod_uid"] = ENVIRONMENT
        self.assertNotEqual(self.rotation_proof(events).returncode, 0)
        events = self.rotation_events()
        events[0]["workspace_token_changed"] = True
        self.assertNotEqual(self.rotation_proof(events).returncode, 0)

    def test_other_environment_authentication_does_not_join_selected_journey(self):
        events = self.rotation_events()
        events.insert(2, dict(events[0], environment_id=WORKSPACE_UID, auth_sequence=2))
        events[3]["auth_sequence"] = 3
        result = self.rotation_proof(events)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrong_identity_old_token_missing_or_misordered_auth_cannot_prove_rotation(self):
        for changes in ({"workspace_token_changed": False}, {"workspace_token_changed": "true"},
                        {"workspace_pod_uid": ENVIRONMENT}, {"gateway_pod_uid": ENVIRONMENT},
                        {"environment_id": WORKSPACE_UID}, {"generation": 3},
                        {"auth_sequence": 1}, {"auth_sequence": 3}):
            events = self.rotation_events()
            events[2].update(changes)
            with self.subTest(changes=changes):
                self.assertNotEqual(self.rotation_proof(events).returncode, 0)
        events = self.rotation_events()
        for reordered in (events[:2] + events[3:],
                          [events[0], events[2], events[1], *events[3:]],
                          [*events[:2], events[3], events[2], *events[4:]]):
            with self.subTest(events=reordered):
                self.assertNotEqual(self.rotation_proof(reordered).returncode, 0)

    def test_authentication_alone_cannot_replace_rotation_duration_or_failed_terminal(self):
        for index, changes in ((0, {"codex_processes": 2}), (0, {"legacy_auth_commands": 1}),
                               (1, {"changed": False}), (1, {"elapsed_ms": 30001}),
                               (1, {"elapsed_ms": 600000}), (1, {"elapsed_ms": 720000}),
                               (2, {"legacy_auth_commands": 2}),
                               (4, {"event": "native_reread_completed"}),
                               (4, {"elapsed_ms": 30000}), (5, {"failed": 0, "completed": 4}),
                               (5, {"same_process": False})):
            session = self.session_events()
            session[index].update(changes)
            with self.subTest(index=index, changes=changes):
                self.assertNotEqual(self.rotation_proof(self.rotation_events(), session).returncode, 0)

    @staticmethod
    def provider_events(baseline=2):
        events = []
        responses, refreshes = 0, 0
        def response(scenario, attempt, status):
            nonlocal responses
            responses += 1
            events.append({"event": "provider_response", "scenario": scenario,
                           "attempt": attempt, "status": status,
                           "response_calls": responses, "refresh_calls": refreshes})
        def refresh():
            nonlocal refreshes
            refreshes += 1
            events.append({"event": "provider_refresh", "response_calls": responses,
                           "refresh_calls": refreshes})
        response("baseline", 1, 200)
        response("baseline", 2, 200)
        response("broker_retry_once", 1, 401)
        refresh()
        response("broker_retry_once", 2, 200)
        response("broker_retry_exhausted", 1, 401)
        refresh()
        response("broker_retry_exhausted", 2, 400)
        for attempt in range(3, baseline + 1):
            response("baseline", attempt, 200)
        return events

    def provider_counts(self, events, baseline=2, restarts=0):
        logs = "\n".join(json.dumps({"target": "codewire_kind_credential_fixture", "fields": event})
                         for event in events)
        pods = json.dumps({"items": [{"metadata": {}, "status": {
            "containerStatuses": [{"restartCount": restarts}]}}]})
        return self.shell('''
NS=codewire-e2e
kubectl() {
  case "$*" in
    '-n codewire-e2e logs deployment/codewire-credential-service -c credential-service')
      printf '%%s\\n' '%s' ;;
    '-n codewire-e2e get pods -l app.kubernetes.io/component=credential-service -o json')
      printf '%%s\\n' '%s' ;;
    *) return 99 ;;
  esac
}
assert_kind_credential_provider_counts %d
''' % (logs, pods, baseline))

    def test_provider_audit_accepts_one_refresh_retry_and_closed_exhaustion(self):
        for baseline in (2, 3, 5):
            with self.subTest(baseline=baseline):
                result = self.provider_counts(self.provider_events(baseline), baseline)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
        for baseline, events in ((4, 4), (5, 4), (5, 3), (3, 5)):
            with self.subTest(baseline=baseline, events=events):
                self.assertNotEqual(
                    self.provider_counts(self.provider_events(events), baseline).returncode, 0)

    @staticmethod
    def reuse_lines(presented=(2, 2, 0), caches=("miss", "hit", "miss"), admitted_between=False,
                    gap=1.5, total_ms=40):
        fixture = [{"target": "codewire_kind_credential_fixture", "fields": {
            "event": "provider_response", "scenario": "baseline", "attempt": attempt,
            "status": 200, "generation": generation, "response_calls": attempt + 4,
            "refresh_calls": 2}} for attempt, generation in zip((3, 4, 5), presented)]
        def at(seconds):
            whole, fraction = divmod(round(seconds * 1_000_000), 1_000_000)
            return f"2026-10-04T00:{whole // 60:02d}:{whole % 60:02d}.{fraction:06d}Z"
        def timed(cache, seconds):
            read = 0 if cache == "hit" else 1
            return {"timestamp": at(seconds), "target": "codewire_credential_broker::timing",
                    "fields": {"event": "proxied_request", "slot": "codex", "route": "openai-api",
                               "outcome": "response", "status": 200, "cache": cache,
                               "total_ms": total_ms, "material_reads": read, "unwraps": read}}
        admission = {"timestamp": at(10.5), "target": "codewire_credential_broker::timing",
                     "fields": {"event": "epoch_admission", "outcome": "admitted"}}
        # The earlier session's requests, then the warm-up at 10 s.
        lines = [timed("miss", 1), timed("hit", 2), fixture[0], timed(caches[0], 10)]
        if admitted_between:
            lines.append(admission)
        lines += [fixture[1], timed(caches[1], 10 + gap), fixture[2],
                  timed(caches[2], 20 + gap)]
        return lines

    def material_reuse(self, lines):
        logs = "\n".join(json.dumps(line) for line in lines)
        return self.shell('''
NS=codewire-e2e
kubectl() {
  [ "$*" = '-n codewire-e2e logs deployment/codewire-credential-service -c credential-service' ] ||
    return 99
  printf '%%s\\n' '%s'
}
assert_kind_credential_material_reuse
''' % logs)

    def test_material_reuse_requires_a_hit_then_the_reconnected_login(self):
        result = self.material_reuse(self.reuse_lines())
        self.assertEqual(result.returncode, 0, result.stderr)
        # Only a new epoch admitted between the first two requests, or a gap
        # that can reach the two-minute window, may miss.
        for cold in ({"admitted_between": True}, {"gap": 119.97}, {"gap": 125}):
            with self.subTest(cold=cold):
                result = self.material_reuse(self.reuse_lines(caches=("miss", "miss", "miss"),
                                                              **cold))
                self.assertEqual(result.returncode, 0, result.stderr)
        for lines in (
                self.reuse_lines(caches=("miss", "miss", "miss")),
                self.reuse_lines(caches=("hit", "hit", "miss")),
                # A reuse after Reconnect, or the old login presented.
                self.reuse_lines(caches=("miss", "hit", "hit")),
                self.reuse_lines(presented=(2, 2, 2)),
                self.reuse_lines(presented=(0, 0, 0)),
                self.reuse_lines(presented=(2, 1, 0)),
                self.reuse_lines(caches=("miss", "hit", "miss"), admitted_between=True),
                self.reuse_lines(caches=("miss", "hit", "miss"), gap=125),
                self.reuse_lines(caches=("miss", "miss", "miss"), gap=119.9),
                self.reuse_lines()[:-1]):
            with self.subTest(lines=lines):
                result = self.material_reuse(lines)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("reused a login after Reconnect", result.stderr)

    def test_provider_audit_rejects_old_third_request_missing_refresh_and_extra_replay(self):
        correct = self.provider_events()
        mutations = []
        old = [dict(event) for event in correct]
        for event in old:
            if event.get("scenario") == "broker_retry_exhausted":
                event["scenario"] = "native_reread"
        old.append({"event": "provider_response", "scenario": "native_reread", "attempt": 3,
                    "status": 200, "response_calls": 7, "refresh_calls": 2})
        mutations.append(old)
        mutations.append([event for event in correct if event["event"] != "provider_refresh"])
        mutations.append(correct + [dict(correct[-1], attempt=3, response_calls=7, status=200)])
        mutations.append(correct + [dict(correct[-1], attempt=3, response_calls=7, status=401)])
        mutations.append(correct + [dict(correct[-1], attempt=3, response_calls=7, status=400)])
        mutations.append(correct[:3] + [dict(correct[3], refresh_calls=2)] + correct[4:])
        mutations.append(correct[:3] + [correct[4], correct[3]] + correct[5:])
        for events in mutations:
            with self.subTest(events=events):
                self.assertNotEqual(self.provider_counts(events).returncode, 0)

    def test_provider_audit_still_rejects_a_restarted_fixture(self):
        self.assertNotEqual(self.provider_counts(self.provider_events(), restarts=1).returncode, 0)

    def test_bootstrap_cleanup_removes_issuer_before_outputs_and_propagates_failures(self):
        for certificate_status, leaf_status in ((0, 0), (42, 0), (0, 43)):
            result = self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() {
  printf '%%s\\n' "$*" >&2
  case "$*" in
    '-n dev-sandboxes delete certificate/cw-credential-gateway-%s --ignore-not-found=true --cascade=background --wait=true --timeout=120s') return %s ;;
    '-n dev-sandboxes delete secret/cw-credential-gateway-%s --ignore-not-found=true --wait=true --timeout=120s') return %s ;;
    *) return 99 ;;
  esac
}
delete_kind_credential_bootstrap '%s'
''' % (ENVIRONMENT, certificate_status, ENVIRONMENT, leaf_status, ENVIRONMENT))
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

    def test_codex_config_map_absence_is_exact_and_fails_closed(self):
        for found, expected in (("", 0), ("configmap/cw-credential-codex-%s" % ENVIRONMENT, 1)):
            result = self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() {
  printf '%%s\\n' "$*" >&2
  [ "$*" = '-n dev-sandboxes get configmap cw-credential-codex-%s --ignore-not-found=true -o name' ] || return 99
  printf '%%s' '%s'
}
assert_no_kind_codex_config_map '%s'
''' % (ENVIRONMENT, found, ENVIRONMENT))
            self.assertEqual(result.returncode, expected, result.stderr)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() { return 42; }
assert_no_kind_codex_config_map '%s'
''' % ENVIRONMENT)
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_native_flow_proves_codex_home_persistence_without_a_config_map(self):
        source = HELPERS.read_text()
        flow = source.split("kind_credential_native_smoke() (", 1)[1]
        self.assertNotIn("configmap", flow.lower().replace("assert_no_kind_codex_config_map", ""))
        self.assertEqual(flow.count('assert_no_kind_codex_config_map "$environment" || return $?'), 4)
        stop = flow.index('env --platform stop "$environment"')
        start = flow.index('env --platform start "$environment"')
        self.assertLess(flow.index("/home/codewire/.codex/kind-persistence"), stop)
        self.assertLess(start, flow.index('cat /home/codewire/.codex/kind-persistence'))

    def codex_login(self, output, status=0, mode="deliver", extra=""):
        directory = tempfile.TemporaryDirectory(prefix="kind-codex-login-")
        self.addCleanup(directory.cleanup)
        return self.shell('''
RUN_DIR='%s'
SANDBOX_NS=dev-sandboxes
kind_credential_workspace() { [ "$1" = '%s' ] || return 97; printf 'workspace-pod\\n'; }
kubectl() {
  [ "$*" = '-n dev-sandboxes exec -i workspace-pod -c workspace -- python3 -B -u - %s%s' ] || return 99
  cmp -s - "$ROOT/scripts/ci/verify/kind/codex_login.py" || return 98
  printf '%%s' '%s'
  return %d
}
kind_credential_codex_login '%s' %s %s
''' % (directory.name, ENVIRONMENT, mode, " " + extra if extra else "", output, status,
       ENVIRONMENT, mode, extra))

    def test_codex_login_step_passes_only_on_its_own_completion(self):
        delivered = '{"event":"delivered","generation":0}\n'
        result = self.codex_login(delivered + '{"event":"complete","mode":"deliver"}\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"generation":0', result.stdout)
        result = self.codex_login('{"event":"rotation_adopted","generation":2}\n'
                                  '{"event":"complete","mode":"rotation"}\n',
                                  mode="rotation", extra="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        for output, status in (
                (delivered + '{"event":"complete","mode":"deliver"}\n', 1),
                (delivered + '{"event":"complete","mode":"logout"}\n', 0),
                ('{"event":"failed","mode":"deliver","reason":"login_not_delivered"}\n'
                 '{"event":"complete","mode":"deliver"}\n', 0),
                ('{"event":"complete","mode":"deliver"}\n', 0),
                ("not-json\n", 0),
                ("", 0)):
            with self.subTest(output=output, status=status):
                result = self.codex_login(output, status)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Codex ChatGPT login acceptance failed in mode deliver", result.stderr)

    def test_native_flow_proves_the_chatgpt_login_in_order(self):
        flow = HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1]
        index = flow.index
        deliver = index('kind_credential_codex_login "$environment" deliver')
        session = index("scripts/ci/verify/kind/codex_session.py")
        counts = index("assert_kind_credential_provider_counts 2")
        rotation = index('kind_credential_codex_login "$environment" rotation "$login_generation" || return $?')
        own = index('kind_credential_codex_login "$environment" own-login || return $?')
        logout = index('kind_credential_codex_login "$environment" logout || return $?')
        stop = index('env --platform stop "$environment"')
        start = index('env --platform start "$environment"')
        redelivered = index('kind_credential_codex_login "$environment" redelivered || return $?')
        success = index('kind_credential_probe "$environment" success')
        warm = index("assert_kind_credential_provider_counts 3")
        reuse = index('kind_credential_probe "$environment" success', warm)
        reconnect = index('credentials --platform connect codex --name "$credential_name" --yes')
        reconnected = index('kind_credential_probe "$environment" success', reconnect)
        reused = index("assert_kind_credential_material_reuse")
        revoke = index('credentials --platform revoke "$credential_name"')
        revoked = index('kind_credential_codex_login "$environment" revoked || return $?')
        destroy = index('env --platform rm "$environment"')
        # Delivery before the proxy session whose refreshes rotate it; the
        # user's own login and logout after rotation; a new container forgets
        # the logout; a cached request then Reconnect precede revocation, which
        # removes the login before destroy.
        order = [deliver, session, counts, rotation, own, logout, stop, start, redelivered,
                 success, warm, reuse, reconnect, reconnected, reused, revoke, revoked, destroy]
        self.assertEqual(sorted(order), order)
        self.assertEqual(flow.count('kind_credential_probe "$environment" success'), 3)
        self.assertEqual(flow.count("assert_kind_credential_provider_counts 5"), 2)
        self.assertIn('login_events="$(kind_credential_codex_login "$environment" deliver)" || return $?',
                      flow)

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

    def test_environment_observation_failure_names_itself_instead_of_a_silent_jq_exit(self):
        result = self.shell('''
kind_credential_cli() { printf '{%%s}' '"state":"running"'; }
sleep() { :; }
wait_kind_credential_environment '%s' running
''' % ENVIRONMENT)
        self.assertEqual(result.returncode, 0, result.stderr)
        # jq exits 4 without a word on empty input; the wait must convert any
        # observation failure into a named error instead of dying silently.
        result = self.shell('''
kind_credential_cli() { return 0; }
sleep() { :; }
wait_kind_credential_environment '%s' running
''' % ENVIRONMENT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            '::error::credential fixture environment observation failed while waiting for running',
            result.stderr)

    def test_environment_observation_failure_survives_an_empty_successful_jq(self):
        # Older jq variants exit 0 with no output on empty input (the job
        # image's jq, where -e does not cover the empty stream). The empty
        # state must still fail as a named observation error, not burn the
        # whole budget into 'did not reach running'.
        result = self.shell('''
kind_credential_cli() { return 0; }
jq() { cat >/dev/null; }
sleep() { :; }
wait_kind_credential_environment '%s' running
''' % ENVIRONMENT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            '::error::credential fixture environment observation failed while waiting for running',
            result.stderr)
        self.assertNotIn('did not reach running', result.stderr)

    @staticmethod
    def _sandbox_pair_pods(workspace_phase, gateway_generation, gateway_uid=GATEWAY_UID):
        return json.dumps({"items": [
            {"metadata": {"name": "sandbox-workspace",
                          "labels": {"codewire.sh/type": "workspace"}},
             "spec": {"serviceAccountName": "codewire-sandbox",
                      "automountServiceAccountToken": False,
                      "containers": [{"name": "workspace"}]},
             "status": {"phase": workspace_phase}},
            {"metadata": {"name": "cw-gateway-restart",
                          "labels": {"codewire.sh/type": "gateway"},
                          "uid": gateway_uid},
             "spec": {"containers": [{"name": "gateway", "env": [
                 {"name": "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
                  "value": str(gateway_generation)}]}]},
             "status": {"phase": "Running"}}]})

    def test_sandbox_pair_wait_retries_until_the_restart_pair_is_running(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-sandbox-pair-")
        self.addCleanup(directory.cleanup)
        # The first observation has the workspace still Pending and only the
        # pre-restart (generation 1) gateway Running; neither may satisfy it.
        pending = self._sandbox_pair_pods("Pending", 1)
        ready = self._sandbox_pair_pods("Running", 2)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() {
  if [ "$*" = "-n dev-sandboxes exec sandbox-workspace -c workspace -- true" ]; then return 0; fi
  count="$(( $(cat '%(dir)s/count' 2>/dev/null || printf 0) + 1 ))"
  printf '%%s\\n' "$count" > '%(dir)s/count'
  if [ "$count" -lt 2 ]; then printf '%%s' '%(pending)s'; else printf '%%s' '%(ready)s'; fi
}
wait_kind_credential_sandbox_pair '%(env)s' 2
''' % {"dir": directory.name, "pending": pending, "ready": ready, "env": ENVIRONMENT})
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2, result.stdout)
        self.assertEqual(lines[0], "sandbox-workspace")
        self.assertEqual(json.loads(lines[1])["metadata"]["uid"], GATEWAY_UID)
        with open(os.path.join(directory.name, "count"), encoding="utf-8") as handle:
            self.assertEqual(int(handle.read()), 2)

    def test_sandbox_pair_wait_holds_through_the_suspended_recreate_transition(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-sandbox-pair-exec-")
        self.addCleanup(directory.cleanup)
        # The recreated pair is Running immediately, but the Suspended/recreate
        # transition has not finished inside the workspace container: execs
        # fail twice before the container accepts them. The wait must hold
        # instead of handing the suite a pod it cannot use yet.
        ready = self._sandbox_pair_pods("Running", 2)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() {
  if [ "$*" = "-n dev-sandboxes exec sandbox-workspace -c workspace -- true" ]; then
    attempts="$(( $(cat '%(dir)s/attempts' 2>/dev/null || printf 0) + 1 ))"
    printf '%%s\\n' "$attempts" > '%(dir)s/attempts'
    [ "$attempts" -ge 3 ]
    return $?
  fi
  printf '%%s' '%(ready)s'
}
wait_kind_credential_sandbox_pair '%(env)s' 2
''' % {"dir": directory.name, "ready": ready, "env": ENVIRONMENT})
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), 2, result.stdout)
        self.assertEqual(lines[0], "sandbox-workspace")
        with open(os.path.join(directory.name, "attempts"), encoding="utf-8") as handle:
            self.assertEqual(int(handle.read()), 3)

    def test_sandbox_pair_wait_exhaustion_names_environment_and_generation(self):
        pending = self._sandbox_pair_pods("Pending", 1)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() { printf '%%s' '%s'; }
wait_kind_credential_sandbox_pair '%s' 2
''' % (pending, ENVIRONMENT))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            '::error::credential fixture environment %s did not materialize its '
            'generation-2 workspace and gateway Pods exec-ready after the managed restart' % ENVIRONMENT,
            result.stderr)

    def test_sandbox_pair_wait_exhaustion_when_exec_never_opens(self):
        ready = self._sandbox_pair_pods("Running", 2)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() {
  if [ "$*" = "-n dev-sandboxes exec sandbox-workspace -c workspace -- true" ]; then return 1; fi
  printf '%%s' '%s'
}
wait_kind_credential_sandbox_pair '%s' 2
''' % (ready, ENVIRONMENT))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('exec-ready', result.stderr)

    def test_native_acceptance_reports_the_failing_command_instead_of_a_bare_exit(self):
        # prepare_kind_credential_cli is the first fallible plain command after
        # the trap is armed; its failure must be reported, never a bare exit.
        result = self.shell('''
log() { :; }
kind_workspace_runtime_image() { printf 'localhost/synthetic:latest\\n'; }
prepare_kind_credential_cli() { synthetic_prepare_failure_marker; }
kind_credential_native_smoke
''')
        self.assertEqual(result.returncode, 127, result.stderr)
        self.assertIn('::error::native Codex acceptance failed:', result.stderr)
        self.assertIn('command=synthetic_prepare_failure_marker', result.stderr)
        self.assertIn('status=127', result.stderr)

    def test_native_acceptance_names_a_delivered_login_without_a_generation(self):
        # Drive the whole post-update window with stubs and hand the flow a
        # deliver completion whose event stream lacks the delivered event.
        # jq's select-miss exit code differs between jq 1.8 and the job image,
        # so the missing generation must be a named error on content.
        gateway = json.dumps({"metadata": {"uid": GATEWAY_UID},
                              "spec": {"containers": [{"name": "gateway", "env": [
                                  {"name": "CODEWIRE_ENVIRONMENT_OPERATION_GENERATION",
                                   "value": "1"}]}]}}) .replace("'", "'\\''")
        workspace = json.dumps({"metadata": {"uid": WORKSPACE_UID},
                                "spec": {"containers": [{"name": "workspace"}]}}).replace("'", "'\\''")
        result = self.shell('''
log() { :; }
SANDBOX_NS=dev-sandboxes
kind_workspace_runtime_image() { printf 'localhost/synthetic:latest\\n'; }
prepare_kind_credential_cli() { :; }
kind_credential_cli() {
  case "$*" in
    'org list --output json')
      printf '[{"id":"org_contract_1","role":"member"},{"id":"org_contract_2","role":"owner"}]\\n' ;;
    'org current') printf 'ID: org_contract_1\\n' ;;
    'credentials --platform get'*)
      printf '[{"name":"%%s","provider":"openai","status":"CREDENTIAL_STATUS_ACTIVE"}]\\n' "$4" ;;
    'env --platform create'*) printf '{"id":"%%s"}\\n' '%(env)s' ;;
    'env --platform update'*) printf '{"operation_generation":1}\\n' ;;
    *) return 0 ;;
  esac
}
wait_kind_credential_environment() { return 0; }
kind_credential_probe() { :; }
wait_kind_credential_sandbox_pair() { printf 'sandbox-x\\n%%s\\n' '%(gateway)s'; }
kubectl() {
  case "$*" in
    "-n dev-sandboxes get pod sandbox-x -o jsonpath={.metadata.uid}") printf '%%s\\n' '%(uid)s' ;;
    "-n dev-sandboxes get pod sandbox-x -o json") printf '%%s\\n' '%(workspace)s' ;;
    *) return 99 ;;
  esac
}
kind_credential_codex_login() { printf '{"event":"complete","mode":"deliver"}\\n'; }
kind_credential_native_smoke
''' % {"env": ENVIRONMENT, "gateway": gateway, "workspace": workspace, "uid": WORKSPACE_UID})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('::error::the delivered Codex login event is missing its generation',
                      result.stderr)

    def test_native_acceptance_arms_its_error_trap_before_io(self):
        source = HELPERS.read_text()
        flow = source.split("kind_credential_native_smoke() (", 1)[1]
        trap = flow.index("trap 'echo \"::error::native Codex acceptance failed:")
        self.assertLess(trap, flow.index('workspace_image="$(kind_workspace_runtime_image)"'))
        self.assertLess(trap, flow.index('prepare_kind_credential_cli'))
        self.assertIn("set -E", flow[:trap])
        generation = flow.index('login_generation="$(jq -er')
        guard = flow.index('::error::the delivered Codex login event is missing its generation')
        self.assertLess(generation, guard)
        self.assertNotIn('login_generation="$(jq -er \'select(.event == "delivered") | .generation\' <<<"$login_events")" ||',
                         flow)

    def test_native_restart_wait_binds_the_update_generation_before_pod_assertions(self):
        source = HELPERS.read_text()
        flow = source.split("kind_credential_native_smoke() (", 1)[1]
        self.assertNotIn("expected one exact managed gateway", flow)
        update = flow.index('update="$(kind_credential_cli env --platform update "$environment"')
        generation = flow.index('restart_generation="$(jq -er')
        pair = flow.index('pair="$(wait_kind_credential_sandbox_pair '
                          '"$environment" "$restart_generation")"')
        gateway_uid = flow.index('gateway_uid="$(jq -er')
        self.assertLess(update, generation)
        self.assertLess(generation, pair)
        self.assertLess(pair, gateway_uid)
        self.assertIn('wait_kind_credential_environment "$environment" running\n  pair=', flow)

    def test_host_cli_build_selects_its_actual_binary_package(self):
        manifest = tomllib.loads((ROOT / "crates/codewire-cli-bin/Cargo.toml").read_text())
        self.assertIn("cw", [binary["name"] for binary in manifest["bin"]])
        expected = f'cargo build --locked --profile ci -p {manifest["package"]["name"]} --bin cw'
        source = (ROOT / "scripts/ci/images/build-kind-smokes.sh").read_text()
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
                                 (0, "registry.example.invalid/oci-approved/jetstack")):
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

    def test_sealed_prepare_and_load_use_only_preloaded_harbor_references(self):
        result = self.shell('''
exec 3>&1
validate_sealed_kind_images() { return 0; }
KIND_CLUSTER_NAME=synthetic-credential-fixture
log() { :; }
docker() {
  case "$1 $2" in
    'image inspect'|'image tag')
      [[ "$3" == registry.example.invalid/oci-approved/jetstack/cert-manager-*@sha256:* ]] || return 98
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
            source = f"registry.example.invalid/oci-approved/jetstack/cert-manager-{name}@sha256:{digest}"
            alias = f"localhost/codewire-ci/cert-manager-{name}:verified-{digest}"
            expected += [f"docker:image inspect {source}", f"docker:image tag {source} {alias}"]
        for name, digest in CREDENTIAL_IMAGES:
            source = f"registry.example.invalid/oci-approved/jetstack/cert-manager-{name}@sha256:{digest}"
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

    RENEWAL_STARTED_MS = 1_800_000_000_000
    RENEWAL_ENDED_MS = RENEWAL_STARTED_MS + 700_000

    @classmethod
    def renewal_probe(cls, requests=700, statuses=None, **fields):
        event = {"event": "bridge_renewal_probe", "started_unix_ms": cls.RENEWAL_STARTED_MS,
                 "ended_unix_ms": cls.RENEWAL_ENDED_MS, "requests": requests,
                 "statuses": {"403": requests} if statuses is None else statuses}
        event.update(fields)
        return json.dumps(event)

    @classmethod
    def gateway_line(cls, offset_ms, event="credential_bridge_epoch_overlap",
                     target="codewire_gateway::hosted_bridge"):
        stamp = datetime.fromtimestamp((cls.RENEWAL_STARTED_MS + offset_ms) / 1000, timezone.utc)
        return json.dumps({
            "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "level": "INFO",
            "fields": {"event": event, "previous_ends_in_ms": 29000, "next_ends_in_ms": 509000,
                       "message": "hosted credential bridge admitted the next epoch"},
            "target": target,
        })

    def renewal_assertion(self, probe, logs, log_status=0, pod="cw-gateway-renewal"):
        directory = tempfile.TemporaryDirectory(prefix="kind-bridge-renewal-")
        self.addCleanup(directory.cleanup)
        probe_path = Path(directory.name) / "probe.jsonl"
        probe_path.write_text("".join(f"{line}\n" for line in probe))
        logs_path = Path(directory.name) / "gateway.log"
        logs_path.write_text("".join(f"{line}\n" for line in logs))
        return self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() {
  [ "$*" = '-n dev-sandboxes logs pod/cw-gateway-renewal -c codewire-gateway' ] || { echo unexpected-kubectl >&2; return 99; }
  cat '%s'
  return %d
}
assert_kind_credential_bridge_renewal '%s' '%s'
''' % (logs_path, log_status, probe_path, pod))

    def test_bridge_renewal_requires_only_broker_answers_and_an_overlap_in_the_window(self):
        noise = ["not-json", json.dumps({"timestamp": "x", "fields": "x"}),
                 self.gateway_line(100_000, event="credential_bridge_epoch_ended")]
        for offset in (300_000, -2_000, 702_000):
            with self.subTest(offset=offset):
                result = self.renewal_assertion(
                    [self.renewal_probe()], [*noise, self.gateway_line(offset)])
                self.assertEqual(result.returncode, 0, result.stderr)
        # About one request a second: the minimum is a short renewal window.
        result = self.renewal_assertion([self.renewal_probe(requests=60)],
                                        [self.gateway_line(300_000)])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bridge_renewal_rejects_any_503_other_status_or_thin_probe(self):
        for probe in (
                self.renewal_probe(statuses={"403": 699, "503": 1}),
                self.renewal_probe(statuses={"403": 699, "error": 1}),
                self.renewal_probe(statuses={"200": 700}),
                self.renewal_probe(statuses={"403": 699}),
                self.renewal_probe(statuses={}),
                self.renewal_probe(requests=59),
                self.renewal_probe(requests=0),
                self.renewal_probe(requests=700.5, statuses={"403": 700.5}),
                self.renewal_probe(ended_unix_ms=self.RENEWAL_STARTED_MS),
                self.renewal_probe(extra=True),
                json.dumps({"event": "bridge_renewal_probe_failed"}),
                "not-json"):
            with self.subTest(probe=probe):
                result = self.renewal_assertion([probe], [self.gateway_line(300_000)])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("a proxied request failed or the probe was incomplete", result.stderr)
                self.assertNotIn("unexpected-kubectl", result.stderr)
        for probes in ([], [self.renewal_probe(), self.renewal_probe()]):
            with self.subTest(probes=probes):
                result = self.renewal_assertion(probes, [self.gateway_line(300_000)])
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_bridge_renewal_requires_the_gateway_overlap_inside_the_window(self):
        for logs in (
                [],
                [self.gateway_line(-3_000)],
                [self.gateway_line(703_000)],
                [self.gateway_line(300_000, event="credential_bridge_epoch_ended")],
                [self.gateway_line(300_000, target="codewire_gateway::runtime")],
                [self.gateway_line(300_000).replace("Z\"", "+00:00\"")]):
            with self.subTest(logs=logs):
                result = self.renewal_assertion([self.renewal_probe()], logs)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("gateway logged no epoch overlap", result.stderr)

    def test_bridge_renewal_fails_closed_on_log_or_pod_name_failure(self):
        result = self.renewal_assertion([self.renewal_probe()], [self.gateway_line(300_000)],
                                        log_status=7)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("could not read the gateway log", result.stderr)
        for pod in ("", "Gateway", "pod/cw-gateway-renewal", "cw gateway"):
            with self.subTest(pod=pod):
                result = self.renewal_assertion([self.renewal_probe()],
                                                [self.gateway_line(300_000)], pod=pod)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn("unexpected-kubectl", result.stderr)

    def test_bridge_renewal_probe_starts_in_the_exact_workspace_and_stops_on_request(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-bridge-renewal-run-")
        self.addCleanup(directory.cleanup)
        result = self.shell('''
RUN_DIR='%s'
SANDBOX_NS=dev-sandboxes
calls="$RUN_DIR/calls"
kubectl() {
  printf '%%s\\n' "$*" >> "$calls"
  case "$*" in
    '-n dev-sandboxes exec -i workspace-pod -c workspace -- python3 -B -u - /tmp/codewire-kind-bridge-renewal-42 900')
      cmp -s - "$ROOT/scripts/ci/verify/kind/bridge_renewal.py" || return 98
      printf '%%s\\n' '{"event":"bridge_renewal_probe"}' ;;
    '--request-timeout=15s -n dev-sandboxes exec workspace-pod -c workspace -- touch /tmp/codewire-kind-bridge-renewal-42'|\\
    '-n dev-sandboxes exec workspace-pod -c workspace -- rm -f /tmp/codewire-kind-bridge-renewal-42') ;;
    *) return 99 ;;
  esac
}
start_kind_credential_bridge_renewal workspace-pod /tmp/codewire-kind-bridge-renewal-42
# The probe starts in the background; the suite stops it minutes later, so
# wait for its exec to be recorded before stopping it here.
for _ in $(seq 1 400); do
  grep -q ' -- python3 ' "$calls" 2>/dev/null && break
  sleep 0.05
done
stop_kind_credential_bridge_renewal workspace-pod /tmp/codewire-kind-bridge-renewal-42 "$KIND_BRIDGE_RENEWAL_PID"
cat "$RUN_DIR/credential-bridge-renewal.jsonl"
''' % directory.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '{"event":"bridge_renewal_probe"}\n')
        calls = (Path(directory.name) / "calls").read_text().splitlines()
        self.assertEqual([call.split(" -- ")[1].split()[0] for call in calls],
                         ["python3", "touch", "rm"])

    def test_bridge_renewal_stop_propagates_probe_and_cleanup_failures(self):
        for probe, touch, remove, expected in (
                (0, 0, 0, 0), (1, 0, 0, 1), (0, 0, 5, 1), (3, 0, 5, 3)):
            with self.subTest(probe=probe, touch=touch, remove=remove):
                result = self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() {
  case "$*" in
    *' touch '*) return %d ;;
    *' rm -f '*) return %d ;;
    *) return 99 ;;
  esac
}
( exit %d ) &
stop_kind_credential_bridge_renewal workspace-pod /tmp/codewire-kind-bridge-renewal-7 $!
''' % (touch, remove, probe))
                self.assertEqual(result.returncode, expected, result.stderr)
        # A probe that cannot be told to stop is asked again, bounded, then its
        # local exec is killed, never left behind.
        directory = tempfile.TemporaryDirectory(prefix="kind-bridge-renewal-stop-")
        self.addCleanup(directory.cleanup)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
calls='%s/calls'
kubectl() { printf '%%s\\n' "$*" >> "$calls"; return 4; }
sleep 30 &
pid=$!
if stop_kind_credential_bridge_renewal workspace-pod /tmp/codewire-kind-bridge-renewal-7 "$pid"; then
  exit 90
fi
kill -0 "$pid" 2>/dev/null && exit 91
exit 0
''' % directory.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("could not stop the bridge renewal probe", result.stderr)
        touch = ("--request-timeout=15s -n dev-sandboxes exec workspace-pod -c workspace -- "
                 "touch /tmp/codewire-kind-bridge-renewal-7")
        self.assertEqual((Path(directory.name) / "calls").read_text().splitlines(),
                         [touch, touch])
        for stop in ("/tmp/other", "/tmp/codewire-kind-bridge-renewal-", "relative",
                     "/tmp/codewire-kind-bridge-renewal-1/../x"):
            with self.subTest(stop=stop):
                result = self.shell('''
SANDBOX_NS=dev-sandboxes
RUN_DIR=/nonexistent
kubectl() { echo unexpected-kubectl >&2; return 99; }
if start_kind_credential_bridge_renewal workspace-pod '%s'; then exit 90; fi
if stop_kind_credential_bridge_renewal workspace-pod '%s' 1; then exit 91; fi
''' % (stop, stop))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("unexpected-kubectl", result.stderr)

    def test_abandoning_the_probe_stops_it_in_the_pod_first_then_kills_the_local_exec(self):
        for touch_status in (0, 4):
            with self.subTest(touch_status=touch_status):
                directory = tempfile.TemporaryDirectory(prefix="kind-bridge-renewal-abandon-")
                self.addCleanup(directory.cleanup)
                result = self.shell('''
SANDBOX_NS=dev-sandboxes
events='%s/events'
kubectl() {
  printf 'kubectl %%s\\n' "$*" >> "$events"
  kill -0 "$pid" 2>/dev/null && printf 'probe alive at touch\\n' >> "$events"
  return %d
}
sleep 30 &
pid=$!
abandon_kind_credential_bridge_renewal workspace-pod /tmp/codewire-kind-bridge-renewal-9 "$pid" || exit 90
kill -0 "$pid" 2>/dev/null && exit 91
exit 0
''' % (directory.name, touch_status))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((Path(directory.name) / "events").read_text().splitlines(), [
                    "kubectl --request-timeout=15s -n dev-sandboxes exec workspace-pod -c workspace"
                    " -- touch /tmp/codewire-kind-bridge-renewal-9",
                    "probe alive at touch",
                ])

    def test_native_flow_runs_the_renewal_probe_across_the_idle_codex_session(self):
        flow = HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1]
        index = flow.index
        start = index('start_kind_credential_bridge_renewal "$pod" "$renewal_stop" || return $?')
        session = index("scripts/ci/verify/kind/codex_session.py")
        stop = index('stop_kind_credential_bridge_renewal "$pod" "$renewal_stop" "$renewal_pid" || return $?')
        rotation = index("assert_kind_credential_rotation")
        renewal = index('assert_kind_credential_bridge_renewal "$RUN_DIR/credential-bridge-renewal.jsonl"')
        counts = index("assert_kind_credential_provider_counts 2")
        self.assertEqual(sorted([start, session, stop, rotation, renewal, counts]),
                         [start, session, stop, rotation, renewal, counts])
        self.assertEqual(flow.count("start_kind_credential_bridge_renewal"), 1)
        trap = flow[:start].rsplit("trap '", 1)[1].split("' EXIT", 1)[0]
        self.assertIn('[ -z "$renewal_pid" ] || abandon_kind_credential_bridge_renewal '
                      '"$pod" "$renewal_stop" "$renewal_pid"', trap)
        self.assertIn('renewal_stop="/tmp/codewire-kind-bridge-renewal-${RANDOM}${RANDOM}"', flow)


class BridgeRenewalProbe(unittest.TestCase):
    STOP = "/tmp/codewire-kind-bridge-renewal-123"

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="kind-bridge-renewal-probe-")
        self.addCleanup(self.scratch.cleanup)
        self.stop = Path(self.scratch.name) / "stop"
        self.outcomes = []
        self.connections = []
        self.sleeps = 0
        def connection(*args, **kwargs):
            result = Mock()
            result.args = (args, kwargs)
            outcome = self.outcomes.pop(0) if self.outcomes else 403
            if isinstance(outcome, BaseException):
                result.request.side_effect = outcome
            else:
                result.getresponse.return_value.status = outcome
                result.getresponse.return_value.read.return_value = b"CW_SECRET_BODY_CANARY"
            self.connections.append(result)
            return result
        def sleep(seconds):
            self.assertEqual(seconds, RENEWAL.INTERVAL)
            self.sleeps += 1
            if self.sleeps >= self.stop_after:
                self.stop.touch()
        self.stop_after = 3
        for fixture in (
            patch.object(RENEWAL.http.client, "HTTPConnection", side_effect=connection),
            patch.object(RENEWAL.time, "sleep", side_effect=sleep),
        ):
            fixture.__enter__()
            self.addCleanup(fixture.__exit__, None, None, None)

    def test_requests_use_the_daemon_loopback_and_an_unselected_fixed_route(self):
        result = RENEWAL.run(str(self.stop), 60)
        self.assertEqual((result["requests"], result["statuses"]), (3, {"403": 3}))
        self.assertGreaterEqual(result["ended_unix_ms"], result["started_unix_ms"])
        for connection in self.connections:
            self.assertEqual(connection.args, (("127.0.0.1", 38081), {"timeout": 20}))
            request = connection.request.call_args
            self.assertEqual(request.args, ("POST", "/v1/messages"))
            self.assertEqual(request.kwargs["headers"],
                             {"Host": "localhost", "Content-Type": "application/json"})
            self.assertNotIn("Authorization", request.kwargs["headers"])
            connection.close.assert_called_once()

    def test_every_status_and_transport_failure_is_counted(self):
        self.stop_after = 6
        self.outcomes = [403, 503, OSError("synthetic"), http.client.RemoteDisconnected("x"),
                         403, 502]
        result = RENEWAL.run(str(self.stop), 60)
        self.assertEqual(result["requests"], 6)
        self.assertEqual(result["statuses"], {"403": 2, "503": 1, "error": 2, "502": 1})

    def test_the_bound_stops_the_loop_without_a_stop_file(self):
        self.stop_after = 10**9
        ticks = iter(range(0, 10**6, 7))
        with patch.object(RENEWAL.time, "monotonic", side_effect=lambda: next(ticks)):
            result = RENEWAL.run(str(self.stop), 30)
        self.assertEqual(result["requests"], 4)
        self.assertFalse(self.stop.exists())

    def test_an_existing_stop_file_sends_nothing(self):
        self.stop.touch()
        result = RENEWAL.run(str(self.stop), 60)
        self.assertEqual((result["requests"], result["statuses"]), (0, {}))
        self.assertEqual(self.connections, [])

    def test_arguments_are_closed(self):
        with patch.object(RENEWAL.os.path, "lexists", return_value=False):
            self.assertEqual(RENEWAL.arguments(["probe", self.STOP, "1200"]), (self.STOP, 1200))
            for argv in (
                    ["probe", self.STOP],
                    ["probe", self.STOP, "1200", "extra"],
                    ["probe", "/tmp/other", "1200"],
                    ["probe", self.STOP + "/../x", "1200"],
                    ["probe", "/tmp/codewire-kind-bridge-renewal-1234567890123", "1200"],
                    ["probe", self.STOP, "0"],
                    ["probe", self.STOP, "1801"],
                    ["probe", self.STOP, "-5"],
                    ["probe", self.STOP, "012"],
                    ["probe", self.STOP, "1e3"]):
                with self.subTest(argv=argv):
                    with self.assertRaises(RENEWAL.Failure):
                        RENEWAL.arguments(argv)
        with patch.object(RENEWAL.os.path, "lexists", return_value=True):
            with self.assertRaises(RENEWAL.Failure):
                RENEWAL.arguments(["probe", self.STOP, "1200"])

    def test_main_prints_one_closed_event_and_never_a_response(self):
        output = io.StringIO()
        with patch.object(RENEWAL, "arguments", return_value=(str(self.stop), 60)), \
                contextlib.redirect_stdout(output):
            self.assertEqual(RENEWAL.main(["probe", self.STOP, "60"]), 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        event = json.loads(lines[0])
        self.assertEqual(sorted(event), ["ended_unix_ms", "event", "requests",
                                         "started_unix_ms", "statuses"])
        self.assertEqual((event["event"], event["statuses"]), ("bridge_renewal_probe", {"403": 3}))
        self.assertNotIn("CANARY", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(RENEWAL.main(["probe", "/tmp/other", "60"]), 1)
        self.assertEqual(output.getvalue(), '{"event":"bridge_renewal_probe_failed"}\n')


if __name__ == "__main__":
    unittest.main()
