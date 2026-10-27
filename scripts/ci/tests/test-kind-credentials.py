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
import shlex
import subprocess
import sys
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
DAEMON_SPEC = importlib.util.spec_from_file_location(
    "daemon_probe", ROOT / "scripts/ci/verify/kind/daemon_probe.py")
DAEMON = importlib.util.module_from_spec(DAEMON_SPEC)
DAEMON_SPEC.loader.exec_module(DAEMON)
CLAUDE_SPEC = importlib.util.spec_from_file_location(
    "claude_session", ROOT / "scripts/ci/verify/kind/claude_session.py")
CLAUDE = importlib.util.module_from_spec(CLAUDE_SPEC)
CLAUDE_SPEC.loader.exec_module(CLAUDE)
PROVIDER = ROOT / "crates/codewire-credential-service/src/runtime/kind/provider.rs"
ENVIRONMENT = "86fb3daa-dde0-4fb4-bf83-6e2399d78a5f"
WORKSPACE_UID = "57f35d02-39f9-40ed-b9e1-bc4a64ad3b0e"
RELAY_UID = "65d41c9c-510b-4c8a-961d-338a879c1fa4"
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
        self.output = io.StringIO()
        self.managed()
        for fixture in (
            patch.object(PROBE, "CODEX_HOME", self.home),
            patch.dict(os.environ, {"CODEX_HOME": str(self.home),
                                   "CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"}, clear=True),
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

    def events(self):
        return [json.loads(line) for line in self.output.getvalue().splitlines()]

    def test_probe_makes_no_request_and_reads_no_capability(self):
        source = (ROOT / "scripts/ci/verify/kind/credential_probe.py").read_text()
        for absent in ("http.client", "ssl", "socket", "/run/codewire-credentials", "Authorization"):
            self.assertNotIn(absent, source)

    def test_current_selected_loopback_configuration_needs_no_ca_override(self):
        PROBE.probe("selected")
        self.assertNotIn("CODEX_CA_CERTIFICATE", os.environ)
        self.assertEqual(self.events(), [{"event": "credential_projection", "mode": "selected"}])

    def test_initial_unselected_configuration_needs_no_codex_settings(self):
        self.unselected()
        PROBE.probe("unselected")
        self.assertEqual(self.events(), [{"event": "credential_projection", "mode": "unselected"}])

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
                PROBE.probe("selected")

    def test_a_login_that_is_not_codewires_fails(self):
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
                    PROBE.probe("selected")
        self.assertEqual(self.output.getvalue(), "")

    def test_provider_auth_file_or_environment_fail(self):
        (self.home / "auth.json").write_text("synthetic", encoding="ascii")
        with self.assertRaises(ValueError):
            PROBE.probe("selected")
        (self.home / "auth.json").unlink()
        os.environ["SYNTHETIC_FIXTURE"] = "CW_KIND_SYNTHETIC_REFRESH_private"
        with self.assertRaises(ValueError):
            PROBE.probe("selected")
        self.assertEqual(self.output.getvalue(), "")

    def test_projection_is_not_caller_overridable(self):
        for mode in ("unknown", "success", "revoked", "unbound", "missing", "wrong-root"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "^selection$"):
                PROBE.probe(mode)
        os.environ["CODEX_CA_CERTIFICATE"] = "/synthetic/other-roots"
        with self.assertRaises(ValueError):
            PROBE.probe("selected")
        self.assertEqual(self.output.getvalue(), "")

    def test_selected_probe_requires_exact_current_selection(self):
        for selection in (None, "", "v1:none", "v1:openai", "codex", "v1:codex,openai"):
            with self.subTest(selection=selection), patch.dict(os.environ, clear=True):
                os.environ["CODEX_HOME"] = str(self.home)
                if selection is not None:
                    os.environ["CODEWIRE_MANAGED_CREDENTIAL_CLIENTS"] = selection
                with self.assertRaisesRegex(ValueError, "^projection$"):
                    PROBE.probe("selected")
        with patch.dict(os.environ, {"CODEX_HOME": "/synthetic/other-home"}):
            with self.assertRaisesRegex(ValueError, "^projection$"):
                PROBE.probe("selected")

    def test_identity_free_selection_is_the_daemon_written_config_alone(self):
        os.environ.pop("CODEX_HOME")
        os.environ.pop("CODEWIRE_MANAGED_CREDENTIAL_CLIENTS")
        PROBE.probe("selected")
        for first_line in ("", "model = \"gpt-5\"", " " + PROBE.MANAGED_HEADER.decode()):
            with self.subTest(first_line=first_line):
                self.managed(first_line)
                with self.assertRaisesRegex(ValueError, "^projection$"):
                    PROBE.probe("selected")
        # A delivered login removes Codewire's config.toml; absence is fine.
        (self.home / "config.toml").unlink()
        PROBE.probe("selected")
        outside = self.home / "outside.toml"
        outside.write_text(PROBE.MANAGED_HEADER.decode() + "\n")
        (self.home / "config.toml").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "^projection$"):
            PROBE.probe("selected")

    def test_unselected_probe_rejects_stale_client_configuration(self):
        self.unselected()
        for values in ({"CODEX_HOME": str(self.home)},
                       {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:codex"},
                       {"CODEWIRE_MANAGED_CREDENTIAL_CLIENTS": "v1:none"}):
            with self.subTest(values=values), patch.dict(os.environ, values, clear=True):
                with self.assertRaisesRegex(ValueError, "^unexpected-unselected-client$"):
                    PROBE.probe("unselected")
        (self.home / "config.toml").write_text("synthetic-stale-client", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "^unexpected-unselected-client$"):
            PROBE.probe("unselected")
        self.assertEqual(self.output.getvalue(), "")

    def test_legacy_ca_override_is_rejected_in_selected_and_unselected_modes(self):
        for mode in ("selected", "unselected"):
            if mode == "unselected":
                self.unselected()
            for value in ("", "/run/codewire-credentials/other-roots/ca.crt",
                          "/synthetic/other-roots"):
                with self.subTest(mode=mode, value=value), patch.dict(
                        os.environ, {"CODEX_CA_CERTIFICATE": value}):
                    with self.assertRaisesRegex(ValueError, "^projection$"):
                        PROBE.probe(mode)
        self.assertEqual(self.output.getvalue(), "")

    def test_unselected_probe_retains_provider_leak_rejections(self):
        self.unselected()
        for value in ("CW_KIND_SYNTHETIC_REFRESH_private", "synthetic-kind-signature"):
            with patch.dict(os.environ, {"SYNTHETIC_FIXTURE": value}):
                with self.assertRaisesRegex(ValueError, "^provider-environment-exposure$"):
                    PROBE.probe("unselected")
        (self.home / "auth.json").write_text("synthetic", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "^unexpected-provider-auth-file$"):
            PROBE.probe("unselected")
        self.assertEqual(self.output.getvalue(), "")


class HarnessGuards(unittest.TestCase):
    @staticmethod
    def session_events():
        return [
            {"event": "baseline_completed", "codex_processes": 1, "legacy_auth_commands": 0},
            {"event": "projected_token_rotated", "changed": True, "rotated_ms": 471000,
             "fresh_admission": True, "elapsed_ms": 478000},
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
                 "relay_pod_uid": RELAY_UID, "auth_sequence": 1,
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
log() { printf '[kind-e2e] %%s\\n' "$*"; }
kind_credential_fixture_events() { printf '%%s\\n' '%s'; }
assert_kind_credential_rotation '%s' 2 '%s' '%s' '%s'
''' % (self.rotation_directory, json.dumps(events), ENVIRONMENT, WORKSPACE_UID, RELAY_UID, path))

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
                                 "workspace_pod_uid": WORKSPACE_UID, "relay_pod_uid": RELAY_UID},
                    "events": events,
                })

    def test_rotation_evidence_excludes_unknown_fields_and_malformed_values(self):
        events = self.rotation_events()
        for event in events:
            event["message"] = "synthetic-do-not-save"
            event["unknown_material"] = {"nested": "synthetic-do-not-save"}
        events[0].update(environment_id="synthetic-do-not-save", generation="synthetic-do-not-save",
                         workspace_pod_uid=["synthetic-do-not-save"], relay_pod_uid=None,
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
''' % (directory, ENVIRONMENT, WORKSPACE_UID, RELAY_UID))
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = [Path(path) for path in result.stdout.splitlines()]
            self.assertEqual(len(set(paths)), 2)
            self.assertEqual(json.loads(paths[0].read_text())["expected"], {
                "environment_id": None, "generation": None,
                "workspace_pod_uid": None, "relay_pod_uid": None,
            })
            self.assertEqual(json.loads(paths[1].read_text())["expected"]["environment_id"], ENVIRONMENT)

    def test_rotation_evidence_write_failure_cannot_reach_acceptance(self):
        with tempfile.TemporaryDirectory(prefix="kind-rotation-write-") as directory:
            result = self.shell('''
RUN_DIR='%s'
kind_credential_fixture_events() { printf '[]'; }
mktemp() { return 38; }
assert_kind_credential_rotation '%s' 2 '%s' '%s' /not-a-session
''' % (directory, ENVIRONMENT, WORKSPACE_UID, RELAY_UID))
            self.assertEqual(result.returncode, 38, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_rotation_collector_failure_cannot_pass_or_emit_evidence(self):
        with tempfile.TemporaryDirectory(prefix="kind-rotation-collector-") as directory:
            result = self.shell('''
RUN_DIR='%s'
kind_credential_fixture_events() { printf '[]'; return 37; }
assert_kind_credential_rotation '%s' 2 '%s' '%s' /not-a-session
''' % (directory, ENVIRONMENT, WORKSPACE_UID, RELAY_UID))
            self.assertEqual(result.returncode, 37, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_rotation_requires_composed_token_time_authentication_and_stock_turn_proof(self):
        result = self.rotation_proof(self.rotation_events())
        self.assertEqual(result.returncode, 0, result.stderr)
        # Only the closed evidence line: times, never fixture values.
        self.assertEqual(result.stdout, "[kind-e2e] projected workspace token replaced 471s after "
                         "the baseline; idle ended at 478s on a fresh-token admission\n")

    def test_initial_unbound_auth_is_not_selected_epoch_evidence(self):
        # A queued source restart legitimately retains its workflow generation.
        # Its old unbound Pod pair must not join the replacement Pod journey.
        for generation in (1, 2):
            events = self.rotation_events()
            first = dict(events[0], generation=generation, workspace_pod_uid=ENVIRONMENT,
                         relay_pod_uid=ENVIRONMENT)
            for event in events:
                if event["event"] == "bridge_authenticated":
                    event["auth_sequence"] += 1
            with self.subTest(generation=generation):
                result = self.rotation_proof([first, *events])
                self.assertEqual(result.returncode, 0, result.stderr)
                events[2]["workspace_token_changed"] = False
                self.assertNotEqual(self.rotation_proof([first, *events]).returncode, 0)

    def test_identity_or_generation_change_after_selection_cannot_be_filtered_out(self):
        for changes in ({"workspace_pod_uid": ENVIRONMENT}, {"relay_pod_uid": ENVIRONMENT},
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
                        {"workspace_pod_uid": ENVIRONMENT}, {"relay_pod_uid": ENVIRONMENT},
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

    def admission_watch(self, events, relay=None):
        directory = tempfile.TemporaryDirectory(prefix="kind-admission-watch-")
        self.addCleanup(directory.cleanup)
        calls = Path(directory.name) / "calls"
        relay_log = Path(directory.name) / "relay.log"
        if relay is None:
            relay = [self.relay_decision("credential_bridge_epoch_overlap")]
        relay_log.write_text("".join(json.dumps(line) + "\n" for line in relay) + "not json\n")
        result = self.shell('''
NS=codewire
SANDBOX_NS=dev-sandboxes
KIND_ADMISSION_WATCH_SECONDS=1
sleep() { :; }
kind_credential_fixture_events() { printf '%%s\\n' '%s'; }
kubectl() {
  case "$*" in
    "-n codewire logs pod/relay-pod -c orchestration") cat '%s' ;;
    *) printf '%%s\\n' "$*" >> '%s' ;;
  esac
}
watch_kind_credential_fresh_admission '%s' workspace-pod relay-pod /tmp/codewire-kind-fresh-admission-7
''' % (json.dumps(events), relay_log, calls, ENVIRONMENT))
        return result.returncode, calls.read_text() if calls.exists() else ""

    @staticmethod
    def relay_decision(event, environment=ENVIRONMENT):
        return {"timestamp": "2026-10-15T14:02:26.072995Z", "level": "INFO",
                "fields": {"event": event, "environment_id": environment},
                "target": "codewire_orchestration::worker::credential_relay::epoch"}

    def test_the_admission_mark_follows_only_a_fresh_token_after_baseline(self):
        baseline = {"event": "provider_response", "scenario": "baseline", "attempt": 1,
                    "status": 200, "response_calls": 1, "refresh_calls": 0}
        def auth(environment=ENVIRONMENT, changed=True):
            return {"event": "bridge_authenticated", "environment_id": environment,
                    "workspace_token_changed": changed}
        self.assertEqual(self.admission_watch([auth(changed=False), baseline, auth()]), (
            0, "-n dev-sandboxes exec workspace-pod -c workspace -- "
               "touch /tmp/codewire-kind-fresh-admission-7\n"))
        for events in ([auth(), baseline], [baseline, auth(changed=False)],
                       [baseline, auth(environment=WORKSPACE_UID)], [auth()]):
            with self.subTest(events=events):
                self.assertEqual(self.admission_watch(events), (1, ""))

    def test_the_admission_mark_waits_for_the_relay_to_admit_its_successor(self):
        # Run 14359: the broker authenticated the replaced workspace token, but
        # the relay refused that successor until kubelet replaced its own token.
        events = [{"event": "provider_response", "scenario": "baseline", "attempt": 1,
                   "status": 200, "response_calls": 1, "refresh_calls": 0},
                  {"event": "bridge_authenticated", "environment_id": ENVIRONMENT,
                   "workspace_token_changed": True}]
        overlap = self.relay_decision("credential_bridge_epoch_overlap")
        refused = self.relay_decision("credential_bridge_successor_refused")
        marked = (0, "-n dev-sandboxes exec workspace-pod -c workspace -- "
                     "touch /tmp/codewire-kind-fresh-admission-7\n")
        self.assertEqual(self.admission_watch(events, [refused, refused, overlap]), marked)
        for relay in ([], [refused], [overlap, refused],
                      [self.relay_decision("credential_bridge_epoch_admitted")],
                      [self.relay_decision("credential_bridge_epoch_overlap", WORKSPACE_UID)],
                      [refused, self.relay_decision("credential_bridge_epoch_overlap",
                                                    WORKSPACE_UID)],
                      [dict(overlap, target="codewire_orchestration::worker::other")]):
            with self.subTest(relay=relay):
                self.assertEqual(self.admission_watch(events, relay), (1, ""))

    def test_rotation_ends_at_an_admission_mark_or_else_past_the_epoch_bound(self):
        for changes in ({}, {"fresh_admission": False, "rotated_ms": 590000, "elapsed_ms": 600001}):
            session = self.session_events()
            session[1].update(changes)
            with self.subTest(changes=changes):
                result = self.rotation_proof(self.rotation_events(), session)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_authentication_alone_cannot_replace_rotation_duration_or_failed_terminal(self):
        for index, changes in ((0, {"codex_processes": 2}), (0, {"legacy_auth_commands": 1}),
                               (1, {"changed": False}), (1, {"elapsed_ms": 30001}),
                               (1, {"elapsed_ms": 720000}), (1, {"rotated_ms": 479000}),
                               (1, {"rotated_ms": -1}), (1, {"rotated_ms": None}),
                               # Without the fixture's admission mark the epoch bound must pass.
                               (1, {"fresh_admission": False}),
                               (1, {"fresh_admission": False, "elapsed_ms": 600000}),
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
        for baseline in (2, 3, 6, 12, 15, 64, 65, 130, 256):
            with self.subTest(baseline=baseline):
                result = self.provider_counts(self.provider_events(baseline), baseline)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "")
        for baseline, events in ((5, 4), (5, 3), (3, 5), (6, 5), (12, 11), (12, 13), (6, 12)):
            with self.subTest(baseline=baseline, events=events):
                self.assertNotEqual(
                    self.provider_counts(self.provider_events(events), baseline).returncode, 0)
        # A baseline outside the session's own count or the journey's bound.
        for baseline in (1, 257):
            with self.subTest(baseline=baseline):
                self.assertNotEqual(
                    self.provider_counts(self.provider_events(baseline), baseline).returncode, 0)

    @staticmethod
    def reuse_lines(presented=(2, 2, 0), caches=("miss", "hit", "miss"), admitted_at=None,
                    gap=1.5, total_ms=40, authorities=("evaluated", "reused", "evaluated"),
                    record_reads=1):
        """The daemon epoch, admitted at 5 s: its warm-up (attempt 3) at 10 s,
        its reuse `gap` later, and the request after Reconnect at 20 s +
        `gap`, with another epoch admission at `admitted_at` seconds if
        given."""
        fixture = [{"target": "codewire_kind_credential_fixture", "fields": {
            "event": "provider_response", "scenario": "baseline", "attempt": attempt,
            "status": 200, "generation": generation, "response_calls": attempt + 4,
            "refresh_calls": 2}} for attempt, generation in zip((3, 4, 5), presented)]
        def at(seconds):
            whole, fraction = divmod(round(seconds * 1_000_000), 1_000_000)
            return f"2026-10-04T00:{whole // 60:02d}:{whole % 60:02d}.{fraction:06d}Z"
        def timed(cache, seconds, authority="evaluated"):
            read = 0 if cache == "hit" else 1
            evaluated = int(authority != "reused")
            return {"timestamp": at(seconds), "target": "codewire_credential_broker::timing",
                    "fields": {"event": "proxied_request", "slot": "codex", "route": "openai-api",
                               "outcome": "response", "status": 200, "cache": cache,
                               "total_ms": total_ms, "material_reads": read, "unwraps": read,
                               "authority": authority, "record_reads": record_reads,
                               "authority_checks": evaluated, "grant_evaluations": evaluated,
                               "resolves": evaluated}}
        def admission(seconds):
            return {"timestamp": at(seconds), "target": "codewire_credential_broker::timing",
                    "fields": {"event": "epoch_admission", "outcome": "admitted"}}
        timeline = [(5, admission(5)),
                    (10, fixture[0]), (10, timed(caches[0], 10, authorities[0])),
                    (10 + gap, fixture[1]), (10 + gap, timed(caches[1], 10 + gap, authorities[1])),
                    (20 + gap, fixture[2]), (20 + gap, timed(caches[2], 20 + gap, authorities[2]))]
        if admitted_at is not None:
            timeline.append((admitted_at, admission(admitted_at)))
        return [line for _, line in sorted(timeline, key=lambda item: item[0])]

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

    def test_material_reuse_requires_a_real_hit_on_one_epoch_then_the_reconnected_login(self):
        result = self.material_reuse(self.reuse_lines())
        self.assertEqual(result.returncode, 0, result.stderr)
        # The warm-up may reuse a decision that reaches its minute before the
        # reuse, which then evaluates again; its login is still reused.
        for authorities in (("reused", "reused", "evaluated"),
                            ("reused", "evaluated", "evaluated")):
            with self.subTest(authorities=authorities):
                result = self.material_reuse(self.reuse_lines(authorities=authorities))
                self.assertEqual(result.returncode, 0, result.stderr)
        # A new epoch admitted before the warm-up or after the last request is
        # outside the window.
        for admitted_at in (9.9, 30):
            with self.subTest(admitted_at=admitted_at):
                result = self.material_reuse(self.reuse_lines(admitted_at=admitted_at))
                self.assertEqual(result.returncode, 0, result.stderr)
        # A new epoch admitted inside the window fails, whatever was reused:
        # it would make the reuse proof vacuous.
        for caches in (("miss", "miss", "miss"), ("miss", "hit", "miss")):
            for admitted_at in (10.5, 15):
                with self.subTest(caches=caches, admitted_at=admitted_at):
                    result = self.material_reuse(self.reuse_lines(caches=caches,
                                                                  admitted_at=admitted_at))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("admitted inside the material reuse window", result.stderr)
        for lines in (
                # No reuse, even when the reuse came too late to be one.
                self.reuse_lines(caches=("miss", "miss", "miss")),
                self.reuse_lines(caches=("miss", "miss", "miss"), gap=125),
                self.reuse_lines(caches=("miss", "hit", "miss"), gap=119.97),
                self.reuse_lines(caches=("hit", "hit", "miss")),
                # A reuse after Reconnect, or the old login presented.
                self.reuse_lines(caches=("miss", "hit", "hit")),
                self.reuse_lines(presented=(2, 2, 2)),
                self.reuse_lines(presented=(0, 0, 0)),
                self.reuse_lines(presented=(2, 1, 0)),
                # The reuse resolved authority right after an evaluation, or
                # read more than its record; Reconnect reused the decision.
                self.reuse_lines(authorities=("evaluated", "evaluated", "evaluated")),
                self.reuse_lines(authorities=("evaluated", "none", "evaluated")),
                self.reuse_lines(record_reads=2),
                self.reuse_lines(authorities=("evaluated", "reused", "reused")),
                # A reused label on a line that still resolved authority.
                [dict(line, fields=dict(line["fields"], resolves=1))
                 if line.get("fields", {}).get("cache") == "hit" else line
                 for line in self.reuse_lines()],
                # The provider never saw the login presented after Reconnect.
                [line for line in self.reuse_lines()
                 if line.get("fields", {}).get("attempt") != 5]):
            with self.subTest(lines=lines):
                result = self.material_reuse(lines)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("reused a login after Reconnect", result.stderr)
                self.assertNotIn("jq: error", result.stderr)

    # The authority journey's probes in order: (mode, final status, requests,
    # bound). Changes are polled within the bound; a `sandbox_replaced` record
    # precedes the replaced Pod's first request. Request numbers: 1, 2 served;
    # 3 the role change's refusal; 4 its restore; 5 served; 6 the rebind's
    # refusal; 7 its restore; 8 served; 9 the replaced Pod's first; 10 revoked.
    WITHIN = 65000
    JOURNEY = (("success", 200, 1, None), ("success", 200, 1, None),
               ("denied", 403, 1, WITHIN), ("success", 200, 1, WITHIN),
               ("success", 200, 1, None), ("denied", 403, 1, WITHIN),
               ("success", 200, 1, WITHIN), ("success", 200, 1, None),
               ("sandbox_replaced", None, 0, None),
               ("success", 200, 1, None), ("revoked", 403, 1, None))

    @classmethod
    def authority_lines(cls, journey=None, outcomes=None, admitted_before=(), waited=40,
                        earlier=3, replaced_admission=True):
        """`earlier` codex requests before the journey, then the journey's
        requests as its probes saw them and as the decision path logs them,
        with an admission before the journey request numbers in
        `admitted_before` and, unless `replaced_admission` is false, before a
        replaced Pod's first request; `outcomes` overrides logged fields by
        journey request number."""
        journey = list(cls.JOURNEY if journey is None else journey)
        outcomes = outcomes or {}
        probes, statuses = [], []
        replaced = False
        for mode, status, requests, within in journey:
            if mode in ("sandbox_replaced", "epoch_renewed"):
                probes.append({"event": mode})
                replaced = True
                continue
            served = 0
            for _ in range(requests - 1):
                before = 403 if status == 200 else 200
                statuses.append((before, "before", False, False))
                served += before == 200
            statuses.append((status, mode, within is not None, replaced))
            replaced = False
            served += status == 200
            probes.append({"event": "daemon_probe", "mode": mode, "status": status,
                           "requests": requests, "served": served,
                           "waited_ms": waited if within else 30, "within_ms": within})
        if replaced_admission:
            first = [number for number, entry in enumerate(statuses, start=1) if entry[3]]
            admitted_before = tuple(admitted_before) + tuple(first)
        def timed(fields):
            return {"timestamp": "2026-10-04T01:00:00.000000Z",
                    "target": "codewire_credential_broker::timing",
                    "fields": {"event": "proxied_request", "slot": "codex",
                               "route": "openai-api", "total_ms": 40, **fields}}
        lines = [timed({"outcome": "response", "status": 200}) for _ in range(earlier)]
        reused = {"authority": "reused", "authority_checks": 0, "resolves": 0,
                  "grant_evaluations": 0, "record_reads": 1, "cache": "hit",
                  "material_reads": 0, "unwraps": 0}
        evaluated = {"authority": "evaluated", "authority_checks": 1, "resolves": 1,
                     "grant_evaluations": 1, "record_reads": 1, "cache": "miss",
                     "material_reads": 1, "unwraps": 1}
        for number, (status, mode, change, first) in enumerate(statuses, start=1):
            if number in admitted_before:
                lines.append({"timestamp": "2026-10-04T01:00:00.000000Z",
                              "target": "codewire_credential_broker::timing",
                              "fields": {"event": "epoch_admission", "outcome": "admitted"}})
            if status == 200:
                # A repeated request, or one served while a refusal is
                # awaited, reuses the decision; a restore or a new epoch's
                # first request evaluates it and reads the login again.
                fields = {"outcome": "response", "status": 200,
                          **(evaluated if change or first else reused)}
            elif mode == "revoked":
                # The fixed 403 Reconnect explanation, as the service logs it.
                fields = {"outcome": "response", "status": 403, "authority": "evaluated"}
            else:
                fields = {"outcome": "denied", "status": 0, "authority": "evaluated"}
            fields.update(outcomes.get(number, {}))
            lines.append(timed(fields))
        return lines, probes

    def authority_changes(self, lines, probes, earlier=3, login_check_seconds=None):
        directory = tempfile.TemporaryDirectory(prefix="kind-authority-changes-")
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "probes.jsonl"
        path.write_text("".join(json.dumps(probe) + "\n" for probe in probes))
        logs = "\n".join(json.dumps(line) for line in lines)
        return self.shell('''
NS=codewire-e2e
kubectl() {
  [ "$*" = '-n codewire-e2e logs deployment/codewire-credential-service -c credential-service' ] ||
    return 99
  printf '%%s\\n' '%s'
}
assert_kind_credential_authority_changes %d '%s' %s
''' % (logs, earlier, path, "" if login_check_seconds is None else login_check_seconds))

    def test_authority_changes_reach_the_connected_epoch_within_the_bound(self):
        result = self.authority_changes(*self.authority_lines())
        self.assertEqual(result.returncode, 0, result.stderr)
        accepted = []
        # A change may take effect after some served requests, within the
        # bound, and a restore after some denied ones.
        slow = list(self.JOURNEY)
        slow[2] = ("denied", 403, 61, self.WITHIN)
        slow[3] = ("success", 200, 2, self.WITHIN)
        accepted.append(self.authority_lines(slow, waited=64999))
        # A restore, or a request between changes, may cross a new epoch.
        accepted.append(self.authority_lines(admitted_before=(4, 5)))
        # A request served while a refusal is awaited may read the login again
        # once per change: a full-check lease the same change refuses, such as
        # the daemon's Codex login check, clears the epoch's material cache.
        reread = {"cache": "miss", "material_reads": 1, "unwraps": 1}
        accepted.append(self.authority_lines(slow, outcomes={10: reread, 40: reread}))
        # A replaced Pod's first request may reuse its new epoch's admission.
        accepted.append(self.authority_lines(outcomes={9: {"authority": "reused",
                                                           "record_reads": 1}}))
        # A rebind's restore is refused from the decision until it ages out.
        late = list(self.JOURNEY)
        late[6] = ("success", 200, 40, self.WITHIN)
        accepted.append(self.authority_lines(
            late, waited=40000,
            outcomes={number: {"authority": "reused"} for number in range(7, 46)}))
        for lines, probes in accepted:
            with self.subTest(probes=probes):
                result = self.authority_changes(lines, probes)
                self.assertEqual(result.returncode, 0, result.stderr)
        rejected = []
        # A refusal or the revocation that landed on a new epoch, not the
        # connected one, or a replaced Pod that admitted no new epoch.
        for number in (3, 6, 10):
            rejected.append(self.authority_lines(admitted_before=(number,)))
        rejected.append(self.authority_lines(slow, admitted_before=(63,)))
        rejected.append(self.authority_lines(replaced_admission=False))
        # A change that took longer than the bound.
        rejected.append(self.authority_lines(waited=65001))
        # The service saw something else than the probe.
        for number, outcome in ((3, {"outcome": "response", "status": 200}),
                                (3, {"outcome": "response", "status": 403}),
                                (10, {"outcome": "denied", "status": 0}),
                                (10, {"outcome": "response", "status": 200}),
                                (1, {"outcome": "denied", "status": 0}),
                                (6, {"outcome": "response", "status": 200})):
            rejected.append(self.authority_lines(outcomes={number: outcome}))
        # A repeated request that resolved authority, read more than its
        # record, or read material; a refusal, restore or revocation that
        # reused a decision; a replaced Pod whose first request was warm.
        for number, outcome in ((1, {"authority": "evaluated"}),
                                (2, {"resolves": 1}),
                                (2, {"authority_checks": 1}),
                                (5, {"grant_evaluations": 1}),
                                (5, {"record_reads": 2}),
                                (8, {"cache": "miss", "material_reads": 1, "unwraps": 1}),
                                (3, {"authority": "reused"}),
                                (4, {"authority": "reused"}),
                                (10, {"authority": "reused"}),
                                (9, {"cache": "hit"})):
            rejected.append(self.authority_lines(outcomes={number: outcome}))
        # A request served while the role change was awaited that evaluated,
        # or more re-reads of the login than changes.
        rejected.append(self.authority_lines(slow, outcomes={4: {"authority": "evaluated"}}))
        rejected.append(self.authority_lines(
            slow, outcomes={number: reread for number in (10, 20, 30)}))
        rejected.append(self.authority_lines(
            slow, outcomes={10: dict(reread, material_reads=2)}))
        # A missing or extra request, or a replacement record without a request.
        lines, probes = self.authority_lines()
        rejected.append((lines[:-1], probes))
        rejected.append((lines + lines[-1:], probes))
        rejected.append((lines, probes[:-1]))
        rejected.append((lines, probes + [{"event": "sandbox_replaced"}]))
        rejected.append((lines, []))
        for lines, probes in rejected:
            with self.subTest(probes=probes):
                result = self.authority_changes(lines, probes)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("did not reach the connected daemon epoch in time", result.stderr)
                # A rejection, never a jq failure that would reject anything.
                self.assertNotIn("jq: error", result.stderr)
        # The journey starts after the requests before it.
        lines, probes = self.authority_lines(earlier=5)
        self.assertEqual(self.authority_changes(lines, probes, earlier=5).returncode, 0)
        self.assertNotEqual(self.authority_changes(lines, probes, earlier=4).returncode, 0)

    def test_a_recorded_epoch_renewal_starts_the_next_change_on_a_warm_epoch(self):
        # The journey waited for the relay's next admission before a change
        # (#2574): the record, then one plain request, cold on the new epoch.
        for at in (2, 5):
            journey = list(self.JOURNEY)
            journey[at:at] = [("epoch_renewed", None, 0, None), ("success", 200, 1, None)]
            with self.subTest(at=at):
                lines, probes = self.authority_lines(journey)
                result = self.authority_changes(lines, probes)
                self.assertEqual(result.returncode, 0, result.stderr)
                # The record without an admitted epoch, or a warm first request.
                lines, probes = self.authority_lines(journey, replaced_admission=False)
                self.assertNotEqual(self.authority_changes(lines, probes).returncode, 0)
                lines, probes = self.authority_lines(journey, outcomes={at + 1: {"cache": "hit"}})
                self.assertNotEqual(self.authority_changes(lines, probes).returncode, 0)
        # An admission no record explains still fails a plain request after it.
        lines, probes = self.authority_lines(
            admitted_before=(5,), outcomes={5: {"cache": "miss", "material_reads": 1, "unwraps": 1}})
        self.assertNotEqual(self.authority_changes(lines, probes).returncode, 0)

    def test_login_rereads_are_bounded_by_the_daemons_check_period(self):
        slow = list(self.JOURNEY)
        slow[2] = ("denied", 403, 61, self.WITHIN)
        reread = {"cache": "miss", "material_reads": 1, "unwraps": 1}
        three = self.authority_lines(slow, outcomes={number: reread for number in (10, 30, 50)})
        seven = self.authority_lines(
            slow, outcomes={number: reread for number in (5, 10, 20, 30, 40, 50, 60)})
        # Production's 120 seconds: one check, so one re-read, per change.
        self.assertNotEqual(self.authority_changes(*three).returncode, 0)
        self.assertNotEqual(self.authority_changes(*three, login_check_seconds=120).returncode, 0)
        # Kind's 30 seconds: up to three checks fall inside a 65-second window.
        result = self.authority_changes(*three, login_check_seconds=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.authority_changes(*seven, login_check_seconds=30).returncode, 0)
        for invalid in (0, 5, 1000, "x"):
            with self.subTest(invalid=invalid):
                self.assertNotEqual(
                    self.authority_changes(*three, login_check_seconds=invalid).returncode, 0)

    @staticmethod
    def epoch_line(at_ms, event, environment=ENVIRONMENT, **fields):
        stamp = datetime.fromtimestamp(at_ms // 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        return json.dumps({
            "timestamp": "%s.%03d123Z" % (stamp, at_ms % 1000), "level": "INFO",
            "target": "codewire_orchestration::worker::credential_relay::epoch",
            "fields": {"event": event, "environment_id": environment, **fields}})

    def epoch_shell(self, lines, body, later=()):
        directory = tempfile.TemporaryDirectory(prefix="kind-epoch-headroom-")
        self.addCleanup(directory.cleanup)
        log = Path(directory.name) / "relay.log"
        log.write_text("".join(line + "\n" for line in lines))
        later_log = Path(directory.name) / "later.log"
        later_log.write_text("".join(line + "\n" for line in later))
        return self.shell('''
NS=codewire-e2e
NOW_MS=%d
log() { printf '[kind-e2e] %%s\\n' "$*"; }
date() { printf '%%s\\n' "$NOW_MS"; }
# Each poll's sleep is when the relay logs what happens later.
sleep() { cat '%s' >> '%s'; : > '%s'; }
kubectl() {
  [ "$*" = '-n codewire-e2e logs pod/relay-pod -c orchestration' ] || return 99
  cat '%s'
}
%s
''' % (self.NOW_MS, later_log, log, later_log, log, body))

    NOW_MS = 1791801611000

    def test_epoch_admissions_are_read_from_the_relays_own_log(self):
        now = self.NOW_MS
        lines = [
            self.epoch_line(now - 400000, "credential_bridge_epoch_admitted", ends_in_ms=510000),
            "not json",
            self.epoch_line(now - 300000, "credential_bridge_epoch_admitted",
                            environment=WORKSPACE_UID, ends_in_ms=1),
            self.epoch_line(now - 200000, "credential_bridge_epoch_ended"),
            self.epoch_line(now - 100000, "credential_bridge_epoch_overlap",
                            previous_ends_in_ms=88000, next_ends_in_ms=509876),
            self.epoch_line(now - 50000, "credential_bridge_epoch_admitted", ends_in_ms=0),
            self.epoch_line(now - 40000, "credential_bridge_epoch_admitted", ends_in_ms="soon"),
        ]
        result = self.epoch_shell(lines, "kind_credential_epoch_admissions '%s' relay-pod" % ENVIRONMENT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "%d 510000" % (now - 400000), "%d 509876" % (now - 100000), "%d 0" % (now - 50000)])
        self.assertNotEqual(self.epoch_shell(lines, "kind_credential_epoch_admissions other relay-pod").returncode, 0)

    def await_headroom(self, lines, later=()):
        return self.epoch_shell(lines, "KIND_AUTHORITY_EPOCH_WAIT_SECONDS=1\n"
                                "await_kind_credential_epoch_headroom '%s' relay-pod" % ENVIRONMENT, later)

    def test_a_change_starts_at_once_on_an_epoch_with_headroom(self):
        now = self.NOW_MS
        for lines in (
            # 510 s admitted 300 s ago: 210 s left.
            [self.epoch_line(now - 300000, "credential_bridge_epoch_admitted", ends_in_ms=510000)],
            # A later admission replaces an earlier one that had none.
            [self.epoch_line(now - 500000, "credential_bridge_epoch_admitted", ends_in_ms=510000),
             self.epoch_line(now - 80000, "credential_bridge_epoch_overlap",
                             previous_ends_in_ms=90000, next_ends_in_ms=570000)],
            # Exactly the headroom.
            [self.epoch_line(now - 100000, "credential_bridge_epoch_overlap",
                             previous_ends_in_ms=1, next_ends_in_ms=280000)],
            # No expiry reported: the relay plans no renewal.
            [self.epoch_line(now - 900000, "credential_bridge_epoch_admitted", ends_in_ms=0)],
        ):
            with self.subTest(lines=lines):
                result = self.await_headroom(lines)
                self.assertEqual((result.returncode, result.stdout), (0, "current\n"), result.stderr)

    def test_a_change_waits_for_the_next_admission_when_renewal_is_near(self):
        now = self.NOW_MS
        # 179.999 s left: the successor could be admitted inside the change window.
        near = [self.epoch_line(now - 330001, "credential_bridge_epoch_admitted", ends_in_ms=510000)]
        overlap = self.epoch_line(now, "credential_bridge_epoch_overlap",
                                  previous_ends_in_ms=70000, next_ends_in_ms=509000)
        result = self.await_headroom(near, later=[overlap])
        self.assertEqual((result.returncode, result.stdout), (0, "renewed\n"), result.stderr)
        self.assertIn("waiting for the relay's next admission", result.stderr)
        # A short next epoch has none either: the wait spans it to the one after.
        short = self.epoch_line(now - 1000, "credential_bridge_epoch_overlap",
                                previous_ends_in_ms=60000, next_ends_in_ms=150000)
        result = self.await_headroom(near + [short], later=[overlap])
        self.assertEqual((result.returncode, result.stdout), (0, "renewed\n"), result.stderr)
        # An ended epoch's fresh successor counts too.
        fresh = self.epoch_line(now, "credential_bridge_epoch_admitted", ends_in_ms=600000)
        ended = [self.epoch_line(now - 700000, "credential_bridge_epoch_admitted", ends_in_ms=600000)]
        result = self.await_headroom(ended, later=[fresh])
        self.assertEqual((result.returncode, result.stdout), (0, "renewed\n"), result.stderr)
        # No admission, one for another environment, or one without headroom: bounded.
        for later in ([], [self.epoch_line(now, "credential_bridge_epoch_overlap", environment=WORKSPACE_UID,
                                           previous_ends_in_ms=1, next_ends_in_ms=509000)],
                      [self.epoch_line(now, "credential_bridge_epoch_admitted", ends_in_ms=5000)]):
            with self.subTest(later=later):
                result = self.await_headroom(near, later=later)
                self.assertEqual((result.returncode, result.stdout), (1, ""), result.stderr)
                self.assertIn("admitted no epoch with 180s of headroom within 1s", result.stderr)
        # A relay that never logged an admission is not evidence of headroom.
        result = self.await_headroom([])
        self.assertEqual(result.returncode, 1)
        self.assertIn("logged no epoch admission", result.stderr)

    def test_the_headroom_wait_spans_two_renewals(self):
        result = self.shell('''
printf '%s %s\\n' "$KIND_AUTHORITY_EPOCH_HEADROOM_MS" "$KIND_AUTHORITY_EPOCH_WAIT_SECONDS"
''')
        # The successor lead and the change window fit the headroom; an epoch
        # is renewed at most 90 seconds before its end, twice in a row.
        self.assertEqual(result.stdout, "180000 360\n", result.stderr)

    def test_a_renewal_inside_a_change_window_fails_by_name(self):
        now = self.NOW_MS
        before = self.epoch_line(now - 60000, "credential_bridge_epoch_admitted", ends_in_ms=510000)
        check = "assert_kind_credential_no_renewal_since '%s' relay-pod %d" % (ENVIRONMENT, now - 30000)
        result = self.epoch_shell([before], check)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        other = self.epoch_line(now - 10000, "credential_bridge_epoch_overlap", environment=WORKSPACE_UID,
                                previous_ends_in_ms=1, next_ends_in_ms=2)
        self.assertEqual(self.epoch_shell([before, other], check).returncode, 0)
        for event, fields in (("credential_bridge_epoch_overlap",
                               {"previous_ends_in_ms": 80000, "next_ends_in_ms": 509000}),
                              ("credential_bridge_epoch_admitted", {"ends_in_ms": 600000})):
            with self.subTest(event=event):
                result = self.epoch_shell([before, self.epoch_line(now - 10000, event, **fields)], check)
                self.assertEqual(result.returncode, 1)
                self.assertIn("::error::renewal inside change window", result.stderr)

    def test_daemon_probe_runs_the_daemon_path_script_in_the_exact_workspace(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-daemon-probe-")
        self.addCleanup(directory.cleanup)
        log = Path(directory.name) / "probes.jsonl"
        for mode, within in (("success", ""), ("denied", "65000"), ("revoked", "")):
            with self.subTest(mode=mode, within=within):
                result = self.shell('''
SANDBOX_NS=dev-sandboxes
KIND_DAEMON_PROBE_LOG='%s'
kind_credential_workspace() { [ "$1" = '%s' ] || return 97; printf 'workspace-pod\\n'; }
kubectl() {
  [ "$*" = '-n dev-sandboxes exec -i workspace-pod -c workspace -- python3 -B -u - %s%s' ] || return 99
  cmp -s - "$ROOT/scripts/ci/verify/kind/daemon_probe.py" || return 98
  printf '{"event":"daemon_probe","mode":"%s"}\\n'
}
kind_credential_daemon_probe '%s' %s %s
''' % (log, ENVIRONMENT, mode, " " + within if within else "", mode, ENVIRONMENT, mode, within))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["mode"], mode)
        self.assertEqual([json.loads(line)["mode"] for line in log.read_text().splitlines()],
                         ["success", "denied", "revoked"])
        for arguments in ("unbound", "success 0", "success 05000", "success 123456", "denied x"):
            with self.subTest(arguments=arguments):
                result = self.shell('''
kind_credential_workspace() { echo unexpected-workspace >&2; return 97; }
kubectl() { echo unexpected-kubectl >&2; return 99; }
kind_credential_daemon_probe '%s' %s
''' % (ENVIRONMENT, arguments))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, "")
        # A failed or foreign probe event fails the step and is still kept.
        for output, status in (('{"event":"daemon_probe_failed"}', 1),
                               ('{"event":"daemon_probe","mode":"denied"}', 0)):
            with self.subTest(output=output):
                result = self.shell('''
SANDBOX_NS=dev-sandboxes
kind_credential_workspace() { printf 'workspace-pod\\n'; }
kubectl() { cat >/dev/null; printf '%%s\\n' '%s'; return %d; }
kind_credential_daemon_probe '%s' success
''' % (output, status, ENVIRONMENT))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("the daemon-path success request failed", result.stderr)

    def test_a_launch_is_retried_only_while_setup_is_not_ready(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-launch-")
        self.addCleanup(directory.cleanup)
        launch = '''
RUN_DIR='%s'
calls="$RUN_DIR/calls"
: > "$calls"
sleep() { :; }
kind_credential_cli() {
  [ "$1 $2 $3 $4" = "run --in %s --detach" ] || return 97
  echo call >> "$calls"
  local count
  count="$(wc -l < "$calls")"
  if [ "$count" -le %d ]; then
    echo "Error: %s" >&2
    return 1
  fi
  printf '{"session_id":"session-1"}\\n'
}
KIND_LAUNCH_SETUP_SECONDS=%d
status=0
launched="$(kind_credential_launch %s --detach)" || status=$?
printf '%%s %%s %%s\\n' "$status" "$(wc -l < "$calls")" "$launched"
'''
        cases = (
            # Refused twice for setup, then launched.
            (2, "environment setup is not ready; wait for setup to finish", 60,
             "0 3 {\"session_id\":\"session-1\"}"),
            # Any other refusal returns at once.
            (5, "environment is not running", 60, "1 1"),
            # Setup that stays not ready fails once the bound passes.
            (5, "environment setup is not ready; wait for setup to finish", 0, "1 1"),
        )
        for refusals, message, seconds, expected in cases:
            with self.subTest(message=message, seconds=seconds):
                result = self.shell(launch % (directory.name, ENVIRONMENT, refusals, message,
                                              seconds, ENVIRONMENT))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)
                if expected.startswith("1"):
                    self.assertIn(message, result.stderr)
        source = (ROOT / "scripts/ci/verify/kind/credentials.sh").read_text()
        self.assertIn('launched="$(kind_credential_launch "$environment" --no-tty --detach', source)

    def test_membership_role_change_is_exact_and_fails_closed(self):
        for changed, expected in (("synthetic-membership\n", 0), ("", 1),
                                  ("one\ntwo\n", 1)):
            with self.subTest(changed=changed):
                result = self.shell('''
NS=codewire-e2e
kubectl() {
  [ "$*" = '-n codewire-e2e exec -i deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -v environment=%s -v role=admin -qAt' ] ||
    return 99
  grep -Fq "UPDATE org_members AS m SET role = :'role'" || return 98
  printf '%%s' '%s'
}
set_kind_credential_member_role '%s' admin
''' % (ENVIRONMENT, changed, ENVIRONMENT))
                self.assertEqual(result.returncode, expected, result.stderr)
        for environment, role in ((ENVIRONMENT, "owner"), (ENVIRONMENT, "admin;"),
                                  ("foreign", "admin")):
            with self.subTest(environment=environment, role=role):
                result = self.shell('''
kubectl() { echo unexpected-kubectl >&2; return 99; }
set_kind_credential_member_role '%s' '%s'
''' % (environment, role))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, "")

    def test_sandbox_replacement_requires_a_new_workspace_pod_and_a_redelivered_login(self):
        for after, expected in (("uid-2", 0), ("uid-1", 1), ("", 1)):
            with self.subTest(after=after):
                result = self.shell('''
SANDBOX_NS=dev-sandboxes
uids=(uid-1 '%s')
COUNT="$(mktemp)"; echo 0 > "$COUNT"
CALLS="$(mktemp)"
kind_credential_workspace() { [ "$1" = '%s' ] || return 97; printf 'workspace-pod\\n'; }
kubectl() {
  [ "$*" = '-n dev-sandboxes get pod workspace-pod -o jsonpath={.metadata.uid}' ] || return 99
  local seen; seen="$(cat "$COUNT")"; echo "$((seen + 1))" > "$COUNT"
  printf '%%s' "${uids[$seen]}"
}
kind_credential_cli() { printf '%%s\\n' "$*" >> "$CALLS"; }
wait_kind_credential_environment() { printf 'wait %%s\\n' "$2" >> "$CALLS"; }
kind_credential_codex_login() { printf 'login %%s\\n' "$2" >> "$CALLS"; }
rc=0
replace_kind_credential_sandbox '%s' || rc=$?
cat "$CALLS"; rm -f "$CALLS" "$COUNT"
exit "$rc"
''' % (after, ENVIRONMENT, ENVIRONMENT))
                self.assertEqual(result.returncode, expected, result.stderr)
                steps = result.stdout.splitlines()
                self.assertEqual(steps[:4], [
                    f"--cloud stop {ENVIRONMENT} --output json", "wait stopped",
                    f"--cloud start {ENVIRONMENT} --output json", "wait running"])
                # The new epoch must deliver the login again before the
                # journey uses it.
                self.assertEqual(steps[4:], ["login redelivered"] if expected == 0 else [])
                if expected:
                    self.assertIn("Stop/Start did not replace the workspace Pod", result.stderr)

    def test_rebind_moves_the_binding_to_the_current_or_an_exact_revision_once(self):
        for revision in ("", "7"):
            for rebound, expected in (("4\n", 0), ("", 1), ("4\n5\n", 1), ("x\n", 1)):
                with self.subTest(revision=revision, rebound=rebound):
                    result = self.shell('''
NS=codewire-e2e
kubectl() {
  [ "$*" = '-n codewire-e2e exec -i deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -v environment=%s -v revision=%s -qAt' ] ||
    return 99
  sql="$(cat)"
  grep -Fq "COALESCE(NULLIF(:'revision', '')::bigint, p.current_revision)" <<<"$sql" || return 98
  grep -Fq "b.profile_revision <> COALESCE" <<<"$sql" || return 97
  printf '%%s' '%s'
}
rebind_kind_credential_environment '%s' %s
''' % (ENVIRONMENT, revision, rebound, ENVIRONMENT, revision))
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if expected:
                        self.assertIn("was not rebound to another profile revision", result.stderr)
        for arguments in ("foreign", "%s 0" % ENVIRONMENT, "%s x" % ENVIRONMENT):
            with self.subTest(arguments=arguments):
                result = self.shell('''
kubectl() { echo unexpected-kubectl >&2; return 99; }
rebind_kind_credential_environment %s
''' % arguments)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, "")
        for found, expected in (("3\n", 0), ("", 1), ("0\n", 1)):
            with self.subTest(found=found):
                result = self.shell('''
NS=codewire-e2e
kubectl() {
  [ "$*" = '-n codewire-e2e exec -i deploy/postgres -- psql -U codewire -d codewire -v ON_ERROR_STOP=1 -v environment=%s -qAt' ] ||
    return 99
  grep -Fq "SELECT profile_revision FROM platform_environment_access_bindings" || return 98
  printf '%%s' '%s'
}
kind_credential_bound_revision '%s'
''' % (ENVIRONMENT, found, ENVIRONMENT))
                self.assertEqual(result.returncode, expected, result.stderr)
                if not expected:
                    self.assertEqual(result.stdout, "3\n")

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

    def test_native_flow_proves_codex_home_persistence_without_a_config_map(self):
        source = HELPERS.read_text()
        flow = source.split("kind_credential_native_smoke() (", 1)[1]
        self.assertNotIn("configmap", flow.lower())
        stop = flow.index('--cloud stop "$environment"')
        start = flow.index('--cloud start "$environment"')
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
        stop = index('--cloud stop "$environment"')
        start = index('--cloud start "$environment"')
        redelivered = index('kind_credential_codex_login "$environment" redelivered || return $?')
        daemon = 'kind_credential_daemon_probe "$environment" '
        bounded = ' "$KIND_AUTHORITY_CHANGE_WITHIN_MS"'
        initial = index('kind_credential_probe "$environment" unselected')
        gateway = index('kind_credential_probe "$environment" selected')
        counted = index("assert_kind_credential_provider_counts 2", gateway)
        warm = index(daemon + "success\n", counted)
        reuse = index(daemon + "success\n", warm + 1)
        reconnect = index('credentials --cloud connect codex --name "$credential_name" --yes')
        reconnected = index(daemon + "success\n", reconnect)
        six = index("assert_kind_credential_provider_counts 5")
        reused = index("assert_kind_credential_material_reuse")
        anchor = index('journey_from="$(kind_credential_codex_request_count)" || return $?')
        logged = index('KIND_DAEMON_PROBE_LOG="$(mktemp "$RUN_DIR/credential-daemon-authority.XXXXXX")"')
        repeated = index(daemon + "success\n", logged)
        member = index('set_kind_credential_member_role "$environment" admin')
        denied = index(daemon + "denied" + bounded, member)
        restored = index('set_kind_credential_member_role "$environment" member', denied)
        readmitted = index(daemon + "success" + bounded, restored)
        bound = index('bound_revision="$(kind_credential_bound_revision "$environment")" || return $?')
        unset = index('--profile "$profile_name" unset codex')
        rebind = index('rebind_kind_credential_environment "$environment"\n')
        unbound = index(daemon + "denied" + bounded, rebind)
        rebound = index('rebind_kind_credential_environment "$environment" "$bound_revision"')
        recovered = index(daemon + "success" + bounded, rebound)
        replaced = index('replace_kind_credential_sandbox "$environment"', recovered)
        marker = index("printf '%s\\n' '{\"event\":\"sandbox_replaced\"}' >> \"$KIND_DAEMON_PROBE_LOG\"", replaced)
        fresh = index(daemon + "success\n", marker)
        revoke = index('credentials --cloud revoke "$credential_name"')
        revoked_daemon = index(daemon + "revoked\n", revoke)
        changes = index('assert_kind_credential_authority_changes "$journey_from" "$KIND_DAEMON_PROBE_LOG"')
        revoked_gateway = index('kind_credential_probe "$environment" selected', revoke)
        revoked = index('kind_credential_codex_login "$environment" revoked || return $?')
        served = index('served="$(jq -s \'map(.served // 0) | add\' "$KIND_DAEMON_PROBE_LOG")" || return $?')
        final = index('assert_kind_credential_provider_counts "$((5 + served))"')
        destroy = index('--cloud rm "$environment"')
        # An unselected projection first; delivery before the proxy session
        # whose refreshes rotate it; the user's own login and logout after
        # rotation; Stop/Start, where a new container forgets the logout; the
        # selected projection with no request since
        # the session; on the daemon's epoch a warm-up, a reuse and Reconnect;
        # then each authority change on that connected epoch; a replaced
        # Pod's new epoch; revocation last, on that epoch, which removes the
        # login before destroy.
        order = [initial, deliver, session, counts, rotation, own, logout, stop,
                 start, redelivered,
                 gateway, counted, warm, reuse, reconnect, reconnected, six, reused, anchor,
                 logged, repeated, member, denied, restored, readmitted, bound, unset, rebind,
                 unbound, rebound, recovered, replaced, marker, fresh, revoke, revoked_daemon,
                 changes, revoked_gateway, revoked, served, final, destroy]
        self.assertEqual(sorted(order), order)
        # Every provider request crosses the daemon: the projection probe
        # makes none.
        self.assertNotIn("kind_credential_probe ", flow[counted:revoked_gateway])
        self.assertEqual(flow.count('kind_credential_probe "$environment" unselected'), 1)
        self.assertEqual(flow.count('kind_credential_probe "$environment" selected'), 2)
        self.assertEqual(flow.count("kind_credential_probe "), 3)
        self.assertEqual(flow.count(daemon + "denied" + bounded), 2)
        self.assertEqual(flow.count(daemon + "success" + bounded), 2)
        # A credential change applies to the very next request: no bound.
        self.assertEqual(flow.count(daemon + "revoked"), 1)
        self.assertEqual(flow.count(daemon + "revoked\n"), 1)
        self.assertEqual(flow.count("replace_kind_credential_sandbox"), 1)
        # Three daemon requests before the journey, each served once.
        self.assertEqual(flow[counted:anchor].count(daemon + "success\n"), 3)
        self.assertIn('login_events="$(kind_credential_codex_login "$environment" deliver)" || return $?',
                      flow)

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

    def test_error_state_records_the_failed_pod_before_cleanup_removes_it(self):
        # The fixture environment is removed right after the wait fails; the
        # failed Pod's container states and init log must be printed first,
        # and nothing from the Pod spec (its environment holds a token).
        pods = json.dumps({"items": [{
            "metadata": {"name": "sandbox-%s" % ENVIRONMENT, "uid": "u1",
                         "creationTimestamp": "t", "labels": {}},
            "spec": {"containers": [{"env": [{"name": "TOKEN", "value": "spec-secret"}]}]},
            "status": {"phase": "Failed", "initContainerStatuses": [{
                "name": "codewire-daemon-init", "image": "codewire-daemon:e2e",
                "imageID": "sha256:d", "restartCount": 0,
                "state": {"terminated": {"exitCode": 137, "reason": "OOMKilled"}},
                "lastState": {}}]}}]})
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
kind_credential_cli() { printf '{%%s}' '"state":"error"'; }
sleep() { :; }
kubectl() {
  case "$*" in
    *"get pods -l codewire.sh/environment-id=%s -o jsonpath="*) printf 'sandbox-%s\\n' ;;
    *"get pods -l codewire.sh/environment-id=%s -o json") printf '%%s' '%s' ;;
    *"logs sandbox-%s -c codewire-daemon-init"*) echo 'cp: write error: No space left on device' ;;
    *"logs sandbox-%s -c workspace"*) echo 'container "workspace" is waiting to start' ;;
    *"get events"*) echo 'Warning PodFailed' ;;
    *) return 99 ;;
  esac
}
wait_kind_credential_environment '%s' running
''' % ((ENVIRONMENT,) * 3 + (pods,) + (ENVIRONMENT,) * 3))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('::error::credential fixture environment entered error state', result.stderr)
        self.assertIn('"exitCode": 137', result.stderr)
        self.assertIn('"reason": "OOMKilled"', result.stderr)
        self.assertIn('cp: write error: No space left on device', result.stderr)
        self.assertIn('Warning PodFailed', result.stderr)
        self.assertNotIn('spec-secret', result.stderr)

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
    def _restart_pods(workspace_phase, workspace_generation):
        return json.dumps({"items": [
            {"metadata": {"name": "sandbox-workspace",
                          "labels": {"codewire.sh/type": "workspace",
                                     "codewire.sh/environment-operation-generation":
                                         str(workspace_generation)}},
             "spec": {"serviceAccountName": "codewire-sandbox",
                      "automountServiceAccountToken": False,
                      "containers": [{"name": "workspace"}]},
             "status": {"phase": workspace_phase}},
            # A lingering pre-removal gateway Pod is never the answer.
            {"metadata": {"name": "cw-gateway-restart",
                          "labels": {"codewire.sh/type": "gateway",
                                     "codewire.sh/environment-operation-generation":
                                         str(workspace_generation)}},
             "spec": {"containers": [{"name": "gateway"}]},
             "status": {"phase": "Running"}}]})

    def test_restart_wait_retries_until_the_restarted_workspace_is_running(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-restart-wait-")
        self.addCleanup(directory.cleanup)
        # The first observation has only the pre-restart (generation 1)
        # workspace Pending; it may not satisfy the wait.
        pending = self._restart_pods("Pending", 1)
        ready = self._restart_pods("Running", 2)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() {
  if [ "$*" = "-n dev-sandboxes exec sandbox-workspace -c workspace -- true" ]; then return 0; fi
  count="$(( $(cat '%(dir)s/count' 2>/dev/null || printf 0) + 1 ))"
  printf '%%s\\n' "$count" > '%(dir)s/count'
  if [ "$count" -lt 2 ]; then printf '%%s' '%(pending)s'; else printf '%%s' '%(ready)s'; fi
}
wait_kind_credential_restarted_workspace '%(env)s' 2
''' % {"dir": directory.name, "pending": pending, "ready": ready, "env": ENVIRONMENT})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["sandbox-workspace"])
        with open(os.path.join(directory.name, "count"), encoding="utf-8") as handle:
            self.assertEqual(int(handle.read()), 2)

    def test_restart_wait_holds_through_the_suspended_recreate_transition(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-restart-wait-exec-")
        self.addCleanup(directory.cleanup)
        # The recreated workspace is Running immediately, but the recreate has
        # not finished inside the workspace container: execs fail twice before
        # the container accepts them. The wait must hold.
        ready = self._restart_pods("Running", 2)
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
wait_kind_credential_restarted_workspace '%(env)s' 2
''' % {"dir": directory.name, "ready": ready, "env": ENVIRONMENT})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["sandbox-workspace"])
        with open(os.path.join(directory.name, "attempts"), encoding="utf-8") as handle:
            self.assertEqual(int(handle.read()), 3)

    def test_restart_wait_exhaustion_names_environment_and_generation(self):
        pending = self._restart_pods("Pending", 1)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() { printf '%%s' '%s'; }
wait_kind_credential_restarted_workspace '%s' 2
''' % (pending, ENVIRONMENT))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(
            '::error::credential fixture environment %s did not materialize its '
            'generation-2 workspace Pod exec-ready after the managed restart' % ENVIRONMENT,
            result.stderr)

    def test_restart_wait_exhaustion_when_exec_never_opens(self):
        ready = self._restart_pods("Running", 2)
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
sleep() { :; }
kubectl() {
  if [ "$*" = "-n dev-sandboxes exec sandbox-workspace -c workspace -- true" ]; then return 1; fi
  printf '%%s' '%s'
}
wait_kind_credential_restarted_workspace '%s' 2
''' % (ready, ENVIRONMENT))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('exec-ready', result.stderr)

    def test_the_relay_is_the_one_running_orchestration_pod(self):
        pods = lambda *items: json.dumps({"items": list(items)}).replace("'", "'\\''")
        running = {"metadata": {"name": "codewire-orchestration-a", "uid": RELAY_UID},
                   "status": {"phase": "Running"}}
        terminating = {"metadata": {"name": "codewire-orchestration-b", "uid": WORKSPACE_UID,
                                    "deletionTimestamp": "2026-10-06T00:00:00Z"},
                       "status": {"phase": "Running"}}
        for listing, expected in ((pods(running, terminating), 0), (pods(), 5),
                                  (pods(running, dict(running, metadata={"name": "c", "uid": "u"})), 5)):
            with self.subTest(listing=listing):
                result = self.shell('''
NS=dev
kubectl() {
  [ "$*" = '-n dev get pods -l app.kubernetes.io/name=codewire,app.kubernetes.io/component=orchestration -o json' ] || return 99
  printf '%%s' '%s'
}
kind_credential_relay_pod
''' % listing)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 0:
                    self.assertEqual(result.stdout.splitlines(),
                                     ["codewire-orchestration-a", RELAY_UID])

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
    'credentials --cloud get'*)
      printf '[{"name":"%%s","provider":"openai","status":"CREDENTIAL_STATUS_ACTIVE"}]\\n' "$4" ;;
    'credentials --cloud profiles list --output json')
      printf '[{"name":"kind-default","isDefault":true}]\\n' ;;
    '--cloud create'*) printf '{"id":"%%s"}\\n' '%(env)s' ;;
    '--cloud update'*) printf '{"operation_generation":1}\\n' ;;
    *) return 0 ;;
  esac
}
wait_kind_credential_environment() { return 0; }
kind_credential_probe() { :; }
wait_kind_credential_restarted_workspace() { printf 'sandbox-x\\n'; }
kind_credential_relay_pod() { printf 'codewire-orchestration-a\\n%%s\\n' '%(relay)s'; }
restart_kind_orchestration() { :; }
kind_credential_relay_token_lead() { printf '40\\n'; }
kubectl() {
  case "$*" in
    "-n dev-sandboxes get pod sandbox-x -o jsonpath={.metadata.uid}") printf '%%s\\n' '%(uid)s' ;;
    *) return 99 ;;
  esac
}
kind_credential_codex_login() { printf '{"event":"complete","mode":"deliver"}\\n'; }
kind_credential_native_smoke
''' % {"env": ENVIRONMENT, "relay": RELAY_UID, "uid": WORKSPACE_UID})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('::error::the delivered Codex login event is missing its generation',
                      result.stderr)

    def default_profile(self, listing, fail=""):
        return self.shell('''
log() { printf '[kind-e2e] %%s\\n' "$*"; }
kind_credential_cli() {
  printf '%%s\\n' "$*" >&2
  case "$*" in
    'credentials --cloud profiles list --output json') printf '%%s\\n' '%(listing)s' ;;
    *'%(fail)s'*) [ -z '%(fail)s' ] || return 7 ;;
  esac
}
ensure_kind_credential_default_profile codex kind-codex-1
''' % {"listing": listing, "fail": fail})

    def test_the_kind_user_keeps_one_lasting_empty_default_profile(self):
        # #3550: a user's first profile becomes the default, which cannot be
        # deleted, so no stage's own profile may become it.
        listed = ["credentials --cloud profiles list --output json"]
        result = self.default_profile('[{"name":"other","isDefault":true},{"name":"kind-x"}]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.splitlines(), listed)
        self.assertEqual(result.stdout, "")
        made = listed + [
            "credentials --cloud --profile kind-default set codex kind-codex-1",
            "credentials --cloud profiles default kind-default",
            "credentials --cloud --profile kind-default unset codex",
        ]
        for listing in ("[]", '[{"name":"kind-x","isDefault":false}]'):
            with self.subTest(listing=listing):
                result = self.default_profile(listing)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr.splitlines(), made)
                self.assertIn("making kind-default its lasting, empty default", result.stdout)
        for listing in ("", "{}", "null"):
            with self.subTest(listing=listing):
                result = self.default_profile(listing)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("::error::the Kind user profile list is not a JSON array", result.stderr)
                self.assertNotIn("kind-default", result.stderr)
        for step in ("set codex", "profiles default", "unset codex"):
            with self.subTest(step=step):
                result = self.default_profile("[]", fail=step)
                self.assertEqual(result.returncode, 7, result.stderr)
                self.assertEqual(result.stderr.splitlines(),
                                 made[:next(i for i, call in enumerate(made) if step in call) + 1])

    def test_every_stage_keeps_a_default_and_creates_without_one(self):
        helpers = HELPERS.read_text()
        runtime = (ROOT / "scripts/ci/verify/kind/suites/cw-runtime.sh").read_text()
        for name, flow, ensure, first in (
            ("native", helpers.split("kind_credential_native_smoke() (", 1)[1].split("\n)\n", 1)[0],
             'ensure_kind_credential_default_profile codex "$credential_name"',
             'stage_profiles="$profile_name"'),
            ("claude-session", helpers.split("kind_credential_claude_session() (", 1)[1].split("\n)\n", 1)[0],
             'ensure_kind_credential_default_profile anthropic "$key_name"',
             'stage_profiles="$key_profile $token_profile"'),
            ("claude-sign-in", helpers.split("kind_credential_claude_sign_in() (", 1)[1].split("\n)\n", 1)[0],
             'ensure_kind_credential_default_profile anthropic "$name"',
             'stage_profiles="$profile"'),
        ):
            with self.subTest(stage=name):
                self.assertEqual(flow.count(ensure), 1)
                self.assertLess(flow.index(ensure), flow.index(first))
                creates = [line for line in flow.splitlines()
                           if "kind_credential_cli --cloud create " in line]
                self.assertEqual(len(creates), 1)
                self.assertTrue(creates[0].endswith(" --no-profile \\"), creates[0])
        self.assertEqual(runtime.count("kind_credential_cli --cloud create "), 3)
        self.assertEqual(runtime.count("kind_credential_cli --cloud create --name "), 3)
        for line in runtime.splitlines():
            if "kind_credential_cli --cloud create " in line:
                self.assertIn(" --no-profile ", line)
        self.assertEqual(runtime.count('ensure_kind_credential_default_profile openai "$credential_name"'), 1)
        self.assertEqual(runtime.count('ensure_kind_credential_default_profile codex "$credential_name"'), 1)
        common = (ROOT / "scripts/ci/verify/kind/common.sh").read_text()
        self.assertIn('kind_credential_cli --cloud create --name "$name" --no-profile --image "$image"', common)
        self.assertEqual(common.count("kind_credential_cli --cloud create "), 1)

    def relay_band(self, lead):
        return self.shell('''
log() { printf '[kind-e2e] %%s\\n' "$*"; }
SANDBOX_NS=dev-sandboxes
kind_workspace_runtime_image() { printf 'localhost/synthetic:latest\\n'; }
prepare_kind_credential_cli() { :; }
kind_credential_cli() {
  case "$*" in
    'org list --output json')
      printf '[{"id":"org_contract_1","role":"member"},{"id":"org_contract_2","role":"owner"}]\\n' ;;
    'org current') printf 'ID: org_contract_1\\n' ;;
    'credentials --cloud get'*)
      printf '[{"name":"%%s","provider":"openai","status":"CREDENTIAL_STATUS_ACTIVE"}]\\n' "$4" ;;
    'credentials --cloud profiles list --output json')
      printf '[{"name":"kind-default","isDefault":true}]\\n' ;;
    '--cloud create'*) printf '{"id":"%%s"}\\n' '%(env)s' ;;
    '--cloud update'*) printf '{"operation_generation":1}\\n' ;;
    *) return 0 ;;
  esac
}
wait_kind_credential_environment() { return 0; }
kind_credential_probe() { :; }
wait_kind_credential_restarted_workspace() { printf 'sandbox-x\\n'; }
kind_credential_relay_pod() { printf 'codewire-orchestration-a\\n%%s\\n' '%(relay)s'; }
restart_kind_orchestration() { :; }
kind_credential_relay_token_lead() {
  [ "$*" = 'sandbox-x codewire-orchestration-a' ] || return 97
  printf '%%s\\n' '%(lead)s'
}
kubectl() {
  case "$*" in
    "-n dev-sandboxes get pod sandbox-x -o jsonpath={.metadata.uid}") printf '%%s\\n' '%(uid)s' ;;
    *) return 99 ;;
  esac
}
kind_credential_codex_login() { echo reached-delivery >&2; return 98; }
kind_credential_native_smoke
''' % {"env": ENVIRONMENT, "relay": RELAY_UID, "uid": WORKSPACE_UID, "lead": lead})

    def test_native_acceptance_forces_the_near_coincident_token_band(self):
        result = self.relay_band(40)
        self.assertIn("[kind-e2e] the workspace Pod started 40s after the credential relay: "
                      "their tokens expire that far apart\n", result.stdout)
        self.assertIn("reached-delivery", result.stderr)
        for lead in (0, 55, 60, 600, -3, "", "40.5"):
            with self.subTest(lead=lead):
                result = self.relay_band(lead)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("::error::the workspace Pod started %ss after the credential relay, "
                              "outside the 1-54s band this stage forces" % lead, result.stderr)
                self.assertNotIn("reached-delivery", result.stderr)
        flow = HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1]
        unselected = flow.index('kind_credential_probe "$environment" unselected')
        restart = flow.index("\n  restart_kind_orchestration\n")
        update = flow.index('kind_credential_cli --cloud update "$environment"')
        relay = flow.index('relay_pod="$(sed -n \'1p\' <<<"$relay")"')
        lead = flow.index('token_lead="$(kind_credential_relay_token_lead "$pod" "$relay_pod")" || return $?')
        deliver = flow.index('kind_credential_codex_login "$environment" deliver')
        renewal = flow.index('start_kind_credential_bridge_renewal "$pod"')
        order = [unselected, restart, update, relay, lead, deliver, renewal]
        self.assertEqual(sorted(order), order)
        # The restart is the only step between the projection probe and the
        # profile update that restarts the workspace Pod.
        self.assertEqual(flow[unselected:update].count("\n  "), 5)

    def relay_token_lead(self, workspace, relay, status=0):
        return self.shell('''
NS=codewire-e2e
SANDBOX_NS=dev-sandboxes
kubectl() {
  case "$*" in
    '-n dev-sandboxes get pod sandbox-x -o jsonpath={.status.startTime}') printf '%%s' '%s' ;;
    '-n codewire-e2e get pod codewire-orchestration-a -o jsonpath={.status.startTime}')
      printf '%%s' '%s'; return %d ;;
    *) return 99 ;;
  esac
}
kind_credential_relay_token_lead sandbox-x codewire-orchestration-a
''' % (workspace, relay, status))

    def test_the_relay_token_lead_is_the_two_pods_start_times_apart(self):
        result = self.relay_token_lead("2026-10-12T14:00:18Z", "2026-10-12T13:59:37Z")
        self.assertEqual((result.returncode, result.stdout), (0, "41\n"), result.stderr)
        result = self.relay_token_lead("2026-10-12T13:59:37Z", "2026-10-12T14:00:18Z")
        self.assertEqual((result.returncode, result.stdout), (0, "-41\n"), result.stderr)
        self.assertNotEqual(self.relay_token_lead("", "2026-10-12T13:59:37Z").returncode, 0)
        self.assertNotEqual(
            self.relay_token_lead("2026-10-12T14:00:18Z", "2026-10-12T13:59:37Z", status=1).returncode, 0)

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
        for retired in ("wait_kind_credential_sandbox_pair", "gateway_uid", "codewire-gateway"):
            self.assertNotIn(retired, flow)
        update = flow.index('update="$(kind_credential_cli --cloud update "$environment"')
        generation = flow.index('restart_generation="$(jq -er')
        pod = flow.index('pod="$(wait_kind_credential_restarted_workspace '
                         '"$environment" "$restart_generation")"')
        relay = flow.index('relay="$(kind_credential_relay_pod)"')
        self.assertLess(update, generation)
        self.assertLess(generation, pod)
        self.assertLess(pod, relay)
        self.assertIn('wait_kind_credential_environment "$environment" running\n  pod=', flow)

    def test_host_cli_build_selects_its_actual_binary_package(self):
        manifest = tomllib.loads((ROOT / "crates/codewire-cli-bin/Cargo.toml").read_text())
        self.assertIn("cw", [binary["name"] for binary in manifest["bin"]])
        expected = f'cargo build --locked --profile ci -p {manifest["package"]["name"]} --bin cw'
        source = (ROOT / "scripts/ci/images/build-kind-smokes.sh").read_text()
        self.assertEqual(source.count(expected), 1)
        self.assertNotIn("-p codewire-cli --bin cw", source)

    def shell(self, body, registry="registry.example.invalid"):
        env = {"PATH": "/usr/bin:/bin", "ROOT": str(ROOT)}
        if registry is not None:
            env["CODEWIRE_IMAGE_REGISTRY"] = registry
        result = subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\n'
             'validate_sealed_kind_images() { return 1; }\n' + body,
             "kind-credential-fixture", str(HELPERS)],
            env=env,
            capture_output=True, text=True, timeout=300,
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

    def test_sealed_support_images_require_the_configured_registry(self):
        result = self.shell('''
validate_sealed_kind_images() { return 0; }
kind_credential_support_images
''', registry=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("CODEWIRE_IMAGE_REGISTRY: set to the image registry host", result.stderr)

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
        # A new cluster's services-ci image is built from this tree, so it
        # carries the runtime profile; the retired ci profile is refused too.
        for profile, promotable in (("release", "false"), ("ci", "false"), ("runtime", "true"),
                                    ("", "false")):
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

    def test_credential_mode_switch_identifies_services_ci_by_promotability(self):
        # A retained cluster keeps the base images it was created with, which
        # may predate the one runtime profile, so the mode switch identifies
        # services-ci by its non-promotable label alone.
        for profile, promotable, expected in (("runtime", "false", 0), ("ci", "false", 0),
                                              ("runtime", "true", 1), ("", "", 1)):
            with self.subTest(profile=profile, promotable=promotable):
                result = subprocess.run(
                    ["/bin/bash", "-c", 'set -euo pipefail\nNS=codewire-e2e\nsource "$1"\n'
                     'docker() {\n  case "$4" in\n    *build.profile*) echo "$FAKE_PROFILE" ;;\n'
                     '    *promotable*) echo "$FAKE_PROMOTABLE" ;;\n    *) return 99 ;;\n  esac\n}\n'
                     'require_kind_services_ci_image\n',
                     "kind-credential-mode", str(ROOT / "scripts/ci/verify/kind/credential-mode.sh")],
                    env={"PATH": "/usr/bin:/bin", "ROOT": str(ROOT), "FAKE_PROFILE": profile,
                         "FAKE_PROMOTABLE": promotable},
                    capture_output=True, text=True, timeout=300,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected:
                    self.assertIn("exact non-promotable services-ci image", result.stderr)

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
    def relay_line(cls, offset_ms, event="credential_bridge_epoch_overlap",
                   target="codewire_orchestration::worker::credential_relay::epoch",
                   environment=ENVIRONMENT, previous=29000, following=509000):
        stamp = datetime.fromtimestamp((cls.RENEWAL_STARTED_MS + offset_ms) / 1000, timezone.utc)
        return json.dumps({
            "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "level": "INFO",
            "fields": {"event": event, "environment_id": environment,
                       "previous_ends_in_ms": previous, "next_ends_in_ms": following,
                       "message": "credential relay admitted the next epoch"},
            "target": target,
        })

    def renewal_assertion(self, probe, logs, log_status=0, pod="codewire-orchestration-7d9c8-x2k4p",
                          environment=ENVIRONMENT):
        directory = tempfile.TemporaryDirectory(prefix="kind-bridge-renewal-")
        self.addCleanup(directory.cleanup)
        probe_path = Path(directory.name) / "probe.jsonl"
        probe_path.write_text("".join(f"{line}\n" for line in probe))
        logs_path = Path(directory.name) / "relay.log"
        logs_path.write_text("".join(f"{line}\n" for line in logs))
        return self.shell('''
NS=dev
log() { printf '[kind-e2e] %%s\\n' "$*"; }
kubectl() {
  [ "$*" = '-n dev logs pod/codewire-orchestration-7d9c8-x2k4p -c orchestration' ] || { echo unexpected-kubectl >&2; return 99; }
  cat '%s'
  return %d
}
assert_kind_credential_bridge_renewal '%s' '%s' '%s'
''' % (logs_path, log_status, probe_path, environment, pod))

    def test_bridge_renewal_requires_only_broker_answers_and_an_overlap_in_the_window(self):
        # An epoch that ended before the window, another environment's, and
        # one outside the relay's epoch target are not this renewal's.
        noise = ["not-json", json.dumps({"timestamp": "x", "fields": "x"}),
                 self.relay_line(-100_000, event="credential_bridge_epoch_ended"),
                 self.relay_line(100_000, event="credential_bridge_epoch_ended",
                                 environment="6f1d1e9a-0b1c-4a52-9a4e-2c1f00000009"),
                 self.relay_line(100_000, event="credential_bridge_epoch_ended",
                                 target="codewire_orchestration::worker::credential_relay")]
        for offset in (300_000, -2_000, 702_000):
            with self.subTest(offset=offset):
                result = self.renewal_assertion(
                    [self.renewal_probe()], [*noise, self.relay_line(offset)])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "[kind-e2e] the credential relay's smallest "
                                 "successor extension in the renewal window: 480s\n")
        # The smallest extension is evidence, not a bound: 41 seconds passes.
        result = self.renewal_assertion([self.renewal_probe()], [
            self.relay_line(100_000, previous=88_000, following=129_000),
            self.relay_line(140_000, previous=89_000, following=569_000)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "[kind-e2e] the credential relay's smallest "
                         "successor extension in the renewal window: 41s\n")
        # About one request a second: the minimum is a short renewal window.
        result = self.renewal_assertion([self.renewal_probe(requests=60)],
                                        [self.relay_line(300_000)])
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
                result = self.renewal_assertion([probe], [self.relay_line(300_000)])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("a proxied request failed or the probe was incomplete", result.stderr)
                self.assertNotIn("unexpected-kubectl", result.stderr)
        for probes in ([], [self.renewal_probe(), self.renewal_probe()]):
            with self.subTest(probes=probes):
                result = self.renewal_assertion(probes, [self.relay_line(300_000)])
                self.assertEqual(result.returncode, 1, result.stderr)

    def test_bridge_renewal_requires_the_relay_overlap_inside_the_window(self):
        for logs in (
                [],
                [self.relay_line(-3_000)],
                [self.relay_line(703_000)],
                [self.relay_line(300_000, target="codewire_orchestration::worker::credential_relay")],
                [self.relay_line(300_000, environment="6f1d1e9a-0b1c-4a52-9a4e-2c1f00000009")],
                [self.relay_line(300_000).replace("Z\"", "+00:00\"")]):
            with self.subTest(logs=logs):
                result = self.renewal_assertion([self.renewal_probe()], logs)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("credential relay logged no epoch overlap", result.stderr)

    def test_bridge_renewal_fails_when_an_epoch_ends_without_a_successor(self):
        for offset in (-2_000, 300_000, 702_000):
            with self.subTest(offset=offset):
                result = self.renewal_assertion([self.renewal_probe()], [
                    self.relay_line(100_000),
                    self.relay_line(offset, event="credential_bridge_epoch_ended")])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("::error::a credential relay epoch ended with no successor "
                              "while proxied requests were running", result.stderr)

    def test_bridge_renewal_fails_when_a_successor_does_not_extend_the_epoch(self):
        for previous, following in ((88_000, 88_000), (88_000, 87_000), (None, 509_000),
                                    (29_000, None), ("29000", 509_000)):
            with self.subTest(previous=previous, following=following):
                result = self.renewal_assertion([self.renewal_probe()], [
                    self.relay_line(100_000),
                    self.relay_line(300_000, previous=previous, following=following)])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("::error::a credential relay successor did not expire later "
                              "than the epoch it replaced", result.stderr)

    # Run J on #2616 (2026-10-12): the relay's and the workspace's tokens
    # expired 41 seconds apart, every successor was refused for want of 60
    # seconds more, the epoch ended at 14:09:37 with none, and one request in
    # the next second got 503 (#2641). The relay log and probe, as recorded.
    RUN_J_ENVIRONMENT = "8ab72e99-a52c-48cc-bc04-7c408f324584"
    RUN_J_PROBE = ('{"event":"bridge_renewal_probe","started_unix_ms":1791813629634,'
                   '"ended_unix_ms":1791814186922,"requests":556,"statuses":{"403":555,"503":1}}')
    RUN_J_RELAY = [
        ("14:00:25.976980", {"event": "credential_bridge_first_epoch_admitted", "attempts": 1,
                             "after_admissible_ms": 76}),
        ("14:00:25.977001", {"event": "credential_bridge_epoch_admitted", "ends_in_ms": 551022}),
        *[(at, {"event": "credential_bridge_successor_refused", "reason": "expiry_not_extended"})
          for at in ("14:08:07.402307", "14:08:10.494415", "14:08:16.606922", "14:08:28.714600",
                     "14:08:43.837725", "14:08:58.894501", "14:09:13.930888", "14:09:29.030291")],
        ("14:09:37.002221", {"event": "credential_bridge_epoch_ended"}),
        ("14:09:38.054562", {"event": "credential_bridge_epoch_admitted", "ends_in_ms": 530945}),
        ("14:09:48.025961", {"event": "credential_bridge_epoch_ended"}),
    ]

    def test_run_j_fails_the_renewal_assertion_on_both_checks(self):
        logs = [json.dumps({
            "timestamp": f"2026-10-12T{at}Z", "level": "INFO",
            "fields": {**fields, "environment_id": self.RUN_J_ENVIRONMENT},
            "target": "codewire_orchestration::worker::credential_relay::epoch"})
            for at, fields in self.RUN_J_RELAY]
        # The 503 in the gap.
        result = self.renewal_assertion([self.RUN_J_PROBE], logs,
                                        environment=self.RUN_J_ENVIRONMENT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("a proxied request failed or the probe was incomplete", result.stderr)
        # Had every request been answered, the epoch that ended with no
        # successor inside the window still fails it.
        answered = json.loads(self.RUN_J_PROBE)
        answered["statuses"] = {"403": answered["requests"]}
        result = self.renewal_assertion([json.dumps(answered)], logs,
                                        environment=self.RUN_J_ENVIRONMENT)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("::error::a credential relay epoch ended with no successor "
                      "while proxied requests were running", result.stderr)

    def test_bridge_renewal_fails_closed_on_log_or_pod_name_failure(self):
        result = self.renewal_assertion([self.renewal_probe()], [self.relay_line(300_000)],
                                        log_status=7)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("could not read the credential relay log", result.stderr)
        for pod in ("", "Gateway", "pod/cw-gateway-renewal", "cw gateway"):
            with self.subTest(pod=pod):
                result = self.renewal_assertion([self.renewal_probe()],
                                                [self.relay_line(300_000)], pod=pod)
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

    def test_a_failure_while_the_creator_is_an_admin_restores_the_member_role(self):
        flow = HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1]
        trap = flow.split("trap '", 1)[1].split("' EXIT", 1)[0]
        self.assertIn('[ -z "$member_role_changed" ] || set_kind_credential_member_role '
                      '"$environment" member >/dev/null 2>&1 || true', trap)
        armed = flow.index('member_role_changed=1')
        admin = flow.index('set_kind_credential_member_role "$environment" admin', armed)
        member = flow.index('set_kind_credential_member_role "$environment" member', admin)
        cleared = flow.index('member_role_changed=""\n', member)
        self.assertEqual(sorted([armed, admin, member, cleared]), [armed, admin, member, cleared])

    def test_each_authority_change_runs_in_a_window_no_epoch_renews_in(self):
        flow = HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1]
        index = flow.index
        awaited = ('headroom="$(await_kind_credential_epoch_headroom "$environment" "$relay_pod")" '
                   '|| return $?\n')
        opened = '  authority_window_from="$(date +%s%3N)"\n'
        recorded = ('  if [ "$headroom" = renewed ]; then\n'
                    "    printf '%s\\n' '{\"event\":\"epoch_renewed\"}' >> \"$KIND_DAEMON_PROBE_LOG\"\n"
                    '    kind_credential_daemon_probe "$environment" success\n'
                    '  fi\n')
        closed = ('kind_credential_daemon_probe "$environment" success\n'
                  '  assert_kind_credential_no_renewal_since "$environment" "$relay_pod" '
                  '"$authority_window_from"\n'
                  '  authority_window_from=""\n')
        self.assertEqual((flow.count(awaited), flow.count(opened), flow.count(closed)), (2, 2, 2))
        self.assertEqual(flow.count(recorded), 1)
        # The first window opens before the epoch's first request: a renewal
        # waited for there needs no record, and the warm-up, the reuse,
        # Reconnect and the role change are all observed on one epoch.
        counted = index("assert_kind_credential_provider_counts 2",
                        index('kind_credential_probe "$environment" selected'))
        first = index(awaited + opened, counted)
        warm = index('kind_credential_daemon_probe "$environment" success\n', first)
        self.assertEqual(flow[first + len(awaited + opened):warm], "  ")
        admin = index('set_kind_credential_member_role "$environment" admin', warm)
        readmitted = index('kind_credential_daemon_probe "$environment" success '
                           '"$KIND_AUTHORITY_CHANGE_WITHIN_MS"', admin)
        role_closed = index(closed, readmitted)
        # The second opens right before the rebind, on a warm epoch.
        rebind = index(awaited + recorded + opened, role_closed)
        unset = index('--profile "$profile_name" unset codex', rebind)
        self.assertEqual(flow[rebind + len(awaited + recorded + opened):unset],
                         '  kind_credential_cli credentials --cloud ')
        recovered = index('kind_credential_daemon_probe "$environment" success '
                          '"$KIND_AUTHORITY_CHANGE_WITHIN_MS"', unset)
        rebind_closed = index(closed, recovered)
        replaced = index('replace_kind_credential_sandbox "$environment"', rebind_closed)
        order = [counted, first, warm, admin, readmitted, role_closed, rebind, unset, recovered,
                 rebind_closed, replaced]
        self.assertEqual(sorted(order), order)
        # No daemon-path request is made between the two windows.
        self.assertNotIn("kind_credential_daemon_probe", flow[role_closed + len(closed):rebind])
        # A probe that fails inside a window names the renewal that caused it.
        trap = flow.split("' EXIT", 1)[0].rsplit("trap '", 1)[1]
        self.assertTrue(trap.startswith(
            '[ -z "$authority_window_from" ] || assert_kind_credential_no_renewal_since '
            '"$environment" "$relay_pod" "$authority_window_from" || true; '))
        # The assertion reads the journey with the period the daemon was given.
        period = index('login_check_seconds="$(kind_credential_codex_login_check_period "$pod")" || return $?')
        self.assertLess(period, admin)
        self.assertIn('assert_kind_credential_authority_changes "$journey_from" "$KIND_DAEMON_PROBE_LOG" \\\n'
                      '    "$login_check_seconds"\n', flow)

    def login_check_period(self, value, status=0):
        return self.shell('''
SANDBOX_NS=dev-sandboxes
kubectl() {
  [ "$*" = '-n dev-sandboxes get pod sandbox-1 -o jsonpath={.spec.containers[?(@.name=="workspace")].env[?(@.name=="CODEWIRE_CODEX_LOGIN_CHECK_PERIOD_SECONDS")].value}' ] || return 99
  printf '%%s' '%s'
  return %d
}
kind_credential_codex_login_check_period sandbox-1
''' % (value, status))

    def test_the_login_check_period_is_read_from_the_workspace_daemon(self):
        for value, period in (("", "120"), ("30", "30"), ("10", "10"), ("120", "120")):
            with self.subTest(value=value):
                result = self.login_check_period(value)
                self.assertEqual((result.returncode, result.stdout), (0, period + "\n"), result.stderr)
        for value in ("9", "121", "030", "1e2", "30 ", "-30"):
            with self.subTest(value=value):
                result = self.login_check_period(value)
                self.assertEqual((result.returncode, result.stdout), (1, ""), result.stderr)
                self.assertIn("invalid Codex login check period", result.stderr)
        self.assertNotEqual(self.login_check_period("30", status=1).returncode, 0)


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
            self.assertEqual(request.args, ("POST", "/_codewire/anthropic/v1/messages"))
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


class DaemonProbe(unittest.TestCase):
    """Proxied Codex requests on the daemon's loopback ingress."""

    def setUp(self):
        self.statuses = []
        self.connections = []
        self.payload = b"data: CWCODEX149 kind"
        self.clock = [0.0]
        def connection(*args, **kwargs):
            result = Mock()
            result.args = (args, kwargs)
            status = self.statuses.pop(0) if self.statuses else 200
            result.getresponse.return_value.status = status
            result.getresponse.return_value.read.return_value = (
                self.payload if status == 200 else b"denied")
            self.clock[0] += 0.05
            self.connections.append(result)
            return result
        def sleep(seconds):
            self.assertEqual(seconds, DAEMON.POLL_SECONDS)
            self.clock[0] += seconds
        self.output = io.StringIO()
        for fixture in (
            patch.object(DAEMON.http.client, "HTTPConnection", side_effect=connection),
            patch.object(DAEMON.time, "sleep", side_effect=sleep),
            patch.object(DAEMON.time, "monotonic", side_effect=lambda: self.clock[0]),
            contextlib.redirect_stdout(self.output),
        ):
            fixture.__enter__()
            self.addCleanup(fixture.__exit__, None, None, None)

    def event(self):
        return json.loads(self.output.getvalue())

    def test_one_request_uses_the_daemon_loopback_codex_route_without_a_credential(self):
        DAEMON.probe("success")
        (connection,) = self.connections
        self.assertEqual(connection.args, (("127.0.0.1", 38081), {"timeout": 20}))
        request = connection.request.call_args
        self.assertEqual(request.args, ("POST", "/v1/responses"))
        self.assertEqual(request.kwargs["headers"],
                         {"Host": "localhost", "Content-Type": "application/json"})
        # A baseline request: no fixture scenario marker.
        self.assertEqual(json.loads(request.kwargs["body"])["input"], "CW_KIND_DAEMON_PATH")
        connection.close.assert_called_once()
        self.assertEqual(self.event(), {"event": "daemon_probe", "mode": "success", "status": 200,
                                        "requests": 1, "served": 1, "waited_ms": 50,
                                        "within_ms": None})

    def test_one_request_must_answer_its_mode_at_once(self):
        for mode, status, wrong in (("denied", 403, 200), ("revoked", 403, 200),
                                    ("success", 200, 403), ("success", 200, 503)):
            with self.subTest(mode=mode, wrong=wrong):
                self.statuses = [wrong, status]
                with self.assertRaises(ValueError):
                    DAEMON.probe(mode)

    def test_a_change_is_awaited_within_its_bound_and_counts_what_was_served(self):
        # Once a second, for up to the broker's one-minute decision window.
        self.assertEqual(DAEMON.POLL_SECONDS, 1.0)
        self.statuses = [200, 200, 403]
        DAEMON.probe("denied", 65000)
        event = self.event()
        self.assertEqual((event["status"], event["requests"], event["served"], event["within_ms"]),
                         (403, 3, 2, 65000))
        self.assertEqual(event["waited_ms"], 2150)
        self.output.truncate(0)
        self.output.seek(0)
        self.statuses = [403, 200]
        DAEMON.probe("success", 65000)
        self.assertEqual((self.event()["requests"], self.event()["served"]), (2, 1))
        # A change that lands as its decision reaches its minute.
        self.output.truncate(0)
        self.output.seek(0)
        self.statuses = [200] * 61 + [403]
        DAEMON.probe("denied", 65000)
        self.assertEqual((self.event()["requests"], self.event()["served"]), (62, 61))
        self.assertLessEqual(self.event()["waited_ms"], 65000)

    def test_a_change_that_misses_its_bound_or_answers_otherwise_fails(self):
        for mode, statuses, within in (("denied", [200] * 40, 1000),
                                       ("denied", [200] * 70, 65000),
                                       ("denied", [200, 503, 403], 65000),
                                       ("success", [403, 200], 100),
                                       ("revoked", [403], 0),
                                       ("denied", [403], 70001)):
            with self.subTest(mode=mode, statuses=statuses, within=within):
                self.statuses = list(statuses)
                with self.assertRaises(ValueError):
                    DAEMON.probe(mode, within)
        self.assertEqual(self.output.getvalue(), "")

    def test_unknown_mode_never_reaches_the_network(self):
        for mode in ("unbound", "missing", "", "success "):
            with self.assertRaises(ValueError):
                DAEMON.probe(mode)
        self.assertEqual(self.connections, [])

    def test_provider_material_missing_marker_and_oversize_are_rejected(self):
        for payload in (b"CW_KIND_SYNTHETIC_REFRESH_private CWCODEX149 kind",
                        b"synthetic-kind-signature CWCODEX149 kind",
                        b"CWCODEX149 kind" + b"x" * (64 * 1024), b"no marker"):
            with self.subTest(size=len(payload)):
                self.payload = payload
                with self.assertRaises(ValueError):
                    DAEMON.probe("success")
        self.assertEqual(self.output.getvalue(), "")

    def test_arguments_are_a_mode_and_an_optional_positive_bound(self):
        self.assertEqual(DAEMON.arguments(["probe", "denied"]), ("denied", None))
        self.assertEqual(DAEMON.arguments(["probe", "denied", "5000"]), ("denied", 5000))
        for argv in (["probe"], ["probe", "denied", "0"], ["probe", "denied", "05"],
                     ["probe", "denied", "-5"], ["probe", "denied", "5", "6"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                DAEMON.arguments(argv)


# A stand-in for the pinned Claude Code binary: it records only the names the
# driver must project (never a value outside them) and replies per FAKE_MODE.
FAKE_CLAUDE = r"""
import json, os, sys, time
mode = os.environ.get("FAKE_CLAUDE_MODE", "ok")
if sys.argv[1:] == ["--version"]:
    print("9.9.9 (Not Claude)" if mode == "bad-version" else "2.1.308 (Claude Code)")
    sys.exit(0)
record = os.environ.get("FAKE_CLAUDE_RECORD")
if record:
    import socket, urllib.parse
    names = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY",
             "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
    proxies = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
               "all_proxy", "NO_PROXY", "no_proxy")
    # Whether the proxy Claude Code would use refuses a connection now.
    proxy = urllib.parse.urlsplit(os.environ.get("HTTPS_PROXY", "http://127.0.0.1:0"))
    try:
        socket.create_connection((proxy.hostname, proxy.port), timeout=60).close()
        refused = False
    except ConnectionRefusedError:
        refused = True
    except OSError:
        refused = None
    with open(record, "a") as output:
        output.write(json.dumps({"argv": sys.argv[1:],
                                 "env": {name: os.environ.get(name) for name in names},
                                 "proxies": {name: os.environ.get(name) for name in proxies},
                                 "proxy_refused": refused,
                                 "home": os.environ["HOME"], "cwd": os.getcwd(),
                                 "stdin": sys.stdin.read()}) + "\n")
if mode == "ok":
    print("CWCLAUDE kind private-claude-output-canary")
elif mode == "refused":
    print("Failed to authenticate. API Error: 401 private-claude-output-canary")
    sys.exit(1)
elif mode == "withheld":
    print("API Error: 403 Anthropic needs Reconnect private-claude-output-canary")
    sys.exit(1)
elif mode == "no-login":
    print("Not logged in. Please run /login private-claude-output-canary")
    sys.exit(1)
elif mode == "refused-silent":
    sys.exit(1)
elif mode == "refused-exit-zero":
    print("API Error: 401")
elif mode == "exit":
    print("CWCLAUDE kind")
    sys.exit(3)
elif mode == "no-marker":
    print("private-claude-output-canary")
elif mode == "leak":
    print("CWCLAUDE kind CW_KIND_SYNTHETIC_CLAUDE_TOKEN")
elif mode == "stderr-leak":
    print("CWCLAUDE kind")
    print("CW_KIND_SYNTHETIC_REFUSED_TOKEN", file=sys.stderr)
elif mode == "huge":
    sys.stdout.write("CWCLAUDE kind" + "x" * (300 * 1024))
elif mode == "hang":
    time.sleep(30)
"""


class ClaudeSessionDriver(unittest.TestCase):
    """claude_session.py with a fake Claude Code; no cluster or provider I/O.

    The environment passed in stands for what the workspace daemon projected
    into the session; the driver must only observe it."""

    SUBSCRIPTION = {"ANTHROPIC_BASE_URL": "http://127.0.0.1:38081/_codewire/anthropic",
                    "CLAUDE_CODE_OAUTH_TOKEN": "codewire-managed"}
    API_KEY = {"ANTHROPIC_BASE_URL": "http://127.0.0.1:38081/_codewire/anthropic",
               "ANTHROPIC_AUTH_TOKEN": "codewire-managed"}
    SIGN_IN = {"ANTHROPIC_BASE_URL": "http://127.0.0.1:38081/_codewire/anthropic"}

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="kind-claude-session-")
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        fake = self.scratch / "fake_claude.py"
        fake.write_text(FAKE_CLAUDE)
        self.record = self.scratch / "record.jsonl"
        # The workspace user's own home, as the daemon left it.
        self.user_home = self.scratch / "workspace-home"
        self.user_home.mkdir()
        self.claude_config = self.user_home / ".claude.json"
        self.write_claude_config(
            '{"numStartups": 1, "hasCompletedOnboarding": true, '
            '"hasAcknowledgedCostThreshold": true, '
            '"projects": {"/workspace": {"hasTrustDialogAccepted": true}}}')
        for fixture in (
            patch.object(CLAUDE, "CLAUDE_ARGV", (sys.executable, str(fake))),
            patch.object(CLAUDE, "SESSION_TIMEOUT", 120.0),
            patch.object(CLAUDE.signal, "signal"),
        ):
            fixture.start()
            self.addCleanup(fixture.stop)

    def environ(self, mode="ok", projected=None, **extra):
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "FAKE_CLAUDE_MODE": mode,
                "FAKE_CLAUDE_RECORD": str(self.record), "HOME": str(self.user_home),
                **(self.SUBSCRIPTION if projected is None else projected), **extra}

    def write_login(self, refresh="codewire-managed-no-refresh-token-" + "a" * 32,
                    marker=True, mode=0o600, login=True):
        """The login the daemon delivers for the sign-in form, in the user's
        own ~/.claude/.credentials.json, beside a key that is not Codewire's."""
        directory = self.user_home / ".claude"
        directory.mkdir(mode=0o700, exist_ok=True)
        document = {"mcpOAuth": {}}
        if login:
            document["claudeAiOauth"] = {
                "accessToken": "sk-ant-oat01-CW_KIND_SYNTHETIC_SIGN_IN_ACCESS-000002",
                "refreshToken": refresh, "expiresAt": 4_000_000_000_000,
                "scopes": ["user:inference", "user:profile"], "subscriptionType": "max"}
        if marker:
            document["codewireManaged"] = 1
        path = directory / ".credentials.json"
        path.unlink(missing_ok=True)
        path.write_text(json.dumps(document))
        path.chmod(mode)
        return path

    def write_claude_config(self, contents, mode=0o600):
        if self.claude_config.is_dir() and not self.claude_config.is_symlink():
            self.claude_config.rmdir()
        self.claude_config.unlink(missing_ok=True)
        self.claude_config.write_text(contents)
        self.claude_config.chmod(mode)

    def main(self, argv, environ):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = CLAUDE.main(argv, environ)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        return status, events, output.getvalue()

    def calls(self):
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_text().splitlines()]

    def test_claude_inherits_exactly_the_daemon_projection_for_each_form(self):
        for form, projected in (("subscription_token", self.SUBSCRIPTION),
                                ("api_key", self.API_KEY)):
            with self.subTest(form=form):
                self.record.unlink(missing_ok=True)
                status, events, output = self.main([form, "success"],
                                                   self.environ(projected=projected))
                self.assertEqual(status, 0, output)
                self.assertEqual(events, [
                    {"event": "claude_projection", "form": form, "source": "daemon_session"},
                    {"event": "claude_session", "form": form, "outcome": "success",
                     "client_version": "2.1.308"},
                    {"event": "complete", "form": form, "outcome": "success"},
                ])
                self.assertNotIn("canary", output)
                [call] = self.calls()
                self.assertEqual(call["argv"], ["-p", CLAUDE.PROMPT])
                self.assertEqual(call["stdin"], "")
                # Exactly the form's names, the others absent, plus the
                # harness's own switch.
                self.assertEqual(call["env"], {
                    **{name: projected.get(name) for name in CLAUDE.NAMES},
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"})
                # A fresh private home, never the workspace user's own login.
                self.assertEqual(call["cwd"], call["home"])
                self.assertTrue(Path(call["home"]).name.startswith("kind-claude-"))
                self.assertFalse(Path(call["home"]).exists())

    def test_claude_has_no_route_but_loopback_in_every_form(self):
        # #2891: a Kind Sandbox has open egress; Claude Code's own account
        # calls must never carry a fixture credential or a placeholder to a
        # real provider. Every proxy names one refusing loopback port, and
        # loopback, where the managed route listens, is the only exemption.
        for form, projected in (("subscription_token", self.SUBSCRIPTION),
                                ("api_key", self.API_KEY), ("sign_in", self.SIGN_IN)):
            with self.subTest(form=form):
                self.record.unlink(missing_ok=True)
                if form == "sign_in":
                    self.write_login()
                status, events, output = self.main(
                    [form, "success"],
                    self.environ(projected=projected, NO_PROXY="corp.example", HTTPS_PROXY="http://corp:3128"))
                self.assertEqual(status, 0, output)
                [call] = self.calls()
                proxies = call["proxies"]
                url = proxies["HTTPS_PROXY"]
                self.assertRegex(url, r"^http://127\.0\.0\.1:[1-9][0-9]*$")
                self.assertEqual(proxies, {**dict.fromkeys(CLAUDE.PROXIES, url),
                                           "NO_PROXY": "127.0.0.1,localhost",
                                           "no_proxy": "127.0.0.1,localhost"})
                self.assertIs(call["proxy_refused"], True)

    def test_the_driver_never_supplies_a_missing_or_wrong_projection(self):
        for name, value in (
                ("CLAUDE_CODE_OAUTH_TOKEN", ""),
                ("ANTHROPIC_AUTH_TOKEN", "codewire-managed"),
                # The other names must be absent, not merely empty.
                ("ANTHROPIC_AUTH_TOKEN", ""),
                ("ANTHROPIC_API_KEY", ""),
                ("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
                ("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-other")):
            with self.subTest(name=name, value=value):
                status, events, _ = self.main(["subscription_token", "success"],
                                              self.environ(**{name: value}))
                self.assertEqual(status, 1)
                self.assertEqual(events, [{"event": "failed", "form": "subscription_token",
                                           "outcome": "success",
                                           "reason": "projection_values"}])
        for name, reason in (("ANTHROPIC_BASE_URL", "projection_missing"),
                             # The base URL alone is the sign-in form's.
                             ("CLAUDE_CODE_OAUTH_TOKEN", "projection_other_form")):
            with self.subTest(missing=name):
                environ = self.environ()
                del environ[name]
                status, events, _ = self.main(["subscription_token", "success"], environ)
                self.assertEqual(events[-1]["reason"], reason)
        # The other form's exact projection is named as such.
        status, events, _ = self.main(["subscription_token", "success"],
                                      self.environ(projected=self.API_KEY))
        self.assertEqual(events[-1]["reason"], "projection_other_form")
        status, events, _ = self.main(["api_key", "success"], self.environ())
        self.assertEqual(events[-1]["reason"], "projection_other_form")
        self.assertEqual(self.calls(), [])

    def test_the_sign_in_form_runs_with_the_session_home_and_its_delivered_login(self):
        login = self.write_login()
        before = login.read_bytes()
        status, events, output = self.main(["sign_in", "success"],
                                           self.environ(projected=self.SIGN_IN))
        self.assertEqual(status, 0, output)
        self.assertEqual(events, [
            {"event": "claude_projection", "form": "sign_in", "source": "daemon_session"},
            {"event": "claude_session", "form": "sign_in", "outcome": "success",
             "client_version": "2.1.308"},
            {"event": "complete", "form": "sign_in", "outcome": "success"},
        ])
        [call] = self.calls()
        # The base URL alone; nothing that would outrank the saved login.
        self.assertEqual(call["env"], {
            **{name: self.SIGN_IN.get(name) for name in CLAUDE.NAMES},
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"})
        # The session user's own home, where the login lives; the driver only
        # read it.
        self.assertEqual(call["home"], str(self.user_home))
        self.assertNotEqual(call["cwd"], call["home"])
        self.assertEqual(login.read_bytes(), before)
        for private in ("CW_KIND_SYNTHETIC", "codewire-managed-no-refresh-token", "canary"):
            self.assertNotIn(private, output)

    def test_the_sign_in_form_needs_codewires_login_and_logged_out_needs_it_gone(self):
        sign_in = self.environ(projected=self.SIGN_IN)
        for prepare, outcome, reason in (
                (lambda: None, "success", "login_missing"),
                (lambda: self.write_login(login=False), "success", "login_missing"),
                (lambda: self.write_login(), "logged_out", "login_kept"),
                (lambda: self.write_login(refresh="users-own-refresh-token"), "success",
                 "login_not_codewires"),
                (lambda: self.write_login(marker=False), "success", "login_not_codewires"),
                (lambda: self.write_login(mode=0o644), "success", "login_file")):
            with self.subTest(reason=reason, outcome=outcome):
                (self.user_home / ".claude/.credentials.json").unlink(missing_ok=True)
                prepare()
                status, events, output = self.main(["sign_in", outcome], sign_in)
                self.assertEqual(status, 1)
                self.assertEqual(events, [{"event": "failed", "form": "sign_in",
                                           "outcome": outcome, "reason": reason}])
                self.assertNotIn("CW_KIND_SYNTHETIC", output)
        self.assertEqual(self.calls(), [])
        # Once the daemon removed its login (other keys kept), Claude Code
        # has none: it says so, or the broker withholds a request without one.
        self.write_login(login=False, marker=False)
        for mode, cause in (("no-login", "no_login"), ("withheld", "withheld")):
            with self.subTest(mode=mode):
                status, events, output = self.main(["sign_in", "logged_out"],
                                                   self.environ(mode, projected=self.SIGN_IN))
                self.assertEqual(status, 0, output)
                self.assertEqual(events[1], {"event": "claude_session", "form": "sign_in",
                                             "outcome": "logged_out",
                                             "client_version": "2.1.308", "cause": cause})
                self.assertNotIn("canary", output)
        for mode, reason in (("ok", "refusal_not_reported"),
                             ("refused-silent", "refusal_status_missing")):
            with self.subTest(mode=mode):
                status, events, _ = self.main(["sign_in", "logged_out"],
                                              self.environ(mode, projected=self.SIGN_IN))
                self.assertEqual((status, events[-1]["reason"]), (1, reason))

    def test_a_refused_token_must_be_reported_by_claude_code(self):
        status, events, output = self.main(["subscription_token", "refused"],
                                           self.environ("refused"))
        self.assertEqual(status, 0, output)
        self.assertEqual(events[1], {"event": "claude_session", "form": "subscription_token",
                                     "outcome": "refused", "client_version": "2.1.308"})
        self.assertEqual(events[-1], {"event": "complete", "form": "subscription_token",
                                      "outcome": "refused"})
        self.assertNotIn("canary", output)
        for mode, reason in (("ok", "refusal_not_reported"),
                             ("refused-exit-zero", "refusal_not_reported"),
                             ("refused-silent", "refusal_status_missing")):
            with self.subTest(mode=mode):
                status, events, _ = self.main(["subscription_token", "refused"],
                                              self.environ(mode))
                self.assertEqual(status, 1)
                self.assertEqual(events[-1]["reason"], reason)
        # A refusal where success is expected is Claude Code's failure.
        status, events, _ = self.main(["subscription_token", "success"], self.environ("refused"))
        self.assertEqual(events[-1]["reason"], "claude_exit")

    def test_a_withheld_capability_must_be_reported_as_the_brokers_403(self):
        status, events, output = self.main(["subscription_token", "withheld"],
                                           self.environ("withheld"))
        self.assertEqual(status, 0, output)
        self.assertEqual(events[-1], {"event": "complete", "form": "subscription_token",
                                      "outcome": "withheld"})
        self.assertNotIn("canary", output)
        # A provider 401 or a silent failure is not the broker withholding it.
        for mode in ("refused", "refused-silent", "ok"):
            with self.subTest(mode=mode):
                status, events, _ = self.main(["subscription_token", "withheld"],
                                              self.environ(mode))
                self.assertEqual(status, 1)

    def test_a_synthetic_credential_anywhere_in_the_session_fails_before_claude(self):
        for name, value in (
                ("UNRELATED", "prefix-CW_KIND_SYNTHETIC_CLAUDE_TOKEN-suffix"),
                ("UNRELATED", "sk-ant-api03-CW_KIND_SYNTHETIC_ANTHROPIC_KEY-0123"),
                ("UNRELATED", "sk-ant-oat01-CW_KIND_SYNTHETIC_REFUSED_TOKEN-0123"),
                ("UNRELATED", "sk-ant-oat01-CW_KIND_SYNTHETIC_SIGN_IN_ACCESS-000001"),
                ("CW_KIND_SYNTHETIC_CLAUDE_TOKEN", "name")):
            with self.subTest(name=name, value=value):
                status, events, output = self.main(["subscription_token", "success"],
                                                   self.environ(**{name: value}))
                self.assertEqual(status, 1)
                self.assertEqual(events, [{"event": "failed", "form": "subscription_token",
                                           "outcome": "success",
                                           "reason": "credential_in_environment"}])
                self.assertNotIn("CW_KIND_SYNTHETIC", output)
        self.assertEqual(self.calls(), [])

    def test_claude_failures_are_closed_reasons_and_never_print_its_output(self):
        for mode, reason in (
                ("exit", "claude_exit"), ("no-marker", "missing_marker"),
                ("leak", "credential_in_output"), ("stderr-leak", "credential_in_output"),
                ("huge", "claude_output_limit"), ("bad-version", "claude_version")):
            with self.subTest(mode=mode):
                status, events, output = self.main(
                    ["api_key", "success"], self.environ(mode, projected=self.API_KEY))
                self.assertEqual(status, 1)
                self.assertEqual(events[-1], {"event": "failed", "form": "api_key",
                                              "outcome": "success", "reason": reason})
                for private in ("canary", "CW_KIND_SYNTHETIC", "xxxx", "Not Claude"):
                    self.assertNotIn(private, output)
        with patch.object(CLAUDE, "SESSION_TIMEOUT", 0.5):
            status, events, _ = self.main(["api_key", "success"],
                                          self.environ("hang", projected=self.API_KEY))
        self.assertEqual(status, 1)
        self.assertEqual(events[-1]["reason"], "claude_timeout")
        with patch.object(CLAUDE, "CLAUDE_ARGV", (str(self.scratch / "missing-claude"),)):
            status, events, _ = self.main(["api_key", "success"],
                                          self.environ(projected=self.API_KEY))
        self.assertEqual(events[-1]["reason"], "claude_version_start")

    def test_claude_runs_only_after_the_daemon_marked_onboarding_complete(self):
        marked = self.claude_config.read_text()
        outside = self.scratch / "dotfiles-claude.json"
        outside.write_text(marked)
        outside.chmod(0o600)

        def replace_with(make):
            def prepare():
                self.claude_config.unlink()
                make()
            return prepare

        for case, prepare, reason in (
                ("missing", self.claude_config.unlink, "onboarding_missing"),
                ("unmarked", lambda: self.write_claude_config(
                    '{"hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": false}'),
                 "onboarding_not_marked"),
                ("one key", lambda: self.write_claude_config('{"hasCompletedOnboarding": true}'),
                 "onboarding_not_marked"),
                ("truthy", lambda: self.write_claude_config(
                    '{"hasCompletedOnboarding": 1, "hasAcknowledgedCostThreshold": "true"}'),
                 "onboarding_not_marked"),
                ("array", lambda: self.write_claude_config("[]"), "onboarding_not_marked"),
                ("untrusted", lambda: self.write_claude_config(
                    '{"hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true}'),
                 "workspace_not_trusted"),
                ("trust declined", lambda: self.write_claude_config(
                    '{"hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true, '
                    '"projects": {"/workspace": {"hasTrustDialogAccepted": false}}}'),
                 "workspace_not_trusted"),
                ("other folder", lambda: self.write_claude_config(
                    '{"hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true, '
                    '"projects": {"/workspace/app": {"hasTrustDialogAccepted": true}}}'),
                 "workspace_not_trusted"),
                ("projects array", lambda: self.write_claude_config(
                    '{"hasCompletedOnboarding": true, "hasAcknowledgedCostThreshold": true, '
                    '"projects": []}'),
                 "workspace_not_trusted"),
                ("invalid", lambda: self.write_claude_config("{"), "onboarding_not_marked"),
                ("wide mode", lambda: self.write_claude_config(marked, 0o644), "onboarding_file"),
                ("symlink", replace_with(lambda: self.claude_config.symlink_to(outside)),
                 "onboarding_file"),
                ("directory", replace_with(self.claude_config.mkdir), "onboarding_file"),
                ("placeholder", lambda: self.write_claude_config(
                    marked[:-1] + ', "primaryApiKey": "codewire-managed"}'),
                 "credential_in_claude_config"),
                ("credential", lambda: self.write_claude_config(
                    marked[:-1] + ', "x": "CW_KIND_SYNTHETIC_CLAUDE_TOKEN"}'),
                 "credential_in_claude_config")):
            with self.subTest(case=case):
                self.write_claude_config(marked)
                prepare()
                status, events, output = self.main(["subscription_token", "success"],
                                                   self.environ())
                self.assertEqual(status, 1)
                self.assertEqual(events, [{"event": "failed", "form": "subscription_token",
                                           "outcome": "success", "reason": reason}])
                self.assertNotIn("CW_KIND_SYNTHETIC", output)
                self.assertNotIn("numStartups", output)
        self.write_claude_config(marked)
        self.assertEqual(outside.read_text(), marked)
        for home in ("", "relative/home"):
            with self.subTest(home=home):
                status, events, _ = self.main(["subscription_token", "success"],
                                              self.environ(HOME=home))
                self.assertEqual(events[-1]["reason"], "onboarding_home")
        environ = self.environ()
        del environ["HOME"]
        status, events, _ = self.main(["subscription_token", "success"], environ)
        self.assertEqual(events[-1]["reason"], "onboarding_home")
        # The driver only reads the user's file, and Claude Code never runs.
        self.assertEqual(self.claude_config.read_text(), marked)
        self.assertEqual(self.calls(), [])

    def test_arguments_are_closed(self):
        for argv in ([], ["subscription_token"], ["oauth", "success"],
                     ["subscription_token", "maybe"],
                     ["subscription_token", "success", "extra"],
                     # A sign-in is never refused by the fixture, and only a
                     # sign-in can be logged out.
                     ["sign_in", "refused"], ["api_key", "logged_out"],
                     ["subscription_token", "logged_out"]):
            with self.subTest(argv=argv):
                status, events, _ = self.main(argv, self.environ())
                self.assertEqual(status, 1)
                self.assertEqual(events, [{"event": "failed", "form": None, "outcome": None,
                                           "reason": "arguments"}])

    def test_driver_markers_match_the_fixture_and_the_journey(self):
        provider = PROVIDER.read_text(encoding="utf-8")
        helpers = HELPERS.read_text(encoding="utf-8")
        for marker in CLAUDE.CREDENTIAL_MARKERS:
            self.assertIn(marker, provider)
            self.assertIn(marker, helpers)
        self.assertIn(f'const CLAUDE_MARKER: &str = "{CLAUDE.MARKER}";', provider)
        for name in ("KIND_ANTHROPIC_API_KEY", "KIND_CLAUDE_SUBSCRIPTION_TOKEN",
                     "KIND_CLAUDE_REFUSED_TOKEN"):
            value = provider.split(f"pub(super) const {name}: &str =", 1)[1].split(";", 1)[0]
            value = value.strip().strip('"')
            self.assertIn(f"{name}='{value}'\n", helpers)
            # The public CLI's shape rule: printable ASCII without whitespace.
            self.assertTrue(16 <= len(value) <= 1024 and value.isascii() and value.isprintable()
                            and " " not in value)


CLAUDE_RUN_STUB = r"""
RUN_DIR='{run_dir}'
KIND_CLAUDE_SESSION_ATTEMPTS=3
sleep() {{ :; }}
kind_credential_cli() {{
  case "$*" in
    "run --in env-1 --no-tty --detach --output json -- python3 -B -u {driver} {form} {outcome}")
      printf '{{"session_id":"session-1","state":"Starting"}}\n' ;;
    "list env-1 --output json") cat "$RUN_DIR/listing.json" ;;
    "logs env-1 --session session-1 --raw") cat "$RUN_DIR/output.txt" ;;
    *) echo "unexpected: $*" >&2; return 99 ;;
  esac
}}
kind_credential_claude_run env-1 {driver} {form} {outcome}
"""

TOKEN_GET_STUB = r"""
kind_credential_cli() {{
  [ "$*" = "credentials --cloud get claude --output json" ] || return 99
  jq -nc --arg status {status} --arg revision {revision} --argjson left {left} '[{{
    name: "claude", provider: "anthropic", status: $status,
    authenticationKind: "CREDENTIAL_AUTHENTICATION_KIND_OAUTH",
    revocationGeneration: $revision, expiresAtUnix: ((now | floor) + $left | tostring)}}]'
}}
assert_kind_credential_claude_token claude 2
"""


class ClaudeSessionHarness(unittest.TestCase):
    """The host side of the Claude Code journey, against stubbed commands."""

    DRIVER = "/tmp/codewire-kind-claude-session-123456.py"

    def shell(self, body):
        return subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\n'
             'validate_sealed_kind_images() { return 1; }\n' + body,
             "kind-credential-fixture", str(HELPERS)],
            env={"PATH": "/usr/bin:/bin", "ROOT": str(ROOT)},
            capture_output=True, text=True, timeout=300,
        )

    def claude_run(self, output, state="Exited", exit_code=0, form="subscription_token",
                   outcome="success"):
        directory = tempfile.TemporaryDirectory(prefix="kind-claude-run-")
        self.addCleanup(directory.cleanup)
        run_dir = Path(directory.name)
        (run_dir / "listing.json").write_text(json.dumps([
            {"session_id": "other", "state": "Running", "exit_code": None},
            {"session_id": "session-1", "state": state, "exit_code": exit_code}]))
        (run_dir / "output.txt").write_text(output)
        return self.shell(CLAUDE_RUN_STUB.format(run_dir=run_dir, driver=self.DRIVER,
                                                 form=form, outcome=outcome))

    def events(self, form="subscription_token", outcome="success"):
        return (json.dumps({"event": "claude_projection", "form": form,
                            "source": "daemon_session"}) + "\n"
                + json.dumps({"event": "claude_session", "form": form, "outcome": outcome,
                              "client_version": "2.1.308"}) + "\n"
                + json.dumps({"event": "complete", "form": form, "outcome": outcome}) + "\n")

    def test_claude_runs_in_a_daemon_session_and_passes_only_on_its_closed_events(self):
        for form, outcome in (("subscription_token", "success"), ("api_key", "success"),
                              ("subscription_token", "refused"), ("sign_in", "success"),
                              ("sign_in", "logged_out")):
            with self.subTest(form=form, outcome=outcome):
                result = self.claude_run(self.events(form, outcome), form=form,
                                         outcome=outcome)
                self.assertEqual(result.returncode, 0, result.stderr)
        good = self.events()
        for output, state, exit_code in (
                (good, "Exited", 1),
                (good, "Failed", 0),
                (good, "Running", 0),
                (self.events(outcome="refused"), "Exited", 0),
                (self.events("api_key"), "Exited", 0),
                (good.replace("daemon_session", "binding"), "Exited", 0),
                (good.split("\n", 1)[1], "Exited", 0),
                ('{"event":"failed","form":"subscription_token","reason":"claude_exit"}\n',
                 "Exited", 0),
                ("", "Exited", 0)):
            with self.subTest(output=output, state=state, exit_code=exit_code):
                result = self.claude_run(output, state, exit_code)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("stock Claude Code acceptance failed for the subscription_token form",
                              result.stderr)
        # Non-event session output, such as a Python warning, is ignored.
        result = self.claude_run("warning: something\n" + good)
        self.assertEqual(result.returncode, 0, result.stderr)
        for driver, form, outcome in (("/tmp/elsewhere.py", "subscription_token", "success"),
                                      (self.DRIVER, "oauth", "success"),
                                      (self.DRIVER, "api_key", "maybe"),
                                      (self.DRIVER, "sign_in", "refused"),
                                      (self.DRIVER, "api_key", "logged_out")):
            result = self.shell(
                "kind_credential_cli() { echo unexpected-cli; return 97; }\n"
                f"kind_credential_claude_run env-1 '{driver}' '{form}' '{outcome}'\n")
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("unexpected-cli", result.stdout)

    def test_the_driver_is_staged_into_the_exact_workspace_pod(self):
        result = self.shell(r"""
SANDBOX_NS=dev-sandboxes
kubectl() {
  [ "$#" = 13 ] || return 96
  [ "$1 $2 $3 $4 $5 $6 $7 $8 $9 ${10} ${12}" = '-n dev-sandboxes exec -i workspace-pod -c workspace -- sh -c sh' ] || return 99
  [ "${11}" = 'umask 022 && cat > "$1"' ] || return 95
  [[ "${13}" =~ ^/tmp/codewire-kind-claude-session-[0-9]{1,12}\.py$ ]] || return 98
  cmp -s - "$ROOT/scripts/ci/verify/kind/claude_session.py" || return 97
}
kind_credential_claude_stage workspace-pod
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"^/tmp/codewire-kind-claude-session-[0-9]{1,12}\.py\n$")
        result = self.shell("kubectl() { echo unexpected-kubectl; return 97; }\n"
                            "kind_credential_claude_stage Workspace_Pod\n")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("unexpected-kubectl", result.stdout)

    def anthropic_events(self, events, baseline, form, status=200):
        return self.shell(
            "kind_credential_fixture_events() { printf '%s\\n' "
            + shlex.quote(json.dumps(events)) + "; }\n"
            f"assert_kind_credential_anthropic_events {baseline} {form} {status}\n")

    def test_provider_events_must_be_new_answers_for_exactly_the_expected_form(self):
        api = {"event": "anthropic_response", "kind": "api_key", "route": "messages",
               "stream": True, "status": 200, "refused": False, "client_identity": True,
               "anthropic_calls": 1}
        token = dict(api, kind="subscription_token", anthropic_calls=3)
        refused = dict(token, status=401, refused=True, anthropic_calls=5)
        unrelated = {"event": "provider_response", "scenario": "baseline"}
        events = [unrelated, api, dict(api, anthropic_calls=2), token,
                  dict(token, anthropic_calls=4), refused]
        result = self.anthropic_events(events, 0, "api_key")
        self.assertEqual(result.returncode, 1)
        result = self.anthropic_events(events[:3], 0, "api_key")
        self.assertEqual((result.returncode, result.stdout), (0, "2\n"), result.stderr)
        result = self.anthropic_events(events[:5], 2, "subscription_token")
        self.assertEqual((result.returncode, result.stdout), (0, "4\n"), result.stderr)
        result = self.anthropic_events(events, 4, "subscription_token", 401)
        self.assertEqual((result.returncode, result.stdout), (0, "5\n"), result.stderr)
        for later, baseline, form, status in (
                ([], 2, "subscription_token", 200),
                ([dict(token, status=500)], 2, "subscription_token", 200),
                ([dict(token, client_identity=False)], 2, "subscription_token", 200),
                ([dict(api, client_identity=False)], 2, "api_key", 200),
                ([refused], 2, "subscription_token", 200),
                ([dict(refused, refused=False)], 2, "subscription_token", 401),
                ([{"event": "anthropic_rejected", "reason": "placeholder",
                   "anthropic_rejections": 1}], 2, "subscription_token", 200),
                ([token, {"event": "anthropic_rejected", "reason": "credential",
                          "anthropic_rejections": 1}], 2, "subscription_token", 200),
                ([dict(token, route="models")], 2, "subscription_token", 200),
                ([api], 2, "subscription_token", 200)):
            with self.subTest(later=later, status=status):
                result = self.anthropic_events(events[:3] + later, baseline, form, status)
                self.assertEqual(result.returncode, 1)
                self.assertIn("did not see only the", result.stderr)
        for baseline, form, status in (("-1", "api_key", 200), ("x", "api_key", 200),
                                       ("0", "oauth", 200), ("0", "api_key", 500)):
            result = self.anthropic_events(events, baseline, form, status)
            self.assertEqual(result.returncode, 1)

    def test_recorded_selections_name_the_expected_form(self):
        for form, clients, valid in (
                ("api_key", "v1:anthropic", True), ("api_key", "v2:14", True),
                ("subscription_token", "v2:24", True), ("subscription_token", "v2:34", True),
                ("api_key", "v2:24", False), ("subscription_token", "v1:anthropic", False),
                ("subscription_token", "v2:3f", False), ("subscription_token", "", False),
                ("sign_in", "v2:44", True), ("sign_in", "v2:54", True),
                ("sign_in", "v2:24", False), ("sign_in", "v2:45", False),
                ("subscription_token", "v2:44", False), ("api_key", "v2:54", False)):
            with self.subTest(form=form, clients=clients):
                result = self.shell(f"assert_kind_credential_claude_selection '{form}' "
                                    f"'{clients}'\n")
                self.assertEqual(result.returncode == 0, valid, result.stderr)

    def test_token_metadata_is_active_at_the_expected_revision_one_year_out(self):
        def get(status="CREDENTIAL_STATUS_ACTIVE", revision="2", left=365 * 86400 - 60):
            return self.shell(TOKEN_GET_STUB.format(status=status, revision=revision,
                                                    left=left))
        result = get()
        self.assertEqual(result.returncode, 0, result.stderr)
        for result in (get(status="CREDENTIAL_STATUS_REFRESH_FAILED"), get(revision="3"),
                       get(left=100 * 86400)):
            self.assertEqual(result.returncode, 1)
            self.assertIn("is not Active at revision 2", result.stderr)

    def test_managed_clients_are_the_single_live_binding_record(self):
        workspace = "57f35d02-39f9-40ed-b9e1-bc4a64ad3b0e"
        expected = (f"-n codewire-e2e exec -i deploy/postgres -- psql -U codewire -d codewire "
                    f"-v ON_ERROR_STOP=1 -v environment={ENVIRONMENT} -v pod_uid={workspace} -At")
        result = self.shell(
            "NS=codewire-e2e\nsleep() { :; }\nkubectl() {\n"
            f"  [ \"$*\" = '{expected}' ] || return 99\n"
            "  grep -Fq 'FROM sandbox_workspace_bindings' || return 98\n"
            "  printf 'v2:24\\n'\n}\n"
            f"kind_credential_managed_clients {ENVIRONMENT} {workspace}\n")
        self.assertEqual((result.returncode, result.stdout), (0, "v2:24\n"), result.stderr)
        for rows in ("", "v2:24\\nv2:24", "not-a-selection"):
            with self.subTest(rows=rows):
                result = self.shell(
                    "NS=codewire-e2e\nsleep() { :; }\n"
                    f"kubectl() {{ cat >/dev/null; printf '{rows}'; }}\n"
                    f"kind_credential_managed_clients {ENVIRONMENT} {workspace}\n")
                self.assertEqual(result.returncode, 1)
                self.assertIn("no single live workspace binding selection", result.stderr)
        result = self.shell("kubectl() { echo unexpected-kubectl; return 97; }\n"
                            f"kind_credential_managed_clients not-a-uuid {workspace}\n")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("unexpected-kubectl", result.stdout)

    def test_anthropic_requests_never_join_the_daemon_authority_pairing(self):
        # The Claude journey runs after the native smoke's authority check, so
        # none of its epoch admissions can land inside that journey. Its
        # Anthropic requests, logged anywhere, are not the Codex requests the
        # check pairs with its probes or counts toward the journey's start.
        lines, probes = HarnessGuards.authority_lines()
        anthropic = {"timestamp": "2026-10-04T01:00:00.000000Z",
                     "target": "codewire_credential_broker::timing",
                     "fields": {"event": "proxied_request", "slot": "anthropic",
                                "route": "anthropic-api", "total_ms": 40,
                                "outcome": "response", "status": 200,
                                "authority": "evaluated", "cache": "miss"}}
        mixed = [anthropic] + [entry for line in lines for entry in (line, anthropic)]
        result = HarnessGuards.authority_changes(self, mixed, probes)
        self.assertEqual(result.returncode, 0, result.stderr)
        logs = "\n".join(json.dumps(line) for line in mixed[:7])
        result = self.shell('''
NS=codewire-e2e
kubectl() {
  [ "$*" = '-n codewire-e2e logs deployment/codewire-credential-service -c credential-service' ] ||
    return 99
  printf '%%s\\n' '%s'
}
kind_credential_codex_request_count
''' % logs)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "3"), result.stderr)
        # The check runs inside the native smoke, which the suite and the full
        # gate run before the Claude journey.
        native = HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1]
        self.assertIn("assert_kind_credential_authority_changes",
                      native.split("\n)\n", 1)[0])

    def test_release_mode_never_runs_the_synthetic_claude_journey(self):
        result = self.shell(
            "log() { :; }\n"
            "kubectl() { echo unexpected-kubectl; return 98; }\n"
            "kind_credential_cli() { echo unexpected-cli; return 97; }\n"
            "CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release\n"
            "kind_credential_claude_session\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_claude_journey_uses_stdin_material_daemon_sessions_and_proves_recovery(self):
        flow = HELPERS.read_text().split("kind_credential_claude_session() (", 1)[1].split(
            "\n)\n", 1)[0]
        self.assertLess(flow.index("set -E"), flow.index("kind_workspace_runtime_image"))
        self.assertIn('printf \'%s\' "$KIND_ANTHROPIC_API_KEY" |\n'
                      '    kind_credential_cli credentials --cloud add anthropic', flow)
        self.assertIn('printf \'%s\' "$KIND_CLAUDE_SUBSCRIPTION_TOKEN" |\n'
                      '    kind_credential_cli credentials --cloud add claude-subscription',
                      flow)
        # No value is ever an argument of a command; each reaches stdin only.
        self.assertEqual(flow.count('"$KIND_ANTHROPIC_API_KEY"'), 1)
        self.assertEqual(flow.count('"$KIND_CLAUDE_SUBSCRIPTION_TOKEN"'), 2)
        self.assertEqual(flow.count('"$KIND_CLAUDE_REFUSED_TOKEN"'), 1)
        for name in ("KIND_ANTHROPIC_API_KEY", "KIND_CLAUDE_SUBSCRIPTION_TOKEN",
                     "KIND_CLAUDE_REFUSED_TOKEN"):
            for line in flow.splitlines():
                if f'"${name}"' in line:
                    self.assertTrue(line.strip().startswith("printf '%s' "), line)
        self.assertIn("for form in api_key subscription_token; do", flow)
        # Claude Code never runs through kubectl exec: only the driver is staged.
        self.assertNotIn("python3 -B -u -", flow)
        ordered = [
            'update="$(kind_credential_cli --cloud update "$environment"',
            'pod="$(wait_kind_credential_restarted_workspace "$environment" "$generation")"',
            'clients="$(kind_credential_managed_clients "$environment" "$pod_uid")"',
            'assert_kind_credential_claude_selection "$form" "$clients"',
            'driver="$(kind_credential_claude_stage "$pod")"',
            'kind_credential_claude_run "$environment" "$driver" "$form" success',
            'baseline="$(assert_kind_credential_anthropic_events "$baseline" "$form" 200)"',
            'printf \'%s\' "$KIND_CLAUDE_REFUSED_TOKEN" |\n'
            '    kind_credential_cli credentials --cloud rotate "$token_name"',
            'assert_kind_credential_claude_token "$token_name" 2',
            'kind_credential_claude_run "$environment" "$driver" subscription_token refused',
            'assert_kind_credential_anthropic_events "$baseline" subscription_token 401',
            'printf \'%s\' "$KIND_CLAUDE_SUBSCRIPTION_TOKEN" |\n'
            '    kind_credential_cli credentials --cloud rotate "$token_name"',
            'assert_kind_credential_claude_token "$token_name" 3',
            'kind_credential_claude_run "$environment" "$driver" subscription_token success',
            'assert_kind_credential_anthropic_events "$baseline" subscription_token 200',
            'kind_credential_cli --cloud rm "$environment"',
            'wait_kind_credential_environment "$environment" destroyed',
            'kind_credential_cli credentials --cloud revoke "$credential"',
            'kind_credential_cli credentials --cloud delete "$credential" --yes',
        ]
        positions = [flow.index(step) for step in ordered]
        self.assertEqual(positions, sorted(positions))
        # The token stays Active after the provider refusal.
        refusal = flow.index("subscription_token refused")
        self.assertIn('assert_kind_credential_claude_token "$token_name" 2',
                      flow[refusal:flow.index('"$KIND_CLAUDE_SUBSCRIPTION_TOKEN" |', refusal)])
        # #2972: the suite and the full gate hand the Claude stages to the
        # native stage, which runs them during its rotation idle; without the
        # native stage the suite runs them one after another.
        suite = (ROOT / "scripts/ci/verify/kind/suites/credential-journey.sh").read_text()
        self.assertIn('    kind_credential_native_smoke "${during[@]}"\n', suite)
        self.assertLess(suite.index("during+=(claude-session)"), suite.index("during+=(claude-sign-in)"))
        self.assertLess(suite.index('kind_credential_native_smoke "${during[@]}"'),
                        suite.index("\n      kind_credential_claude_session\n"))
        gate = (ROOT / "scripts/ci/verify/kind/common.sh").read_text().split(
            "deploy_agent_sandbox_and_smoke() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("\n  kind_credential_native_smoke claude-session claude-sign-in\n", gate)
        self.assertNotIn("kind_credential_claude_session", gate)

    def claude_login(self, output, status=0, mode="deliver", extra="3"):
        directory = tempfile.TemporaryDirectory(prefix="kind-claude-login-")
        self.addCleanup(directory.cleanup)
        return self.shell('''
RUN_DIR='%s'
SANDBOX_NS=dev-sandboxes
kind_credential_workspace() { [ "$1" = '%s' ] || return 97; printf 'workspace-pod\\n'; }
kubectl() {
  [ "$*" = '-n dev-sandboxes exec -i workspace-pod -c workspace -- python3 -B -u - %s%s' ] || return 99
  cmp -s - "$ROOT/scripts/ci/verify/kind/claude_login.py" || return 98
  printf '%%s' '%s'
  return %d
}
kind_credential_claude_login '%s' %s %s
''' % (directory.name, ENVIRONMENT, mode, " " + extra if extra else "", output, status,
       ENVIRONMENT, mode, extra))

    def test_claude_login_step_passes_only_on_its_own_completion(self):
        delivered = '{"event":"delivered","generation":3}\n'
        result = self.claude_login(delivered + '{"event":"complete","mode":"deliver"}\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"generation":3', result.stdout)
        result = self.claude_login('{"event":"revoked_login_removed","unrelated":"kept"}\n'
                                   '{"event":"complete","mode":"revoked"}\n',
                                   mode="revoked", extra="")
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
                result = self.claude_login(output, status)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Claude Code login acceptance failed in mode deliver",
                              result.stderr)

    def test_a_failed_redelivery_prints_the_events_and_both_containers_login_checks(self):
        directory = tempfile.TemporaryDirectory(prefix="kind-claude-redelivery-")
        self.addCleanup(directory.cleanup)
        checks = Path(directory.name) / "checks.log"
        checks.write_text('{"fields":{"message":"hosted Claude login checked",'
                          '"claude_login":"LoggedOut"}}\n')
        events = ('{"event":"own_login_untouched","unrelated":"kept","waited_ms":45000}\n'
                  '{"event":"logout_stays_logged_out","marker":"kept","unrelated":"kept",'
                  '"waited_ms":45000}\n'
                  '{"event":"redelivered","generation":5,"unrelated":"absent","other_keys":0}')
        result = self.shell('''
SANDBOX_NS=dev-sandboxes
kind_credential_workspace() { [ "$1" = env-1 ] || return 97; printf 'workspace-pod\\n'; }
kubectl() {
  [ "$*" = '-n dev-sandboxes logs workspace-pod -c workspace --since=30m' ] || return 99
  printf '%%s\\n' 'an unrelated daemon line' \\
    '{"fields":{"message":"hosted Claude login checked","claude_login":"Written"}}'
}
kind_credential_fixture_events() { printf '[]\\n'; }
kind_credential_claude_redelivery_diagnostics env-1 %s %s
''' % (shlex.quote(events), shlex.quote(str(checks))))
        self.assertEqual(result.returncode, 0, result.stderr)
        for expected in ('"unrelated":"kept","waited_ms"', '"other_keys":0',
                         '"claude_login":"LoggedOut"', '"claude_login":"Written"'):
            self.assertIn(expected, result.stdout)
        self.assertLess(result.stdout.index("LoggedOut"), result.stdout.index("Written"))
        self.assertNotIn("an unrelated daemon line", result.stdout)

    def test_the_latest_sign_in_token_is_the_fixtures_last_issue(self):
        def latest(events):
            return self.shell("kind_credential_fixture_events() { printf '%s\\n' "
                              + shlex.quote(json.dumps(events)) + "; }\n"
                              "kind_credential_claude_latest_token\n")
        issued = [{"event": "claude_sign_in_token", "grant": "authorization_code",
                   "generation": 4},
                  {"event": "anthropic_response"},
                  {"event": "claude_sign_in_token", "grant": "refresh_token", "generation": 5}]
        result = latest(issued)
        self.assertEqual((result.returncode, result.stdout), (0, "5 refresh_token\n"),
                         result.stderr)
        result = latest(issued[:2])
        self.assertEqual(result.stdout, "4 authorization_code\n")
        for events in ([], [{"event": "anthropic_response"}],
                       [dict(issued[0], grant="password")], [dict(issued[0], generation="4")]):
            with self.subTest(events=events):
                self.assertNotEqual(latest(events).returncode, 0)

    ROTATION_STUB = r"""
RUN_DIR='{run_dir}'
SANDBOX_NS=dev-sandboxes
KIND_CLAUDE_ROTATION_READY_SECONDS=100
sleep() {{ command sleep 0.02; }}
kind_credential_workspace() {{ printf 'workspace-pod\n'; }}
kubectl() {{
  case "$*" in
    "-n dev-sandboxes exec -i workspace-pod -c workspace -- python3 -B -u - rotation 3 "/tmp/codewire-kind-claude-rotation-*)
      cmp -s - "$ROOT/scripts/ci/verify/kind/claude_login.py" || return 98
      touch "$RUN_DIR/ready"
      # The probe ends only after the reconnect.
      for _ in $(seq 1 200); do [ -e "$RUN_DIR/reconnected" ] && break; command sleep 0.01; done
      [ -e "$RUN_DIR/reconnected" ] || {{ printf '%s\n' '{{"event":"failed","mode":"rotation","reason":"rotation_not_delivered"}}'; return 1; }}
      printf '%s\n' '{output}' '{{"event":"complete","mode":"rotation"}}' ;;
    "-n dev-sandboxes exec workspace-pod -c workspace -- test -e /tmp/codewire-kind-claude-rotation-"*)
      [ "{ready}" = yes ] && [ -e "$RUN_DIR/ready" ] ;;
    *) echo "unexpected: $*" >&2; return 99 ;;
  esac
}}
kind_credential_claude_connect() {{
  [ "$*" = "kind-claude match reconnect" ] || return 96
  [ -e "$RUN_DIR/ready" ] || return 95
  touch "$RUN_DIR/reconnected"
}}
kind_credential_claude_rotation env-1 kind-claude 3
"""

    def rotation(self, output, ready="yes"):
        directory = tempfile.TemporaryDirectory(prefix="kind-claude-rotation-")
        self.addCleanup(directory.cleanup)
        return self.shell(self.ROTATION_STUB.format(run_dir=directory.name, output=output,
                                                    ready=ready))

    def test_rotation_reconnects_only_after_the_first_turn_and_prints_the_adopted_generation(self):
        adopted = {"event": "rotation_adopted", "previous": 3, "generation": 5,
                   "first_turn": 3, "second_turn": 5, "restarted": False}
        result = self.rotation(json.dumps(adopted))
        self.assertEqual((result.returncode, result.stdout), (0, "5\n"), result.stderr)
        for changed in ({"second_turn": 3}, {"generation": 3}, {"first_turn": 4},
                        {"restarted": True}):
            with self.subTest(changed=changed):
                result = self.rotation(json.dumps(dict(adopted, **changed)))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("missing its adopted generation", result.stderr)
        # A probe that never answers its first turn is never reconnected.
        result = self.rotation(json.dumps(adopted), ready="no")
        self.assertEqual(result.returncode, 1)
        self.assertIn("never answered its first turn", result.stderr)

    def test_claude_sign_in_journey_delivers_rotates_and_removes_the_login_in_order(self):
        flow = HELPERS.read_text().split("kind_credential_claude_sign_in() (", 1)[1].split(
            "\n)\n", 1)[0]
        connect = HELPERS.read_text().split("kind_credential_claude_connect() {", 1)[1].split(
            "\n}\n", 1)[0]
        # The code is pasted on the CLI's stdin, after the printed URL's own
        # state; it is never an argument. A reconnect only adds --yes.
        self.assertIn('<"$fifo"', connect)
        self.assertIn('connect claude --name "$name" "${confirm[@]}"', connect)
        self.assertIn("reconnect) confirm=(--yes)", connect)
        self.assertIn("printf '%s#%s\\n' \"$KIND_CLAUDE_SIGN_IN_CODE\" \"$state\" >&\"$writer\"",
                      connect)
        ordered = [
            'kind_credential_claude_connect "$name" mismatch',
            "grep -Fq 'not from this Claude sign-in'",
            'kind_credential_claude_connect "$name" match',
            'assert_kind_credential_claude_sign_in "$name" 1',
            'latest="$(kind_credential_claude_latest_token)"',
            'kind_credential_cli credentials --cloud --profile "$profile" set anthropic "$name"',
            'assert_kind_credential_claude_selection sign_in "$clients"',
            'kind_credential_claude_login "$environment" deliver "$((exchanged + 1))"',
            '[ "$(kind_credential_claude_latest_token)" = "$delivered refresh_token" ]',
            'kind_credential_claude_run "$environment" "$driver" sign_in success',
            'baseline="$(assert_kind_credential_anthropic_events "$baseline" sign_in 200)"',
            'revision="$(assert_kind_credential_claude_sign_in "$name" 2)"',
            'rotated="$(kind_credential_claude_rotation "$environment" "$name" "$delivered")"',
            'kind_credential_claude_login "$environment" own-login',
            'kind_credential_claude_login "$environment" logout',
            # Stop replaces the Pod, so its login checks are saved first.
            'kind_credential_claude_login_checks "$pod" >"$checks"',
            'kind_credential_cli --cloud stop "$environment"',
            'kind_credential_cli --cloud start "$environment"',
            'kind_credential_claude_login "$environment" redelivered',
            "the redelivered Claude login dropped the file's other keys",
            'kind_credential_claude_redelivery_diagnostics "$environment"',
            'kind_credential_cli credentials --cloud revoke "$name"',
            'kind_credential_claude_login "$environment" revoked',
            'driver="$(kind_credential_claude_stage "$pod")"',
            'kind_credential_claude_run "$environment" "$driver" sign_in logged_out',
            'length == $baseline',
            'kind_credential_cli --cloud rm "$environment"',
            'kind_credential_cli credentials --cloud --profile "$profile" delete --yes',
            'kind_credential_cli credentials --cloud delete "$name" --yes',
        ]
        positions = []
        cursor = 0
        for step in ordered:
            cursor = flow.index(step, cursor)
            positions.append(cursor)
        self.assertEqual(positions, sorted(positions))
        # Claude Code itself never runs through kubectl exec in the journey:
        # the session driver is staged, and the login probe pins its source.
        self.assertNotIn("claude_session.py", flow)
        self.assertIn("prebuilt-release", flow.split("log ", 1)[0])
        suite = (ROOT / "scripts/ci/verify/kind/suites/credential-journey.sh").read_text()
        self.assertLess(suite.index("\n      kind_credential_claude_session\n"),
                        suite.index("\n      kind_credential_claude_sign_in\n"))
        gate = (ROOT / "scripts/ci/verify/kind/common.sh").read_text().split(
            "deploy_agent_sandbox_and_smoke() {", 1)[1].split("\n}", 1)[0]
        self.assertIn("kind_credential_native_smoke claude-session claude-sign-in", gate)

    def test_the_login_probe_is_staged_from_its_checked_in_source(self):
        helpers = HELPERS.read_text()
        self.assertIn('< "$ROOT/scripts/ci/verify/kind/claude_login.py"', helpers)
        source = (ROOT / "scripts/ci/verify/kind/claude_login.py").read_text()
        self.assertIn('READY = re.compile(r"/tmp/codewire-kind-claude-rotation-[0-9]{1,12}")',
                      source)
        self.assertIn('ready="/tmp/codewire-kind-claude-rotation-${RANDOM}${RANDOM}"', helpers)


class RotationIdleStages(unittest.TestCase):
    """#2972: the Claude stages run during the native stage's rotation idle."""

    def shell(self, body, timeout=300):
        directory = tempfile.TemporaryDirectory(prefix="kind-rotation-stages-")
        self.addCleanup(directory.cleanup)
        self.run_dir = Path(directory.name)
        return subprocess.run(
            ["/bin/bash", "-c", 'set -euo pipefail\nsource "$1"\n'
             'validate_sealed_kind_images() { return 1; }\n'
             'log() { printf "[kind-e2e] %s\\n" "$*" >&2; }\n' + body,
             "kind-credential-fixture", str(HELPERS)],
            env={"PATH": "/usr/bin:/bin", "ROOT": str(ROOT), "RUN_DIR": str(self.run_dir)},
            capture_output=True, text=True, timeout=timeout,
        )

    @staticmethod
    def native_flow():
        return HELPERS.read_text().split("kind_credential_native_smoke() (", 1)[1].split("\n)\n", 1)[0]

    def test_the_stages_run_through_the_idle_and_end_before_the_fixture_is_read(self):
        flow = self.native_flow()
        ordered = [
            'start_kind_credential_bridge_renewal "$pod" "$renewal_stop"',
            'start_kind_credential_admission_watch "$environment" "$pod" "$relay_pod" "$admission"',
            'start_kind_credential_rotation_stages "$@"\n',
            '< "$ROOT/scripts/ci/verify/kind/codex_session.py"',
            'stop_kind_credential_bridge_renewal "$pod" "$renewal_stop" "$renewal_pid" || return $?',
            'finish_kind_credential_rotation_stages\n',
            'assert_kind_credential_rotation "$environment"',
            'assert_kind_credential_bridge_renewal',
            "assert_kind_credential_provider_counts 2",
            'kind_credential_cli --cloud stop "$environment"',
            'set_kind_credential_member_role "$environment" admin',
            'kind_credential_cli --cloud rm "$environment"',
        ]
        positions = [flow.index(step) for step in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(flow.count("start_kind_credential_rotation_stages"), 1)
        self.assertEqual(flow.count("\n  finish_kind_credential_rotation_stages\n"), 1)
        # Started as a plain statement: Bash ignores errexit in anything a
        # function called under || starts, and the stages rely on it.
        self.assertIn("\n  start_kind_credential_rotation_stages \"$@\"\n", flow)
        # Between the start and the wait nothing reads the fixture, restarts a
        # service or changes the shared membership.
        window = flow[flow.index("start_kind_credential_rotation_stages"):
                      flow.index("\n  finish_kind_credential_rotation_stages\n")]
        for reader in ("kind_credential_fixture_events", "assert_kind_credential", "set_kind_credential_member_role",
                       "restart_kind_orchestration", "restart_credential_service"):
            self.assertNotIn(reader, window)
        # A failing native stage waits for them first, so each cleans up.
        exit_traps = [line for line in flow.splitlines()
                      if line.strip().startswith("trap '") and line.rstrip().endswith("EXIT")]
        self.assertEqual(len(exit_traps), 1)
        waits = exit_traps[0].index('[ -z "$KIND_CREDENTIAL_ROTATION_STAGES_PID" ] || '
                                    "finish_kind_credential_rotation_stages || true;")
        self.assertLess(waits, exit_traps[0].index("cleanup_kind_credential_stage"))

    def test_stages_run_in_order_with_errexit_and_stop_at_the_first_failure(self):
        result = self.shell(
            "kind_credential_claude_session() ( echo session-ran >&2 )\n"
            "kind_credential_claude_sign_in() ( echo sign-in-ran >&2 )\n"
            "run_kind_credential_rotation_stages claude-session claude-sign-in\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(result.stderr.index("session-ran"), result.stderr.index("sign-in-ran"))
        self.assertIn("credentials stage claude-sign-in green during the native rotation idle", result.stderr)
        result = self.shell(
            "kind_credential_claude_session() (\n"
            "  echo session-started >&2\n"
            "  false\n"
            "  echo session-continued-after-failure >&2\n"
            ")\n"
            "kind_credential_claude_sign_in() ( echo sign-in-ran >&2 )\n"
            "set +e\n"
            "(run_kind_credential_rotation_stages claude-session claude-sign-in)\n"
            "status=$?\n"
            "set -e\n"
            'echo "status=$status" >&2\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("session-started", result.stderr)
        self.assertNotIn("session-continued-after-failure", result.stderr)
        self.assertNotIn("sign-in-ran", result.stderr)
        self.assertIn("::error::credentials stage claude-session failed during the native rotation idle (status 1)",
                      result.stderr)
        self.assertIn("status=1", result.stderr)

    def test_stages_refuse_to_run_where_bash_ignores_errexit(self):
        for call in ("run_kind_credential_rotation_stages claude-session || status=$?",
                     "if run_kind_credential_rotation_stages claude-session; then :; else status=$?; fi",
                     "starter() { (run_kind_credential_rotation_stages claude-session) & wait $!; }\n"
                     "starter || status=$?"):
            with self.subTest(call=call):
                result = self.shell(
                    "kind_credential_claude_session() ( echo session-ran >&2; false; echo session-continued >&2 )\n"
                    "status=0\n"
                    f"{call}\n"
                    'echo "status=$status" >&2\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("the credentials stages need errexit in force; start them as a plain statement",
                              result.stderr)
                self.assertNotIn("session-ran", result.stderr)
                self.assertRegex(result.stderr, r"status=[1-9]")

    def test_an_unknown_stage_is_refused_before_any_stage_runs(self):
        for command in ("run_kind_credential_rotation_stages", "start_kind_credential_rotation_stages"):
            with self.subTest(command=command):
                result = self.shell(
                    "kind_credential_claude_session() ( echo session-ran >&2 )\n"
                    "status=0\n"
                    f"{command} claude-session native || status=$?\n"
                    'echo "status=$status pid=${KIND_CREDENTIAL_ROTATION_STAGES_PID:-none}" >&2\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("native is not a credentials stage that runs during the native rotation idle",
                              result.stderr)
                self.assertIn("status=2 pid=none", result.stderr)
                self.assertNotIn("session-ran", result.stderr)

    def test_start_returns_at_once_and_finish_waits_reports_and_fails(self):
        result = self.shell(
            'release="$RUN_DIR/release"\n'
            "kind_credential_claude_session() (\n"
            '  while [ ! -e "$release" ]; do sleep 0.1; done\n'
            "  echo session-finished >&2\n"
            ")\n"
            "kind_credential_claude_sign_in() ( echo sign-in-ran >&2 )\n"
            "start_kind_credential_rotation_stages claude-session claude-sign-in\n"
            '[ -n "$KIND_CREDENTIAL_ROTATION_STAGES_PID" ]\n'
            'kill -0 "$KIND_CREDENTIAL_ROTATION_STAGES_PID"\n'
            "echo started-while-running >&2\n"
            'touch "$release"\n'
            "finish_kind_credential_rotation_stages\n"
            '[ -z "$KIND_CREDENTIAL_ROTATION_STAGES_PID" ]\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(result.stderr.index("started-while-running"), result.stderr.index("session-finished"))
        self.assertLess(result.stderr.index("session-finished"), result.stderr.index("sign-in-ran"))
        self.assertIn("the credentials stages that ran during the native rotation idle passed", result.stderr)
        logs = list(self.run_dir.glob("credential-rotation-stages.*"))
        self.assertEqual(len(logs), 1)
        self.assertIn("sign-in-ran", logs[0].read_text())
        result = self.shell(
            "kind_credential_claude_session() ( echo session-failing >&2; return 7 )\n"
            "kind_credential_claude_sign_in() ( echo sign-in-ran >&2 )\n"
            "start_kind_credential_rotation_stages claude-session claude-sign-in\n"
            "status=0\n"
            "finish_kind_credential_rotation_stages || status=$?\n"
            'echo "status=$status" >&2\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("session-failing", result.stderr)
        self.assertNotIn("sign-in-ran", result.stderr)
        self.assertIn("::error::a credentials stage that ran during the native rotation idle failed (status 7)",
                      result.stderr)
        self.assertIn("status=1", result.stderr)
        # No stages: nothing starts and the wait returns.
        result = self.shell(
            "start_kind_credential_rotation_stages\n"
            '[ -z "$KIND_CREDENTIAL_ROTATION_STAGES_PID" ]\n'
            "finish_kind_credential_rotation_stages\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.run_dir.glob("credential-rotation-stages.*")), [])

    def test_the_native_stages_traps_stay_its_own(self):
        result = self.shell(
            "set -E\n"
            "trap 'echo native-error-trap >&2' ERR\n"
            "trap 'echo native-exit-trap >&2' EXIT\n"
            "kind_credential_claude_session() ( echo session-failing >&2; return 3 )\n"
            "start_kind_credential_rotation_stages claude-session\n"
            "status=0\n"
            "finish_kind_credential_rotation_stages || status=$?\n"
            "trap - ERR EXIT\n"
            'echo "status=$status" >&2\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=1", result.stderr)
        self.assertNotIn("native-exit-trap", result.stderr)
        log, = self.run_dir.glob("credential-rotation-stages.*")
        self.assertIn("session-failing", log.read_text())
        self.assertNotIn("native-error-trap", log.read_text())

    def test_release_mode_names_the_stages_it_does_not_run(self):
        result = self.shell(
            "kubectl() { echo unexpected-kubectl >&2; return 98; }\n"
            "kind_credential_claude_session() ( echo unexpected-session >&2 )\n"
            "CODEWIRE_KIND_PRODUCT_IMAGE_MODE=prebuilt-release\n"
            "kind_credential_native_smoke claude-session claude-sign-in\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("synthetic native credential composition is not selected; "
                      "neither are claude-session claude-sign-in", result.stderr)
        self.assertNotIn("unexpected", result.stderr)

    def test_the_fixture_compares_each_environments_authentications_only_with_its_own(self):
        source = (ROOT / "crates/codewire-credential-service/src/runtime/kind/authentication.rs").read_text()
        self.assertIn("previous: HashMap<String, PreviousAuthentication>", source)
        self.assertIn("self.previous.get(environment_id)", source)
        self.assertIn("fn another_environment_in_between_neither_hides_nor_invents_a_change()", source)


if __name__ == "__main__":
    unittest.main()
