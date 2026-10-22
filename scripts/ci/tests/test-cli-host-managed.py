#!/usr/bin/env python3
"""Focused actual-host harness admission and isolated Linux kernel custody proof."""
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("host_managed", ROOT / "scripts/dev/test-cli-host-managed.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


class Admission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cwhmt-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.payload = self.root / "payload"
        self.payload.mkdir(mode=0o700)
        binary = Path("/usr/bin/true").read_bytes()
        self.files = []
        for name in ("claude", "codex"):
            path = self.payload / name
            path.write_bytes(binary)
            path.chmod(0o500)
            self.files.append({"path": name, "size": len(binary), "sha256": hashlib.sha256(binary).hexdigest(), "mode": 0o500})
        self.manifest = {"schema": "codewire.host-agent-payloads/v1", "platform": "linux/amd64",
                         "source": {"kind": "workspace-oci", "image_digest": "sha256:" + "a" * 64,
                                    "verification_sha256": "b" * 64, "source_revision": "c" * 40},
                         "agents": {n: {"version": v, "entry": n} for n, v in H.VERSIONS.items()},
                         "host_runtime": {"kind": "ordinary-trusted-linux-os", "loader": "/lib64/ld-linux-x86-64.so.2", "sonames": H.SONAMES},
                         "files": self.files}
        self.path = self.payload / "agents.json"
        self.write()

    def admit(self, path=None):
        path = path or self.path
        # This synthetic fixture owns and supplies its expected input pin.
        return H.admit_agents(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        self.path.write_text(json.dumps(self.manifest))
        self.path.chmod(0o600)

    def test_scratch_parent_refuses_noexec_and_public_directory(self):
        with mock.patch.object(os, "fstatvfs", return_value=SimpleNamespace(f_flag=os.ST_NOEXEC)), \
                self.assertRaisesRegex(H.Failure, "executable agent payloads"):
            H.admit_scratch(self.root)
        with mock.patch.object(os, "fstatvfs", return_value=SimpleNamespace(f_flag=0)):
            self.assertEqual(H.admit_scratch(self.root), self.root)
            self.root.chmod(0o755)
            with self.assertRaisesRegex(H.Failure, "unsafe directory permissions"):
                H.admit_scratch(self.root)
            self.root.chmod(0o700)

    def test_complete_real_elf_inventory_and_streamed_readonly_staging(self):
        admitted = self.admit()
        target = self.root / "staged"
        target.mkdir(mode=0o700)
        payload, bins = H.stage_agents(admitted, target)
        self.assertEqual(set(admitted["elf"]), {"claude", "codex"})
        for name in H.VERSIONS:
            self.assertEqual((payload / name).read_bytes(), (self.payload / name).read_bytes())
            self.assertEqual(stat.S_IMODE((payload / name).stat().st_mode), 0o500)
            self.assertIn(str(payload / name), (bins / name).read_text())
        self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o500)
        # This test does not execute the synthetic entries as real agents.
        H.remove_owned_tree(target, (target.stat().st_dev, target.stat().st_ino))
        self.assertFalse(target.exists())

    def test_expected_manifest_pin_refuses_before_parse_staging_or_tool_launch(self):
        expected = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with mock.patch.object(H, "json_value", side_effect=AssertionError("must not parse")), \
             mock.patch.object(H.subprocess, "run", side_effect=AssertionError("must not launch")):
            for pin in (None, True, "f" * 63, "F" * 64, "invalid", "0" * 64):
                with self.assertRaises(H.Failure): H.admit_agents(self.path, pin)
        self.assertEqual(set(os.listdir(self.root)), {"payload"})
        admitted = H.admit_agents(self.path, expected)
        self.assertEqual(admitted["expected_sha256"], expected)
        self.assertEqual(admitted["sha256"], expected)

    def test_unknown_fields_duplicate_json_and_wrong_versions_refuse(self):
        self.manifest["extra"] = True
        self.write()
        with self.assertRaises(H.Failure): self.admit()
        self.manifest.pop("extra")
        self.manifest["agents"]["codex"]["version"] = "0.0.0"
        self.write()
        with self.assertRaises(H.Failure): self.admit()
        with self.assertRaises(H.Failure): H.json_value('{"x":1,"x":2}')

    def test_uncovered_hidden_empty_and_untracked_members_refuse(self):
        for name in (".ignored", "untracked"):
            path = self.payload / name
            path.write_text("not admitted")
            with self.assertRaises(H.Failure): self.admit()
            path.unlink()
        extra = self.payload / "empty"
        extra.mkdir(mode=0o700)
        with self.assertRaises(H.Failure): self.admit()

    def test_symlink_hardlink_special_and_unsafe_ancestry_refuse(self):
        extra = self.payload / "extra"
        extra.symlink_to(self.payload / "codex")
        with self.assertRaises(H.Failure): self.admit()
        extra.unlink()
        os.link(self.payload / "codex", extra)
        with self.assertRaises(H.Failure): self.admit()
        extra.unlink()
        os.mkfifo(extra)
        with self.assertRaises(H.Failure): self.admit()
        extra.unlink()
        self.payload.chmod(0o777)
        with self.assertRaises(H.Failure): self.admit()
        self.payload.chmod(0o700)
        linked = self.root / "linked"
        linked.symlink_to(self.payload, target_is_directory=True)
        with self.assertRaises(H.Failure): self.admit(linked / "agents.json")

    def test_corrupt_bytes_modes_bound_and_replacement_refuse(self):
        codex = self.payload / "codex"
        original = codex.read_bytes()
        codex.chmod(0o600)
        codex.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        codex.chmod(0o500)
        with self.assertRaises(H.Failure): self.admit()
        codex.chmod(0o600)
        codex.write_bytes(original)
        codex.chmod(0o500)
        admitted = self.admit()
        codex.rename(self.payload / "old")
        codex.write_bytes(original)
        codex.chmod(0o500)
        target = self.root / "staged"
        target.mkdir(mode=0o700)
        with self.assertRaises(H.Failure): H.stage_agents(admitted, target)
        self.manifest["files"][0]["size"] = H.MAX_AGENT_FILE + 1
        self.write()
        with self.assertRaises(H.Failure): self.admit()

    def test_stream_hash_does_not_capture_large_bytes_and_exact_identity(self):
        path = self.root / "large"
        data = b"a" * 70000 + b"end"
        path.write_bytes(data)
        path.chmod(0o400)
        digest, metadata, buffered = H.scan_regular(path, len(data))
        self.assertEqual(buffered, b"")
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())
        self.assertEqual(metadata.st_size, len(data))
        with self.assertRaises(H.Failure): H.scan_regular(path, len(data) - 1)

    def test_cleanup_refuses_external_aliases_and_links_before_first_unlink(self):
        owned = self.root / "owned"
        owned.mkdir(mode=0o700)
        leaf = owned / "a"
        leaf.write_text("preserve")
        os.link(leaf, self.root / "outside")
        identity = (owned.stat().st_dev, owned.stat().st_ino)
        with self.assertRaises(H.Failure): H.remove_owned_tree(owned, identity)
        self.assertEqual(leaf.read_text(), "preserve")
        (self.root / "outside").unlink()
        (owned / "unknown").symlink_to(leaf)
        with self.assertRaises(H.Failure): H.remove_owned_tree(owned, identity)
        self.assertEqual(leaf.read_text(), "preserve")
        (owned / "unknown").unlink()
        H.remove_owned_tree(owned, identity)
        self.assertFalse(owned.exists())

    def test_cleanup_exact_readonly_tree_and_managed_entry_preserves_neighbor(self):
        owned = self.root / "owned"
        owned.mkdir(mode=0o700)
        version = owned / "store" / "versions" / ("a" * 64)
        version.mkdir(parents=True, mode=0o700)
        (version / "cw").write_text("synthetic immutable asset")
        (version / "cw").chmod(0o500)
        version.chmod(0o500)
        entry = owned / "entry"
        entry.mkdir(mode=0o700)
        (entry / "cw").symlink_to(version / "cw")
        neighbor = self.root / "neighbor"
        neighbor.write_text("preserve")
        H.remove_owned_tree(owned, (owned.stat().st_dev, owned.stat().st_ino))
        self.assertEqual(neighbor.read_text(), "preserve")
        self.assertFalse(owned.exists())

    def test_closed_paths_redaction_and_exact_notification_identity(self):
        for name in ("../cw", "a//cw", "/cw", "a/auth.json", "a/credentials.json"):
            with self.assertRaises(H.Failure): H.relative(name)
        text = "cwlocalbroker" + "a" * 32 + " cwhm_" + "b" * 64
        self.assertNotIn("cwlocalbroker", H.scrub(text))
        self.assertNotIn("cwhm_", H.scrub(text))
        message = "12345678-1234-4234-9234-123456789abc"
        self.assertEqual(H.notification_id(message), "b4f3216a-70cf-4eaa-9511-a4aad9cd7b2f")

    def test_private_ready_partial_missing_oversize_and_multiple_records_refuse(self):
        for payload in (b"partial", b"x" * 2049 + b"\n", b"one\ntwo\n"):
            read, write = os.pipe()
            with os.fdopen(read, "rb", buffering=0) as stream:
                os.write(write, payload)
                os.close(write)
                with self.assertRaises(H.Failure): H.read_private_ready(stream, timeout=0.1)
        read, write = os.pipe()
        with os.fdopen(read, "rb", buffering=0) as stream:
            os.write(write, b"partial")
            started = time.monotonic()
            with self.assertRaises(H.Failure): H.read_private_ready(stream, timeout=0.05)
            self.assertLess(time.monotonic() - started, 0.5)
            os.close(write)
        read, write = os.pipe()
        with os.fdopen(read, "rb", buffering=0) as stream:
            os.write(write, b'{"ready":true}\n')
            os.close(write)
            self.assertEqual(H.read_private_ready(stream), b'{"ready":true}\n')

    def test_composed_broker_receipt_refuses_missing_grammar_stale_source_and_wrong_feature(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        pins = {}
        for name in H.BROKER_INPUTS:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_text("synthetic source:" + name)
            pins[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        binary = self.root / "broker"
        binary.write_bytes(Path("/usr/bin/true").read_bytes())
        binary.chmod(0o500)
        receipt = {"schema": "codewire.host-agent-broker-build/v1", "source_revision": "c" * 40,
                   "source_tree_sha256": "d" * 64, "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "executable_size": binary.stat().st_size, "toolchain": "1.99.0", "profile": "ci",
                   "features": ["host-agent-synthetic-smoke"], "inputs": pins, "build_exit": 0, "source_unchanged": True}
        receipt_path = self.root / "broker.json"
        # The complete-graph producer is stubbed only for this wire/physical
        # inventory test; this is never a real build or acceptance receipt.
        producer = mock.Mock()
        producer.head_revision.return_value = "c" * 40
        producer.source_tree_sha256.return_value = "d" * 64
        receipt_path.write_text(json.dumps(receipt))
        self.assertEqual(H.admit_broker(binary, receipt_path, source, producer), receipt)
        native = source / "crates/codewire-credential-broker/src/runtime/native_managed_smoke.rs"
        native.unlink()
        with self.assertRaises(OSError): H.admit_broker(binary, receipt_path, source, producer)
        native.write_text("changed original grammar")
        with self.assertRaises(H.Failure): H.admit_broker(binary, receipt_path, source, producer)
        native.write_text("synthetic source:crates/codewire-credential-broker/src/runtime/native_managed_smoke.rs")
        producer.source_tree_sha256.return_value = "e" * 64
        with self.assertRaises(H.Failure): H.admit_broker(binary, receipt_path, source, producer)
        producer.source_tree_sha256.return_value = "d" * 64
        for change in ({"features": ["platform"]}, {"build_exit": True}, {"source_unchanged": False}, {"extra": 1}):
            receipt_path.write_text(json.dumps(dict(receipt, **change)))
            with self.assertRaises(H.Failure): H.admit_broker(binary, receipt_path, source, producer)


class Setup(unittest.TestCase):
    class FirstLaunch(Exception):
        pass

    def run_prefix(self, refused=None):
        # Exercise the real run/setup path up to its first managed launch.
        # Only CLI/kernel actor boundaries and admitted agent --version are
        # mocked: no daemon, broker or agent process is started by this case.
        with tempfile.TemporaryDirectory(prefix="cwhms-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            journey = object.__new__(H.Journey)
            journey.root, journey.workspace = root, root / "project"
            journey.workspace.mkdir(mode=0o700)
            marker = journey.workspace / "preserved"
            marker.write_text("same workspace")
            journey.entry = root / "entry" / "cw"
            journey.entry.parent.mkdir(mode=0o700)
            journey.store = root / "store"
            immutable = journey.store / "versions" / ("a" * 64) / "cw"
            immutable.parent.mkdir(parents=True, mode=0o700)
            immutable.write_text("synthetic admitted A")
            journey.entry.symlink_to(immutable)
            journey.cw = str(root / "a" / "cw")
            journey.assets = [{"path": root / n, "identity": {"sha256": n * 64}} for n in ("a", "b")]
            journey.environment, journey.daemon_binding = None, None
            journey.owned, journey.conversations, journey.actors = [], {}, []
            journey.setup_daemon_actor = journey.setup_proof = None
            journey.agent_input, journey.agent_versions = {}, {}
            journey.env = {"HOME": str(root / "home"), "PATH": "/usr/bin:/bin"}
            journey.capability = None
            journey.selection, journey.check = mock.Mock(), mock.Mock()
            journey.popen = mock.Mock(return_value=SimpleNamespace(pid=300))
            environment = "12345678-1234-4234-9234-123456789abc"
            created = {"id": environment, "name": "host-managed-proof", "type": "host", "placement": "local",
                       "state": "running", "path": str(journey.workspace), "created_at": "synthetic"}
            capability = "cwhm_" + "d" * 64
            events, commands, inherited = [], [], []
            initial = mock.Mock(pid=100, birth=10, path=str(immutable), image_sha256="a" * 64,
                                args=[b"cw", b"_host-daemon", b"--environment", environment.encode()])
            initial.dead.return_value = False
            baseline = mock.Mock(pid=200, birth=20, path=str(immutable), image_sha256="a" * 64,
                                 args=initial.args.copy())
            baseline.dead.return_value = False
            sentinel = mock.Mock()
            broker = mock.Mock()
            journey.broker_actor = broker

            def call(*argv, **options):
                commands.append(argv)
                if argv[0] == "install":
                    return {"identity": journey.assets[0]["identity"], "generation": 1}
                operation = argv[0]
                self.assertIn(operation, ("create", "stop", "start"))
                events.append(operation)
                if operation == "create":
                    inherited.append(dict(journey.env))
                    return created.copy()
                self.assertIn(environment, argv)
                self.assertNotIn("--env", argv)
                self.assertEqual(options, {"data": True})
                if operation == "stop":
                    if refused == "stop-failed":
                        raise H.Failure("public setup stop refused")
                    initial.dead.return_value = refused != "death-unknown"
                    result = dict(created, state="stopped")
                    if refused == "stop-identity": result["id"] = "87654321-4321-4324-9234-cba987654321"
                    return result
                self.assertEqual(operation, "start")
                self.assertTrue(initial.dead(), "start preceded captured daemon death")
                inherited.append(dict(journey.env))
                result = created.copy()
                if refused == "start-identity": result["path"] = str(root / "another-project")
                return result

            def ready():
                events.append("broker-ready")
                journey.capability = capability
                journey.env.update(CW_HOST_AGENT_CAPABILITY=capability, ANTHROPIC_AUTH_TOKEN=capability,
                                   ANTHROPIC_BASE_URL="http://127.0.0.1:32001/anthropic")
                if refused == "projection-missing": journey.env.pop("CW_HOST_AGENT_CAPABILITY")

            def pin(path):
                self.assertEqual(path, root / "hosts" / environment / "daemon.sock")
                if "start" not in events:
                    events.append("pin-initial")
                    return initial, (1, 10)
                events.append("pin-baseline")
                if refused == "same-birth": baseline.pid, baseline.birth = initial.pid, initial.birth
                if refused == "wrong-image": baseline.image_sha256 = "b" * 64
                return baseline, (1, 20)

            def until(probe, accept, **options):
                self.assertEqual(options, {"timeout": 10})
                value = probe()
                H.require(accept(value), "setup daemon death is unknown")
                events.append("initial-death")
                return value

            def launch(*args):
                # This proves why the old prefix is wrong: its create-time
                # inherited environment cannot contain the later ready data.
                H.require(len(inherited) == 2 and inherited[1].get("CW_HOST_AGENT_CAPABILITY") == capability and
                          inherited[1].get("ANTHROPIC_AUTH_TOKEN") == capability and
                          inherited[1].get("ANTHROPIC_BASE_URL") == "http://127.0.0.1:32001/anthropic",
                          "first agent inherited the pre-broker daemon environment")
                self.assertEqual(events, ["create", "pin-initial", "broker-ready", "stop", "initial-death", "start", "pin-baseline"])
                self.assertTrue(initial.dead())
                self.assertEqual(journey.daemon_binding, (200, 20, str(immutable), "a" * 64, (1, 20)))
                self.assertEqual(journey.actors, [baseline])
                self.assertEqual(journey.environment, environment)
                self.assertEqual(marker.read_text(), "same workspace")
                self.assertNotIn(capability, json.dumps(journey.setup_proof))
                raise self.FirstLaunch()

            def version(argv, **options):
                name = Path(argv[0]).name
                output = "codex-cli " + H.VERSIONS[name] if name == "codex" else H.VERSIONS[name] + " (Claude Code)"
                return SimpleNamespace(returncode=0, stdout=output, stderr="")

            journey.call, journey.start_broker, journey.until = call, ready, until
            journey.launch = mock.Mock(side_effect=launch)
            with mock.patch.object(H, "stage_agents", return_value=(root / "payload", root / "bins")), \
                 mock.patch.object(H, "subreaper"), mock.patch.object(H, "socket_process", side_effect=pin), \
                 mock.patch.object(H, "Process", return_value=sentinel), mock.patch.object(H.subprocess, "run", side_effect=version):
                if refused:
                    with self.assertRaises(H.Failure): journey.run()
                    journey.launch.assert_not_called()
                    if refused in ("projection-missing", "stop-failed", "death-unknown", "stop-identity"):
                        self.assertNotIn("start", events)
                else:
                    with self.assertRaises(self.FirstLaunch): journey.run()
                    journey.launch.assert_called_once()
                    self.assertEqual(sum(v[0] == "stop" for v in commands), 1)
                    self.assertEqual(sum(v[0] == "start" for v in commands), 1)
                    self.assertFalse(any("env" in v for v in commands), commands)
                    self.assertTrue(journey.setup_proof["public_stop_confirmed"])
                    self.assertTrue(journey.setup_proof["initial_daemon_death_observed"])
                    self.assertTrue(journey.setup_proof["public_start_confirmed"])
                    self.assertNotIn("CW_HOST_AGENT_CAPABILITY", inherited[0])
                    self.assertIn(str(root / "bins"), inherited[1]["PATH"])
                self.assertEqual(marker.read_text(), "same workspace")
                self.assertNotIn(capability, json.dumps(commands))
                sentinel.verify.assert_called()

    def test_broker_projection_stop_start_precedes_first_conversation_and_baseline(self):
        self.run_prefix()

    def test_projection_or_public_cleanup_identity_refusal_prevents_first_launch(self):
        for refusal in ("projection-missing", "stop-failed", "death-unknown", "stop-identity", "start-identity", "same-birth", "wrong-image"):
            with self.subTest(refusal=refusal): self.run_prefix(refusal)


class Interruption(unittest.TestCase):
    class Finished(Exception):
        pass

    class Clock:
        def __init__(self):
            self.now = 0.0

        def sleep(self, duration):
            self.now += duration

    def record(self, session, message, **changes):
        return dict({"id": message, "target_session_id": session, "driver_id": session + "-driver",
                     "action": "message", "state": "completed", "native_acknowledged": True,
                     "turn_id": None, "result": "CWCLAUDE synthetic response"}, **changes)

    def run_interrupt_prefix(self, refusal=None):
        # Run the actual acceptance entrypoint through its interrupt group. All
        # process/CLI boundaries are synthetic; no provider or daemon is started.
        with tempfile.TemporaryDirectory(prefix="cwhmi-") as temp:
            root = Path(temp)
            journey = object.__new__(H.Journey)
            journey.root, journey.workspace = root, root / "project"
            journey.workspace.mkdir(mode=0o700)
            journey.entry, journey.store = root / "entry" / "cw", root / "store"
            journey.env, journey.agent_input, journey.agent_versions = {}, {}, {}
            journey.assets = [{"path": root / name, "identity": {"sha256": name * 64}} for name in ("a", "b")]
            journey.environment, journey.deadline = "owned-environment", 1500
            journey.conversations, journey.observations, journey.notifications = {}, [], []
            journey.checks, journey.owned = [], []
            journey.selection, journey.setup_environment = mock.Mock(), mock.Mock()
            journey.popen = mock.Mock(return_value=SimpleNamespace(pid=123))
            actor = mock.Mock()
            actor.dead.return_value = False
            clock = self.Clock()
            records, active, turns, held_at, interrupt_times = {}, {}, {}, {}, []
            threads = {"lead": "codex-thread", "worker": "claude-thread"}

            def notification(source):
                message = H.notification_id(source["id"])
                record = self.record("lead", message, action="notification",
                                     source={"session_id": "worker", "driver_id": "worker-driver", "message_id": source["id"]})
                records[message] = record
                return record

            def launch(name, agent, parent=None, prompt=None):
                journey.conversations[name] = {"driver": name + "-driver", "agent": agent}
                journey.owned.append(name)
                result = {"session": {"session_id": name, "parent_session_id": parent}}
                if prompt:
                    record = self.record(name, "initial-worker")
                    records[record["id"]] = record
                    notification(record)
                    result["message"] = record
                return result

            def turn(session):
                message = f"{session}-turn-{len(records)}"
                record = self.record(session, message, turn_id=message if session == "lead" else None)
                records[message] = record
                if session == "worker": notification(record)
                return record

            def inbox(session):
                messages = [r.copy() for r in records.values() if r["target_session_id"] == session]
                return {"driver": {"driver_id": "replacement-driver" if session == "worker" and
                                   refusal == "final-driver" and "worker-interrupt" in records else session + "-driver",
                                   "native_thread_id": threads[session],
                                   "active_message_id": active.get(session), "current_turn_id": turns.get(session),
                                   "phase": "busy" if active.get(session) else "idle", "capabilities": {"interrupt": True}},
                        "messages": messages,
                        "parent": {"session_id": "lead", "driver_id": "lead-driver"} if session == "worker" else None}

            def call(*argv, **options):
                operation = argv[0]
                if operation == "install": return {"identity": journey.assets[0]["identity"], "generation": 1}
                if operation in ("send", "steer"): return SimpleNamespace(returncode=1)
                if operation == "inbox": return inbox(argv[2])
                if operation == "wait":
                    return SimpleNamespace(stdout=json.dumps(records[argv[2]]), returncode=0)
                if operation == "msg":
                    session, text = argv[2], argv[3]
                    message = f"{session}-message-{len(records)}"
                    if text.startswith("CW_FIXTURE_TOOL "):
                        words = text.splitlines()[0].split()
                        (journey.workspace / words[-1]).write_text(words[3])
                        record = self.record(session, message)
                    else:
                        self.assertTrue(text.startswith("CW_FIXTURE_HOLD "))
                        held_at[session] = clock.now
                        active[session] = message
                        turns[session] = "held-codex-turn" if session == "lead" else None
                        record = self.record(session, message, state="running", native_acknowledged=session == "lead",
                                             turn_id=turns[session])
                    records[message] = record
                    return record.copy()
                self.assertEqual(operation, "interrupt")
                self.assertEqual(argv[2], "--session")
                session = argv[3]
                original = records[active[session]]
                interrupt_times.append((session, clock.now - held_at[session]))
                control = self.record(session, session + "-interrupt", action="interrupt", result="interrupted",
                                      expected_active_message_id=original["id"], expected_turn_id=turns[session])
                original["state"] = "interrupted"
                if session == "worker":
                    if refusal == "control-ack": control["native_acknowledged"] = False
                    if refusal == "wrong-active": control["expected_active_message_id"] = "another-message"
                    if refusal == "wrong-turn": control["expected_turn_id"] = "another-turn"
                    if refusal == "wrong-driver": control["driver_id"] = "another-driver"
                    if refusal == "unknown": original["state"] = "unknown"
                    if refusal == "conversation": threads[session] = "replacement-thread"
                    parent = notification(original)
                    if refusal == "parent-ack": parent["native_acknowledged"] = False
                    if refusal == "parent-duplicate":
                        records["duplicate"] = dict(parent, id="duplicate")
                records[control["id"]] = control
                active[session], turns[session] = None, None
                return control.copy()

            def check(label):
                journey.checks.append(label)
                if label == "native-interrupt/claude-steer-and-undetected-controls-refused": raise self.Finished()

            def version(argv, **options):
                agent = Path(argv[0]).name
                return SimpleNamespace(returncode=0, stdout="codex-cli " + H.VERSIONS[agent] if agent == "codex"
                                       else H.VERSIONS[agent] + " (Claude Code)", stderr="")

            journey.call, journey.launch, journey.turn, journey.check = call, launch, turn, check
            with mock.patch.object(H, "stage_agents", return_value=(root / "payload", root / "bins")), \
                 mock.patch.object(H, "subreaper"), mock.patch.object(H, "Process", return_value=actor), \
                 mock.patch.object(H.subprocess, "run", side_effect=version), \
                 mock.patch.object(H.time, "monotonic", side_effect=lambda: clock.now), \
                 mock.patch.object(H.time, "sleep", side_effect=clock.sleep):
                if refusal:
                    with self.assertRaises(H.Failure): journey.run()
                    self.assertNotIn("native-interrupt/claude-steer-and-undetected-controls-refused", journey.checks)
                else:
                    with self.assertRaises(self.Finished): journey.run()
                    self.assertEqual([session for session, _ in interrupt_times], ["lead", "worker"])
                    self.assertTrue(all(elapsed >= 2 for _, elapsed in interrupt_times))
                    held = next(r for r in records.values() if r["target_session_id"] == "worker" and r["state"] == "interrupted")
                    observed = next(r for r in journey.observations if r["message_id"] == held["id"])
                    self.assertIs(held["native_acknowledged"], False)
                    self.assertIs(observed["native_acknowledged"], False)
                    self.assertEqual(observed["interrupt_message_id"], "worker-interrupt")
                    self.assertEqual(journey.notifications.count((held["id"], "worker", "lead")), 1)
                    self.assertEqual(threads["worker"], "claude-thread")

    def test_claude_stream_without_early_user_ack_is_interrupted_and_notified_once(self):
        self.run_interrupt_prefix()

    def test_control_unknown_conversation_and_parent_refusals(self):
        for refusal in ("control-ack", "wrong-active", "wrong-turn", "wrong-driver", "unknown", "conversation", "final-driver", "parent-ack", "parent-duplicate"):
            with self.subTest(refusal=refusal): self.run_interrupt_prefix(refusal)

    def bare(self, agent="claude"):
        journey = object.__new__(H.Journey)
        journey.conversations = {"worker": {"driver": "worker-driver", "agent": agent}}
        journey.deadline, journey.observations = time.monotonic() + 90, []
        return journey

    def held_inbox(self, **changes):
        return {"driver": dict({"driver_id": "worker-driver", "native_thread_id": "thread", "phase": "busy",
                                "active_message_id": "held", "current_turn_id": None}, **changes),
                "messages": [self.record("worker", "held", state="running", native_acknowledged=False)]}

    def test_hold_requires_continuous_running_busy_active_dwell(self):
        for agent in ("claude", "codex"):
            journey, clock = self.bare(agent), self.Clock()

            def inbox(session):
                # A gap resets dwell, while the same native turn may continue.
                value = self.held_inbox(active_message_id="another" if 1 <= clock.now < 1.4 else "held",
                                        current_turn_id="same-turn" if agent == "codex" else None)
                value["messages"][0].update(native_acknowledged=agent == "codex", turn_id=value["driver"]["current_turn_id"])
                return value

            journey.inbox = inbox
            with mock.patch.object(H.time, "monotonic", side_effect=lambda: clock.now), \
                 mock.patch.object(H.time, "sleep", side_effect=clock.sleep):
                journey.held("worker", "held", "thread")
            self.assertGreaterEqual(clock.now, 3.4)
        for field, value in (("phase", "idle"), ("active_message_id", "another")):
            journey, clock = self.bare(), self.Clock()
            journey.inbox = lambda session: self.held_inbox(**{field: value})
            with mock.patch.object(H.time, "monotonic", side_effect=lambda: clock.now), \
                 mock.patch.object(H.time, "sleep", side_effect=clock.sleep), self.assertRaises(H.Failure):
                journey.held("worker", "held", "thread")
        journey, clock = self.bare(), self.Clock()
        pending = self.held_inbox()
        pending["messages"][0]["state"] = "accepted"
        journey.inbox = lambda session: pending
        with mock.patch.object(H.time, "monotonic", side_effect=lambda: clock.now), \
             mock.patch.object(H.time, "sleep", side_effect=clock.sleep), self.assertRaises(H.Failure):
            journey.held("worker", "held", "thread")

    def test_codex_hold_requires_native_ack_and_native_turn(self):
        for acknowledged, turn in ((False, "turn"), (True, None), (1, "turn")):
            journey, clock = self.bare("codex"), self.Clock()
            inbox = self.held_inbox(current_turn_id=turn)
            inbox["messages"][0]["native_acknowledged"] = acknowledged
            inbox["messages"][0]["turn_id"] = turn
            journey.inbox = lambda session: inbox
            with mock.patch.object(H.time, "monotonic", side_effect=lambda: clock.now), \
                 mock.patch.object(H.time, "sleep", side_effect=clock.sleep), self.assertRaises(H.Failure):
                journey.held("worker", "held", "thread")

    def codex_turn_refusal(self, gap=False, mismatch=False):
        journey, clock = self.bare("codex"), self.Clock()

        def inbox(session):
            current = "second-native-turn" if not mismatch and clock.now >= 1.4 else "first-native-turn"
            value = self.held_inbox(current_turn_id=current,
                                    active_message_id="another" if gap and 1 <= clock.now < 1.4 else "held")
            value["messages"][0].update(native_acknowledged=True,
                                        turn_id="foreign-native-turn" if mismatch else current)
            return value

        journey.inbox = inbox
        reason = "running Codex message differs from its native turn" if mismatch else "held Codex native turn changed"
        with mock.patch.object(H.time, "monotonic", side_effect=lambda: clock.now), \
             mock.patch.object(H.time, "sleep", side_effect=clock.sleep), self.assertRaisesRegex(H.Failure, reason):
            journey.held("worker", "held", "thread")

    def test_codex_changing_native_turn_refuses_before_interrupt(self):
        self.codex_turn_refusal()

    def test_codex_native_turn_pin_survives_inactivity_gap(self):
        self.codex_turn_refusal(gap=True)

    def test_codex_running_record_must_match_native_turn(self):
        self.codex_turn_refusal(mismatch=True)

    def test_ended_missing_duplicate_or_rebound_hold_refuses(self):
        cases = []
        for state in ("completed", "error", "unknown", "interrupted"):
            inbox = self.held_inbox(); inbox["messages"][0]["state"] = state; cases.append(inbox)
        inbox = self.held_inbox(); inbox["messages"] = []; cases.append(inbox)
        inbox = self.held_inbox(); inbox["messages"] *= 2; cases.append(inbox)
        for field in ("target_session_id", "driver_id"):
            inbox = self.held_inbox(); inbox["messages"][0][field] = "replacement"; cases.append(inbox)
        for field in ("native_thread_id", "driver_id"):
            cases.append(self.held_inbox(**{field: "replacement"}))
        for inbox in cases:
            journey = self.bare()
            journey.inbox = mock.Mock(return_value=inbox)
            with self.assertRaises(H.Failure): journey.held("worker", "held", "thread")
            journey.inbox.assert_called_once_with("worker")

    def test_false_original_ack_exception_requires_exact_claude_interrupt(self):
        original = self.record("worker", "held", state="interrupted", native_acknowledged=False)
        control = self.record("worker", "control", action="interrupt", expected_active_message_id="held")
        for field, value in (("native_acknowledged", False), ("native_acknowledged", 1), ("state", "unknown"),
                             ("action", "message"), ("expected_active_message_id", "another"),
                             ("target_session_id", "another"), ("driver_id", "another")):
            journey = self.bare()
            journey.call = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(original)))
            with self.assertRaises(H.Failure):
                journey.message("held", "interrupted", claude_interrupt=dict(control, **{field: value}))
            self.assertEqual(journey.observations, [])
        for field, value in (("id", "another"), ("state", "completed"), ("state", "unknown"),
                             ("action", "notification"), ("native_acknowledged", None), ("native_acknowledged", 0),
                             ("driver_id", "another"), ("target_session_id", "another")):
            journey = self.bare()
            journey.call = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(dict(original, **{field: value}))))
            with self.assertRaises(H.Failure): journey.message("held", "interrupted", claude_interrupt=control)
            self.assertEqual(journey.observations, [])
        journey = self.bare()
        foreign = dict(original, driver_id="foreign-driver")
        journey.call = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(foreign)))
        with self.assertRaises(H.Failure):
            journey.message("held", "interrupted", claude_interrupt=dict(control, driver_id="foreign-driver"))
        self.assertEqual(journey.observations, [])

    def test_completed_control_and_codex_ack_requirements_stay_strict(self):
        for action, state, agent in (("message", "completed", "claude"), ("interrupt", "completed", "claude"),
                                     ("message", "interrupted", "codex"), ("message", "interrupted", "claude")):
            journey = self.bare(agent)
            record = self.record("worker", "held", action=action, state=state, native_acknowledged=False)
            journey.call = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(record)))
            with self.assertRaises(H.Failure): journey.message("held", state)
            self.assertEqual(journey.observations, [])
        journey = self.bare("codex")
        record = self.record("worker", "held", state="interrupted", native_acknowledged=False)
        control = self.record("worker", "control", action="interrupt", expected_active_message_id="held")
        journey.call = mock.Mock(return_value=SimpleNamespace(stdout=json.dumps(record)))
        with self.assertRaises(H.Failure): journey.message("held", "interrupted", claude_interrupt=control)


class Kernel(unittest.TestCase):
    def case(self, name):
        # Parent sentinel is outside the isolated subreaper lineage.
        sibling = subprocess.Popen(["/usr/bin/sleep", "60"])
        handle = os.pidfd_open(sibling.pid)
        try:
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--kernel-case", name],
                                    env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(select.select([handle], [], [], 0)[0], "unrelated sibling was signalled")
            return json.loads(result.stdout)
        finally:
            signal.pidfd_send_signal(handle, signal.SIGTERM)
            sibling.wait(timeout=5)
            os.close(handle)

    def test_actual_subreaper_normal_family_echild_without_salvage(self):
        proof = self.case("normal")
        self.assertTrue(proof["echild"])
        self.assertEqual(proof["salvage"], [])

    def test_detached_doublefork_term_resistant_late_child_salvage_is_not_success(self):
        proof = self.case("detached")
        self.assertTrue(proof["echild"])
        self.assertTrue(proof["salvage"])
        self.assertFalse(proof["product_success"])
        self.assertTrue(any(row[2] == signal.SIGKILL for row in proof["salvage"]))

    def test_kernel_socket_derived_cloexec_identity_and_replacement_refusal(self):
        proof = self.case("socket")
        self.assertTrue(proof["kernel_socket_pidfd"])
        self.assertTrue(proof["cloexec"])
        self.assertTrue(proof["replacement_refused"])

    def test_non_sigchld_clone_child_must_prevent_plain_echild(self):
        proof = self.case("clone")
        self.assertTrue(proof["plain_echild_while_clone_alive"])
        self.assertTrue(proof["echild"])
        self.assertFalse(proof["product_success"])


def kernel_case(name):
    H.subreaper(True)
    if name == "normal":
        # The child ends on its own once its input closes, not on a timer that
        # admission under load could outlast. It is pinned only once its exec
        # is visible: Popen can return while the child still runs this
        # interpreter's image.
        child = subprocess.Popen(["/usr/bin/cat"], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL)
        image = os.path.realpath("/usr/bin/cat")
        while True:
            try:
                if os.readlink(f"/proc/{child.pid}/exe") == image:
                    break
            except FileNotFoundError:
                pass
            assert child.poll() is None, "the child ended before its exec was visible"
            time.sleep(0.001)
        pin = H.Process(child.pid, parent=os.getpid())
        child.stdin.close()
        child.wait(timeout=5)
        if pin:
            assert pin.dead()
            pin.close()
        proof = H.reap_family(timeout=2)
    elif name == "detached":
        read, write = os.pipe()
        launcher = os.fork()
        if launcher == 0:
            os.close(read)
            os.setsid()
            first = os.fork()
            if first != 0:
                os._exit(0)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            os.write(write, b"ready\n")
            os.close(write)
            time.sleep(0.3)
            late = os.fork()
            if late == 0:
                time.sleep(8)
                os._exit(0)
            time.sleep(8)
            os._exit(0)
        os.close(write)
        assert os.read(read, 6) == b"ready\n"
        os.close(read)
        os.waitpid(launcher, 0)
        # No census snapshot can authorize removal while the family lives.
        try:
            H.reap_family(timeout=0.4)
        except H.Failure:
            pass
        else:
            raise AssertionError("normal shutdown incorrectly proved clean")
        proof = H.reap_family(timeout=5, salvage=True)
        proof["product_success"] = False
    elif name == "socket":
        with tempfile.TemporaryDirectory(prefix="cwhmk-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            path = root / "peer.sock"
            read, write = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(read)
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(str(path))
                listener.listen(1)
                os.write(write, b"1")
                os.close(write)
                connection, _ = listener.accept()
                connection.close()
                time.sleep(5)
                os._exit(0)
            os.close(write)
            assert os.read(read, 1) == b"1"
            os.close(read)
            pin, _ = H.socket_process(path)
            import fcntl
            cloexec = bool(fcntl.fcntl(pin.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            pin.verify()
            pin.signal(signal.SIGTERM, direct=True)
            os.waitpid(pid, 0)
            try:
                pin.verify()
            except H.Failure:
                refused = True
            else:
                refused = False
            pin.close()
            proof = {"kernel_socket_pidfd": True, "cloexec": cloexec, "replacement_refused": refused,
                     **H.reap_family(timeout=2)}
    elif name == "clone":
        # raw fork-like clone with exit_signal=0: plain waitpid must exclude it.
        # No Python callback/custom stack executes, and __WALL proves cleanup.
        library = ctypes.CDLL(None, use_errno=True)
        library.syscall.restype = ctypes.c_long
        syscall_number = 56  # amd64 SYS_clone; fixture is platform closed.
        assert os.uname().machine == "x86_64"
        pid = library.syscall(syscall_number, 0, 0, 0, 0, 0)
        assert pid >= 0, "raw clone is unavailable"
        if pid == 0:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(8)
            os._exit(0)
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            plain = True
        else:
            plain = False
        assert plain, "plain waitpid unexpectedly included non-SIGCHLD clone"
        proof = H.reap_family(timeout=5, salvage=True)
        proof.update(plain_echild_while_clone_alive=True, product_success=False)
    else:
        raise AssertionError("unknown closed kernel fixture")
    print(json.dumps(proof))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--kernel-case":
        kernel_case(sys.argv[2])
    else:
        unittest.main()
