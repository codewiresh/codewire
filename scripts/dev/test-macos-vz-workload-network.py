#!/usr/bin/env python3
"""Synthetic coordinator tests: no VM, credentials or external network."""

import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "workload_network_tested", Path(__file__).with_name("macos-vz-workload-network.py")
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
m = module
c = m.common
old = m.load_sibling("workload_network_old_test_support", "test-macos-vz-production-boot.py")

CHILD_COMMON = old.COMMON.replace(
    'sys.argv[1] == "production-init-fixture"', 'sys.argv[1] == "workload-network-fixture"'
) + r'''
import hashlib, hmac
def framed_read(stream):
    return exact(stream, struct.unpack(">I", exact(stream, 4))[0])
def native_result(stream, value):
    stream.sendall(frame(json.dumps({"result": value, "schemaVersion": 4}, sort_keys=True, separators=(",", ":")).encode()))
'''

NATIVE_CHILD = r'''
assert sys.argv[1] == "workload-network-fixture"
opts = options()
assert set(opts) == {"--control-fd"}
control = socket.socket(fileno=int(opts["--control-fd"]))
control.settimeout(4)
data, ancillary, flags, _ = control.recvmsg(16388, socket.CMSG_SPACE(10 * array.array("i").itemsize))
assert flags == 0 and len(ancillary) == 1
assert ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
fds = array.array("i"); fds.frombytes(ancillary[0][2])
assert len(fds) == len(set(fds)) == 10
size = struct.unpack(">I", data[:4])[0]; data = data[4:]
data += exact(control, size - len(data))
config = json.loads(data)
assert config["schemaVersion"] == 4 and config["serviceBinding"]["size"] == 4096
assert set(config) == {"schemaVersion", "vmID", "generation", "cpuCount", "memoryMiB", "daemonVsockPort", "kernel", "initialRamdisk", "seedDisk", "stateDisk", "rootDisk", "setupDisk", "runNonce", "serviceInitialRamdisk", "serviceBinding"}
identities = set()
for index, fd in enumerate(fds[:8]):
    info = os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_mode & 0o7777 == 0o600 and info.st_nlink == 1
    identities.add((info.st_dev, info.st_ino))
    assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == (os.O_RDWR if index in (3, 4) else os.O_RDONLY)
assert len(identities) == 8
progress, daemon = [socket.socket(fileno=fd) for fd in fds[8:]]
for stream in (progress, daemon): stream.settimeout(4)
binding = json.loads(os.read(fds[7], 4096).rstrip(b"\0"))
assert binding["kind"] == "product-network" and binding["role"] == "service"
assert binding["vmID"] == config["vmID"] and binding["runNonce"] == config["runNonce"]
assert binding["networkKey"] == (b"k" * 32).hex()
import uuid
identity = uuid.UUID(config["vmID"]).bytes
nonce = bytes.fromhex(binding["runNonce"]); key = bytes.fromhex(binding["statusKey"])
sequence = 0
def status(code, waits=None):
    global sequence
    sequence += 1
    value = bytearray(128); value[:8] = b"CWPNST1\0"; value[8:10] = bytes([2, code])
    value[16:32] = identity; value[32:40] = (1).to_bytes(8, "little")
    value[40:72] = nonce; value[72:80] = sequence.to_bytes(8, "little")
    if waits is not None: value[80:96] = struct.pack("<4i", *waits)
    value[96:] = hmac.new(key, b"codewire-product-network-status-v1\0" + value[:96], hashlib.sha256).digest()
    if MODE == "forged-status": value[127] ^= 1
    control.sendall(frame(b"R\x02" + value))
def command(prefix, code, sequence):
    value = framed_read(control)
    assert len(value) == 130 and value[:2] == prefix + b"\x02"
    body = value[2:]
    assert body[:8] == b"CWPNCT1\0" and body[8:10] == bytes([2, code])
    assert body[16:32] == identity and body[40:72] == nonce
    assert int.from_bytes(body[72:80], "little") == sequence
    assert body[96:] == hmac.new(key, b"codewire-product-network-control-v1\0" + body[:96], hashlib.sha256).digest()
event("ten-descriptors-admitted")
if MODE == "helper-eof": sys.exit(0)
native_result(control, "workload-network-admitted")
assert framed_read(control) == b"\x01"
native_result(control, "workload-network-started")
for marker in ("progress-connected", "daemon-connected", "progress-closed"):
    native_result(control, marker)
progress.shutdown(socket.SHUT_WR)
for code in (14, 15, 16, 17, 18, 2): status(code)
command(b"A", 1, 1)
event("held-start")
native_result(control, "packet-attached"); status(5)
assert exact(daemon, 3) == b"run"
status(19)
command(b"C", 4, 2); status(13); status(8)
command(b"C", 2, 3)
status(10, (9472, 0, 18432, 0)); status(9)
command(b"C", 5, 4)
event("service-poweroff")
assert exact(daemon, 1) == b"q"
daemon.sendall(b"a")
if MODE == "helper-shutdown-rejected":
    os.write(2, b"codewire-workload-network: relay-rejected\n")
    control.sendall(frame(b"V\x02\x00") + frame(b"V\x01\x02"))
    while True: time.sleep(1)
control.sendall(frame(b"V\x01\x00") + frame(b"V\x02\x00"))
if MODE == "partial-native": control.sendall(b"\0\0")
if MODE == "trailing-native": control.sendall(frame(b"bad"))
if MODE == "helper-exit": sys.exit(2)
if MODE == "helper-unreaped":
    control.close()
    while True: time.sleep(1)
'''

VERIFIER_CHILD = r'''
opts = options()
if sys.argv[1] == "seed":
    assert set(opts) == {"--setup-fd", "--output-fd", "--network-key-fd", "--vm-id", "--generation"}
    fds = [int(opts[key]) for key in ("--setup-fd", "--output-fd", "--network-key-fd")]
    assert len(set(fds)) == 3
    for fd in fds[1:]:
        assert os.fstat(fd).st_size == 0 and os.fstat(fd).st_mode & 0o7777 == 0o600
        assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY
    os.write(fds[1], b"s" * 4096)
    os.write(fds[2], b"k" * (31 if MODE == "short-key" else 32))
    sys.exit(0)
assert sys.argv[1] == "verify"
assert set(opts) == {"--progress-fd", "--daemon-fd", "--control-fd", "--seed-fd"}
assert len(set(opts.values())) == 4
assert os.read(int(opts["--seed-fd"]), 4097) == b"s" * 4096
progress, daemon, control = [socket.socket(fileno=int(opts["--" + name + "-fd"])) for name in ("progress", "daemon", "control")]
for stream in (progress, daemon, control): stream.settimeout(4)
if MODE == "verifier-eof": sys.exit(0)
if MODE == "early-workload": control.sendall(b"W")
seen = [exact(control, 1) for _ in range(3)]
assert set(seen) == {b"P", b"D", b"S"}
assert progress.recv(1) == b""
control.sendall(b"R"); daemon.sendall(b"run")
assert exact(control, 1) == b"E"
control.sendall(b"W")
event("real-session-stopped")
assert exact(control, 1) == b"Q"
event("guest-poweroff")
daemon.sendall(b"q"); assert exact(daemon, 1) == b"a"
if MODE == "vm-before-acceptance": time.sleep(0.1)
control.sendall(b"A")
assert exact(control, 1) == b"F"
event("helper-reaped-before-finish")
control.sendall(b"CC" if MODE == "duplicate-complete" else b"C")
if MODE == "verifier-exit": sys.exit(2)
if MODE == "verifier-unreaped":
    control.close()
    while True: time.sleep(1)
'''


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.codec = m.ServiceCodec(uuid.UUID(int=1), 1, b"n" * 32, b"k" * 32)
        self.state = m.Coordinator(self.codec)
        self.native_writes = []
        self.verifier_writes = []

    def advance(self):
        self.state.advance(self.native_writes.append, self.verifier_writes.append)

    def native(self, marker):
        self.state.feed_native(c.framed(c.canonical({"result": marker, "schemaVersion": 4})))
        self.advance()

    def frame(self, code, waits=None):
        frame = bytearray(128)
        frame[:8] = self.codec.status_magic
        frame[8:10] = bytes([2, code])
        frame[16:32] = self.codec.vm_id.bytes
        frame[32:40] = (1).to_bytes(8, "little")
        frame[40:72] = b"n" * 32
        frame[72:80] = self.codec.status_sequence[2].to_bytes(8, "little")
        if waits is not None:
            frame[80:96] = struct.pack("<4i", *waits)
        frame[96:] = hmac.new(b"k" * 32, self.codec.status_domain + frame[:96], hashlib.sha256).digest()
        return c.framed(b"R\x02" + frame)

    def status(self, code, waits=None):
        self.state.feed_native(self.frame(code, waits))
        self.advance()

    def verifier(self, data):
        self.state.feed_verifier(data)
        self.advance()

    def prepared(self):
        self.native("workload-network-admitted")
        self.native("workload-network-started")
        for code in m.product.PREPARATION:
            self.status(code)
        self.assertEqual(self.native_writes[-1][4:6], b"A\x02")
        self.assertNotIn(b"S", self.verifier_writes)

    def ready(self):
        self.prepared()
        self.native("progress-connected")
        self.native("daemon-connected")
        self.native("progress-closed")
        self.status(c.STATUS_WORKER_READY)
        self.assertNotIn(b"S", self.verifier_writes)
        self.native("packet-attached")
        self.assertIn(b"S", self.verifier_writes)
        self.verifier(b"R")

    def workload(self):
        self.ready()
        self.status(m.product.STATUS_ENDPOINT_COMPLETED)
        self.verifier(b"W")
        self.status(c.STATUS_EOF_ARMED)
        self.status(c.STATUS_NO_EOF_OBSERVED)
        self.status(c.STATUS_CHILDREN_REAPED, m.EXPECTED_WAITS)
        self.status(c.STATUS_CANCELLED)
        self.assertIn(b"Q", self.verifier_writes)

    def test_requires_all_independent_facts_and_both_owned_reaps(self):
        self.workload()
        self.assertFalse(self.state.complete())
        self.verifier(b"A")
        for role in c.ROLES:
            self.state.feed_native(c.framed(bytes([ord("V"), role, c.VM_STOPPED])))
        self.state.helper_reaped = True
        self.advance()
        self.assertEqual(self.verifier_writes[-1], b"F")
        self.verifier(b"C")
        self.assertFalse(self.state.complete())
        self.state.verifier_reaped = True
        self.assertTrue(self.state.complete())

    def test_actual_vm_stops_can_arrive_before_poweroff_acceptance(self):
        self.workload()
        for role in c.ROLES:
            self.state.feed_native(c.framed(bytes([ord("V"), role, c.VM_STOPPED])))
        self.state.helper_reaped = True
        self.advance()
        self.assertNotIn(b"F", self.verifier_writes)
        self.verifier(b"A")
        self.assertEqual(self.verifier_writes[-1], b"F")

    def test_rejected_vm_event_is_preserved_but_never_actual_stop(self):
        self.workload()
        with self.assertRaises(m.FixtureFailure):
            self.state.feed_native(c.framed(b"V\x01\x02"))
        facts = self.state.diagnostic_state()
        self.assertEqual(facts["observedVMEvents"], [[1, 2]])
        self.assertEqual(facts["actualVMStops"], [])
        self.assertFalse(self.state.complete())

    def test_endpoint_alone_cannot_emit_workload_success(self):
        self.prepared()
        self.native("packet-attached")
        self.status(c.STATUS_WORKER_READY)
        self.status(m.product.STATUS_ENDPOINT_COMPLETED)
        with self.assertRaises(m.FixtureFailure):
            self.verifier(b"W")
        self.assertNotIn("observe", self.state.sent)

    def test_session_marker_without_endpoint_cannot_advance(self):
        self.ready()
        with self.assertRaises(m.FixtureFailure):
            self.verifier(b"W")
        self.assertNotIn("cancel", self.state.sent)

    def test_wrong_waits_do_not_authorize_poweroff(self):
        self.ready()
        self.status(m.product.STATUS_ENDPOINT_COMPLETED)
        self.verifier(b"W")
        self.status(c.STATUS_EOF_ARMED)
        self.status(c.STATUS_NO_EOF_OBSERVED)
        with self.assertRaises(m.FixtureFailure):
            self.status(c.STATUS_CHILDREN_REAPED, (9472, 0, 0, 0))
        self.assertNotIn(b"Q", self.verifier_writes)

    def test_forced_or_early_stop_is_not_actual_success(self):
        self.prepared()
        for state in (c.VM_STOPPED, c.VM_FAILED, c.VM_FORCE_STOPPED):
            with self.assertRaises(m.FixtureFailure):
                self.state.native_record(bytes([ord("V"), 1, state]))
        self.assertFalse(self.state.vm_stops)

    def test_replayed_forged_wrong_role_and_old_schema_frames_fail(self):
        self.native("workload-network-admitted")
        frame = self.frame(m.product.PREPARATION[0])
        self.state.feed_native(frame)
        bad = [frame, frame[:-1] + bytes([frame[-1] ^ 1]),
               c.framed(b"R\x01" + frame[6:]),
               c.framed(c.canonical({"result": "console-pair-started", "schemaVersion": 3}))]
        for payload in bad:
            with self.assertRaises(m.FixtureFailure):
                self.state.feed_native(payload)
        self.assertFalse(self.state.complete())

    def test_invalid_frame_length_is_rejected_before_body(self):
        for length in (0, 257, 2**32 - 1):
            state = m.Coordinator(self.codec)
            with self.assertRaises(m.FixtureFailure):
                state.feed_native(struct.pack(">I", length))

    def test_partial_frame_cannot_complete(self):
        self.state.feed_native(b"\0\0")
        self.assertFalse(self.state.complete())

    def test_failed_write_is_not_a_completed_control_fact(self):
        self.state.native.add("workload-network-admitted")
        def failed(_payload):
            raise OSError("synthetic write failure")
        with self.assertRaises(OSError):
            self.state.advance(failed, self.verifier_writes.append)
        self.assertNotIn("boot", self.state.sent)

    def test_early_attach_and_duplicate_ready_are_rejected(self):
        self.native("workload-network-admitted")
        with self.assertRaises(m.FixtureFailure):
            self.native("packet-attached")
        self.native("workload-network-started")
        with self.assertRaises(m.FixtureFailure):
            self.native("workload-network-started")

    def test_diagnostics_contain_only_fixed_classifications(self):
        self.prepared()
        rendered = c.canonical(self.state.diagnostic_state())
        for value in (b"n" * 32, b"k" * 32, str(self.codec.vm_id).encode(), b"CWPNCT1"):
            self.assertNotIn(value, rendered)

    def test_partial_poweroff_write_retains_exact_role_fact_and_never_replays(self):
        self.ready()
        self.status(m.product.STATUS_ENDPOINT_COMPLETED)
        self.verifier(b"W")
        self.status(c.STATUS_EOF_ARMED)
        self.status(c.STATUS_NO_EOF_OBSERVED)
        self.status(c.STATUS_CHILDREN_REAPED, m.EXPECTED_WAITS)
        self.state.feed_native(self.frame(c.STATUS_CANCELLED))
        def failed(_payload):
            raise OSError("synthetic second write failure")
        with self.assertRaises(OSError):
            self.state.advance(failed, self.verifier_writes.append)
        self.assertIn("guest-poweroff", self.state.sent)
        self.assertNotIn("service-poweroff", self.state.sent)
        self.assertEqual(self.verifier_writes.count(b"Q"), 1)
        with self.assertRaises(m.FixtureFailure):
            self.advance()
        self.assertEqual(self.verifier_writes.count(b"Q"), 1)
        self.assertFalse(self.state.complete())

    def test_vm_stop_authorization_is_per_role(self):
        self.prepared()
        self.state.sent.add("guest-poweroff")
        self.state.native_record(bytes([ord("V"), 1, c.VM_STOPPED]))
        with self.assertRaises(m.FixtureFailure):
            self.state.native_record(bytes([ord("V"), 2, c.VM_STOPPED]))
        self.state.sent.add("service-poweroff")
        self.state.native_record(bytes([ord("V"), 2, c.VM_STOPPED]))
        self.assertEqual(self.state.vm_stops, {1, 2})
        self.assertFalse(self.state.complete())


class ResultCommitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.run = m.Run()
        self.run.directory = Path(self.temporary.name)
        self.document = m.result_document(self.run, 1)
        self.document["outcome"] = "pass"  # Persistence test, not fixture proof.

    def tearDown(self):
        self.temporary.cleanup()

    def assert_unknown(self):
        self.assertEqual(json.loads((self.run.directory / "result.json").read_bytes())["outcome"], "unknown")

    def test_atomic_commit_publishes_complete_bytes(self):
        m.persist_result(self.run, self.document)
        self.assertEqual(json.loads((self.run.directory / "result.json").read_bytes()), self.document)
        self.assertFalse((self.run.directory / "result-candidate.json").exists())

    def test_candidate_short_write_keeps_canonical_unknown(self):
        real = c.write_private
        def fail(path, data):
            if path.name == "result-candidate.json":
                path.write_bytes(data[:32])
                raise OSError("synthetic partial write")
            real(path, data)
        with mock.patch.object(c, "write_private", side_effect=fail):
            with self.assertRaises(OSError): m.persist_result(self.run, self.document)
        self.assert_unknown()

    def test_candidate_fsync_failure_keeps_canonical_unknown(self):
        real = os.fsync
        calls = 0
        def fail(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError("synthetic late candidate fsync")
            real(descriptor)
        with mock.patch.object(os, "fsync", side_effect=fail):
            with self.assertRaises(OSError): m.persist_result(self.run, self.document)
        self.assert_unknown()

    def test_canonical_fsync_failure_never_leaves_pass(self):
        with mock.patch.object(os, "fsync", side_effect=OSError("synthetic canonical fsync")):
            with self.assertRaises(OSError): m.persist_result(self.run, self.document)
        self.assert_unknown()

    def test_rejected_commit_keeps_canonical_unknown(self):
        with mock.patch.object(os, "replace", side_effect=OSError("synthetic rejected commit")):
            with self.assertRaises(OSError): m.persist_result(self.run, self.document)
        self.assert_unknown()


class PhaseBudgetTests(unittest.TestCase):
    def test_expiry_between_read_and_transition_cannot_refresh_budget(self):
        run = m.Run()
        state = m.Coordinator(m.ServiceCodec(uuid.UUID(int=1), 1, b"n" * 32, b"k" * 32))
        with mock.patch.object(m.time, "monotonic", return_value=100):
            budget = m.PhaseBudget(run)
        with mock.patch.object(m.time, "monotonic", return_value=116):
            state.sent.add("boot")
            with self.assertRaises(m.FixtureFailure): budget.update(state)
            self.assertEqual(budget.stop, 115)

    def test_write_completing_after_phase_expiry_is_terminal_unknown(self):
        run = m.Run()
        state = m.Coordinator(m.ServiceCodec(uuid.UUID(int=1), 1, b"n" * 32, b"k" * 32))
        state.native.add("workload-network-admitted")
        now = [100.0]
        stream = mock.Mock()
        def sent(data):
            now[0] = 116
            return len(data)
        stream.send.side_effect = sent
        with mock.patch.object(m.time, "monotonic", side_effect=lambda: now[0]), \
             mock.patch.object(m.select, "select", return_value=([], [stream], [])):
            budget = m.PhaseBudget(run)
            with self.assertRaises(m.FixtureFailure):
                state.advance(lambda data: m.send_all(run, stream, data, remaining=budget.remaining), lambda _data: None)
        self.assertTrue(state.write_failed)
        self.assertNotIn("boot", state.sent)

    def test_repeated_facts_never_refresh_stage_deadline(self):
        run = m.Run()
        state = m.Coordinator(m.ServiceCodec(uuid.UUID(int=1), 1, b"n" * 32, b"k" * 32))
        with mock.patch.object(m.time, "monotonic", return_value=100):
            budget = m.PhaseBudget(run)
            state.sent.add("boot")
            budget.update(state)
            self.assertEqual(budget.stop, 220)
        with mock.patch.object(m.time, "monotonic", return_value=150):
            budget.update(state)
            self.assertEqual(budget.stop, 220)
        with mock.patch.object(m.time, "monotonic", return_value=221):
            with self.assertRaises(m.FixtureFailure): budget.remaining()

    def test_stage_never_extends_whole_run_deadline(self):
        run = m.Run()
        state = m.Coordinator(m.ServiceCodec(uuid.UUID(int=1), 1, b"n" * 32, b"k" * 32))
        with mock.patch.object(m.time, "monotonic", return_value=100):
            run.deadline = 101
            budget = m.PhaseBudget(run)
            state.sent.add("boot")
            budget.update(state)
            self.assertEqual(budget.remaining(), 1)


class DiagnosticCleanupTests(unittest.TestCase):
    def test_diagnostic_exception_cannot_skip_owned_teardown_or_pass(self):
        run = m.Run()
        child = mock.Mock()
        child.poll.side_effect = RuntimeError(old.CANARY)
        run.proof_children = {"helper": child}
        with mock.patch.object(run, "stop_and_close", return_value=True) as stop:
            try:
                self.assertFalse(run.cleanup())
                self.assertTrue(run.quiescent)
            finally:
                stop.assert_called_once_with()


class ParentHarnessTests(unittest.TestCase):
    # A run ends as soon as its children finish, so the whole-run deadline only
    # has to outlast a slow host: a 3 s deadline failed a passing run whose
    # verifier had not been reaped yet. Only the unreaped cases wait for it,
    # and they set a short one.
    DEADLINE_SECONDS = 60
    PROCESS_TIMEOUT = DEADLINE_SECONDS + 30

    def setUp(self):
        # Reuse synthetic private image/signing construction, not the old
        # nine-FD protocol, killed-helper success condition or deletion claim.
        self.support = old.ParentFixtureTests(methodName="runTest")
        self.support.setUp()
        self.base = self.support.base
        self.root = self.base / "trial"
        self.service = self.base / "service-initramfs"
        self.service.write_bytes(b"service" * 1024)
        self.service.chmod(0o600)
        source = Path(m.__file__).resolve()
        self.support.wrapper.write_text(
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('tested', {str(source)!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "m.production.require_host = lambda: None\n"
            f"m.production.CODESIGN = {str(self.support.codesign)!r}\n"
            "m.production.MIN_DISK_BYTES = 4096; m.production.DISK_ALIGNMENT = 4096\n"
            f"m.production.DEADLINE_SECONDS = {self.DEADLINE_SECONDS}; m.production.STOP_SECONDS = 0.1\n"
            "sys.exit(m.main())\n"
        )
        self.mode("success")

    def tearDown(self):
        self.support.tearDown()

    def mode(self, mode):
        child = CHILD_COMMON.replace("__MODE__", repr(mode)).replace("__EVENTS__", repr(str(self.support.events)))
        for name, body in (("helper", NATIVE_CHILD), ("fixture", VERIFIER_CHILD)):
            self.support.executable(self.support.paths[name], child + body)

    def arguments(self):
        return self.support.arguments() + [
            "--service-initramfs", str(self.service), "--service-initramfs-sha256",
            hashlib.sha256(self.service.read_bytes()).hexdigest(), "--artifact-root", str(self.root),
        ]

    def finish(self, expected=0, *, args=None):
        process = self.support.start(self.arguments() if args is None else args)
        output, errors = process.communicate(timeout=self.PROCESS_TIMEOUT)
        self.assertEqual(process.returncode, expected, (output, errors))
        self.assertEqual(errors, b"")
        self.assertNotIn(old.CANARY.encode(), output)
        self.assertNotIn(b"kkkkkkkk", output)
        result = json.loads(output)
        self.assertEqual(result["outcome"], "pass" if expected == 0 else "unknown")
        self.assertFalse(result["parity"])
        self.assertFalse(result["confinement"])
        self.support.assert_no_children()
        if self.root.exists():
            self.assertEqual(json.loads((self.root / "result.json").read_bytes()), result)
            self.assertEqual(self.root.stat().st_mode & 0o7777, 0o700)
            self.assertEqual((self.root / "result.json").stat().st_mode & 0o7777, 0o600)
        return result

    def test_real_children_ten_fds_joined_shutdown_and_retained_artifacts(self):
        result = self.finish()
        self.assertTrue(result["ownedGroupsAbsent"])
        self.assertTrue(result["helperControlEOF"] and result["verifierControlEOF"])
        self.assertEqual(result["eofObservation"], "not-observed-within-bound")
        self.assertEqual(result["facts"]["serviceWaits"], list(m.EXPECTED_WAITS))
        self.assertTrue((self.root / "seed").exists())
        events = self.support.events.read_text().splitlines()
        for event in ("ten-descriptors-admitted", "held-start", "real-session-stopped", "guest-poweroff", "service-poweroff", "helper-reaped-before-finish"):
            self.assertEqual(events.count(event), 1)

    def test_native_vm_events_may_precede_independent_acceptance(self):
        self.mode("vm-before-acceptance")
        self.finish()

    def test_shutdown_failure_retains_boundary_event_and_pending_fixed_log(self):
        self.mode("helper-shutdown-rejected")
        result = self.finish(1)
        self.assertEqual(result["lastObservationBoundary"], "native-record")
        self.assertEqual(result["facts"]["observedVMEvents"], [[2, 0], [1, 2]])
        self.assertEqual(result["facts"]["actualVMStops"], [2])
        # This child was still live at the failure boundary, before owned TERM.
        self.assertIsNone(result["preCleanupChildExit"]["helper"])
        self.assertIn(b"relay-rejected", (self.root / "child-5.log").read_bytes())
        self.assertTrue(result["ownedGroupsAbsent"])

    def test_diagnostic_exception_still_stops_actual_owned_children(self):
        self.mode("helper-shutdown-rejected")
        wrapper = self.support.wrapper.read_text()
        self.support.wrapper.write_text(wrapper.replace(
            "sys.exit(m.main())",
            "def diagnostic_failure(self): raise RuntimeError(" + repr(old.CANARY) + ")\n"
            "m.Run.retain_diagnostics = diagnostic_failure\n"
            "sys.exit(m.main())",
        ))
        result = self.finish(1)
        self.assertTrue(result["ownedGroupsAbsent"])
        self.assertEqual(result["preCleanupChildExit"], {})

    def test_broken_stdout_after_commit_preserves_authoritative_pass_and_zero_exit(self):
        process = self.support.start(self.arguments())
        process.stdout.close()
        self.assertEqual(process.wait(timeout=self.PROCESS_TIMEOUT), 0)
        errors = process.stderr.read()
        process.stderr.close()
        self.assertEqual(errors, b"")
        self.assertEqual(json.loads((self.root / "result.json").read_bytes())["outcome"], "pass")
        self.support.assert_no_children()

    def test_full_live_stdout_pipe_cannot_block_committed_exit(self):
        reader, writer = os.pipe()
        os.set_blocking(writer, False)
        try:
            while True:
                os.write(writer, b"x" * 4096)
        except BlockingIOError:
            pass
        os.set_blocking(writer, True)
        original_flags = m.fcntl.fcntl(writer, m.fcntl.F_GETFL)
        process = subprocess.Popen(
            [sys.executable, str(self.support.wrapper), *self.arguments()],
            stdout=writer, stderr=subprocess.PIPE,
            env={**os.environ, "CODEWIRE_TEST_SECRET_CANARY": old.CANARY},
        )
        try:
            self.assertEqual(process.wait(timeout=self.PROCESS_TIMEOUT), 0)
            self.assertEqual(m.fcntl.fcntl(writer, m.fcntl.F_GETFL), original_flags)
            self.assertEqual(process.stderr.read(), b"")
            self.assertEqual(json.loads((self.root / "result.json").read_bytes())["outcome"], "pass")
            self.support.assert_no_children()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            process.stderr.close()
            os.close(reader)
            os.close(writer)

    def test_protocol_and_process_failures_cannot_pass(self):
        for mode in ("helper-eof", "verifier-eof", "forged-status", "early-workload",
                     "partial-native", "trailing-native", "helper-exit", "verifier-exit",
                     "duplicate-complete", "short-key"):
            with self.subTest(mode=mode):
                self.root = self.base / mode
                self.mode(mode)
                self.finish(1)

    def test_eof_without_exact_child_reap_cannot_pass(self):
        # An unreaped child is only refused at the deadline; keep it short here.
        wrapper = self.support.wrapper.read_text()
        short = wrapper.replace(f"m.production.DEADLINE_SECONDS = {self.DEADLINE_SECONDS};",
                                "m.production.DEADLINE_SECONDS = 3;")
        self.assertNotEqual(short, wrapper)
        self.support.wrapper.write_text(short)
        for mode in ("helper-unreaped", "verifier-unreaped"):
            with self.subTest(mode=mode):
                self.root = self.base / mode
                self.mode(mode)
                result = self.finish(1)
                self.assertTrue(result["ownedGroupsAbsent"])

    def test_extra_service_input_uses_existing_admission(self):
        for mode in ("public", "symlink", "alias", "hash"):
            with self.subTest(mode=mode):
                args = self.arguments()
                if mode == "public":
                    self.service.chmod(0o644)
                elif mode in ("symlink", "alias"):
                    path = self.base / mode
                    if mode == "symlink": path.symlink_to(self.service)
                    else: os.link(self.service, path)
                    args[args.index("--service-initramfs") + 1] = str(path)
                else:
                    args[args.index("--service-initramfs-sha256") + 1] = "0" * 64
                self.root = self.base / (mode + "-trial")
                args[args.index("--artifact-root") + 1] = str(self.root)
                self.finish(1, args=args)
                self.service.chmod(0o600)
                if mode == "alias": path.unlink()


if __name__ == "__main__":
    unittest.main()
