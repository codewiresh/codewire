#!/usr/bin/env python3
"""Synthetic parent-process tests. No Virtualization.framework or guest runs."""

from __future__ import annotations

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


SOURCE = Path(__file__).with_name("macos-vz-production-boot.py").resolve()
SPEC = importlib.util.spec_from_file_location("production_boot", SOURCE)
assert SPEC and SPEC.loader
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)
CANARY = "synthetic-private-child-log-canary"

COMMON = r'''
import array, fcntl, json, os, select, signal, socket, stat, struct, sys, time
MODE = __MODE__
EVENTS = __EVENTS__
def event(value):
    with open(EVENTS, "a") as output:
        output.write(value + "\n")
def exact(stream, size):
    value = b""
    while len(value) < size:
        part = stream.recv(size - len(value))
        assert part
        value += part
    return value
def frame(value):
    return struct.pack(">I", len(value)) + value
def result(stream, value):
    stream.sendall(frame(json.dumps({"result": value, "schemaVersion": 2}, sort_keys=True, separators=(",", ":")).encode()))
def options():
    assert len(sys.argv[2:]) % 2 == 0
    pairs = list(zip(sys.argv[2::2], sys.argv[3::2]))
    assert len(dict(pairs)) == len(pairs)
    return dict(pairs)
assert "CODEWIRE_TEST_SECRET_CANARY" not in os.environ
# Apple's Python adds this CoreFoundation locale variable at interpreter
# startup, even with the parent's fixed environment. Do not allow it elsewhere.
native_names = {"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set()
assert set(os.environ) <= {"HOME", "TMPDIR", "LC_ALL", "PATH", "LC_CTYPE"} | native_names
assert os.stat(os.getcwd()).st_mode & 0o7777 == 0o700
print("synthetic-private-child-log-canary", flush=True)
event("pid:" + str(os.getpid()))
kind = "helper" if sys.argv[1] == "production-init-fixture" else sys.argv[1]
if MODE == "flood-" + kind:
    while True: os.write(1, b"x" * 8192)
'''

HELPER = r'''
assert sys.argv[1] == "production-init-fixture"
opts = options()
assert set(opts) == {"--control-fd"}
control = socket.socket(fileno=int(opts["--control-fd"]))
control.settimeout(10)
data, ancillary, flags, _ = control.recvmsg(16388, socket.CMSG_SPACE(9 * array.array("i").itemsize))
assert flags == 0 and len(ancillary) == 1
assert ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
fds = array.array("i")
fds.frombytes(ancillary[0][2])
assert len(fds) == len(set(fds)) == 9
size = struct.unpack(">I", data[:4])[0]
data = data[4:]
if len(data) < size: data += exact(control, size - len(data))
assert len(data) == size
config = json.loads(data)
assert config["schemaVersion"] == 2 and config["cpuCount"] == 2 and config["memoryMiB"] == 2048
assert config["daemonVsockPort"] == 7777 and config["generation"] == 1
assert set(config) == {"schemaVersion", "vmID", "generation", "cpuCount", "memoryMiB", "daemonVsockPort", "kernel", "initialRamdisk", "seedDisk", "stateDisk", "rootDisk", "setupDisk"}
assert config["seedDisk"]["size"] == 4096
identities = set()
for index, fd in enumerate(fds[:6]):
    info = os.fstat(fd)
    assert stat.S_ISREG(info.st_mode) and info.st_mode & 0o7777 == 0o600 and info.st_nlink == 1
    identities.add((info.st_dev, info.st_ino))
    expected = os.O_RDWR if index in (3, 4) else os.O_RDONLY
    assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == expected
assert len(identities) == 6
streams = [socket.socket(fileno=fd) for fd in fds[6:]]
assert all(stream.family == socket.AF_UNIX and stream.type == socket.SOCK_STREAM for stream in streams)
event("nine-descriptors-admitted")
if MODE == "helper-eof": sys.exit(0)
if MODE == "malformed":
    control.sendall(frame(b'{"result":"guest-ready","schemaVersion":1}'))
else:
    result(control, "descriptors-admitted")
    assert exact(control, 4) == struct.pack(">I", 1) and exact(control, 1) == b"\x01"
    event("started")
    if MODE == "helper-exit": os._exit(2)
    if MODE == "duplicate-admission": result(control, "descriptors-admitted")
    elif MODE == "progress-before-connected": result(control, "progress-closed")
    elif MODE in ("wait", "ignore-term"):
        if MODE == "ignore-term": signal.signal(signal.SIGTERM, signal.SIG_IGN)
        event("ready-to-signal")
    else:
        for name in ("progress-connected", "network-connected", "daemon-connected"):
            result(control, name)
        if MODE == "duplicate-network": result(control, "network-connected")
        if MODE != "missing-progress-closed":
            result(control, "progress-closed")
            if MODE == "duplicate-progress-closed": result(control, "progress-closed")
        streams[1].shutdown(socket.SHUT_WR)
while True: time.sleep(1)
'''

FIXTURE = r'''
opts = options()
if sys.argv[1] == "seed":
    assert set(opts) == {"--setup-fd", "--output-fd", "--vm-id", "--generation"}
    setup, output = int(opts["--setup-fd"]), int(opts["--output-fd"])
    assert setup != output
    assert fcntl.fcntl(setup, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    assert fcntl.fcntl(output, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY
    assert os.fstat(output).st_size == 0
    assert os.fstat(setup).st_size >= 65536
    os.write(output, b"s" * (4095 if MODE == "short-seed" else 4096))
    sys.exit(0)
assert sys.argv[1] == "verify"
assert set(opts) == {"--network-fd", "--progress-fd", "--daemon-fd", "--control-fd", "--seed-fd"}
assert len(set(opts.values())) == 5
seed = int(opts["--seed-fd"])
assert fcntl.fcntl(seed, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
assert os.read(seed, 4097) == b"s" * 4096
streams = {name: socket.socket(fileno=int(opts["--" + name + "-fd"])) for name in ("network", "progress", "daemon", "control")}
control = streams["control"]
control.settimeout(10)
if MODE == "early-ready": control.sendall(b"R")
if MODE == "early-workload": control.sendall(b"W")
if MODE == "early-armed": control.sendall(b"A")
if MODE == "early-closed": control.sendall(b"C")
if MODE == "rust-eof": sys.exit(0)
seen = []
while len(seen) < 3:
    marker = exact(control, 1)
    assert marker in (b"N", b"P", b"D") and marker not in seen
    seen.append(marker)
assert exact(streams["progress"], 0) == b""
assert streams["progress"].recv(1) == b""
event("rust-transport-ready")
coalesced = {"coalesced-ready-workload": b"RW", "coalesced-duplicate-workload": b"RWW", "coalesced-early-armed": b"RWA"}
if MODE in coalesced:
    control.sendall(coalesced[MODE])
else:
    control.sendall(b"R")
    if MODE == "duplicate-ready": control.sendall(b"R")
    # Readiness is not permission for the parent to kill the guest: the separate
    # fixed-workload proof must finish first. This is a synthetic protocol test,
    # not evidence that any real command ran inside a guest.
    assert not select.select([control], [], [], 0.08)[0]
    event("workload-gate-waited")
    if MODE == "workload-eof": sys.exit(0)
    if MODE == "workload-failed": sys.exit(2)
    if MODE == "armed-before-workload": control.sendall(b"A")
    if MODE == "missing-workload":
        event("workload-waiting")
        while True:
            if select.select([control], [], [], 1)[0]:
                if not control.recv(1): sys.exit(0)
                event("premature-workload-control")
                raise AssertionError("control received before workload completion")
    control.sendall(b"WW" if MODE == "duplicate-workload" else b"W")
event("workload-complete")
assert exact(control, 1) == b"K"
event("kill-requested")
control.sendall(b"A")
assert streams["network"].recv(1) == b""
event("network-closed")
control.sendall(b"C")
if MODE == "duplicate-closed": control.sendall(b"C")
if MODE == "rust-exit": sys.exit(2)
'''


class ParentFixtureTests(unittest.TestCase):
    def setUp(self):
        parent = SOURCE.parents[2] / ".tmp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="vz-parent-test-", dir=parent)
        self.base = Path(self.temporary.name)
        self.runtime = self.base / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.events = self.base / "events"
        self.paths = {}
        for name in ("kernel", "initramfs", "setup", "state", "root"):
            path = self.base / name
            path.write_bytes(name.encode() + bytes((65536 if name == "setup" else 4096) - len(name)))
            path.chmod(0o600)
            self.paths[name] = path
        self.uuids = {name: str(uuid.uuid4()) for name in ("state", "root")}
        for name, value in self.uuids.items():
            with self.paths[name].open("r+b") as output:
                output.seek(1024 + 0x38)
                output.write(b"\x53\xef")
                output.seek(1024 + 0x68)
                output.write(uuid.UUID(value).bytes)
        self.codesign = self.base / "codesign"
        self.signing()
        self.wrapper = self.base / "parent.py"
        self.wrapper.write_text(
            "import importlib.util, pathlib, sys, tempfile\n"
            f"spec = importlib.util.spec_from_file_location('fixture', {str(SOURCE)!r})\n"
            "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
            "m.require_host = lambda: None\n"
            f"m.CODESIGN = {str(self.codesign)!r}\n"
            "m.MIN_DISK_BYTES = 4096; m.DISK_ALIGNMENT = 4096\n"
            "m.DEADLINE_SECONDS = 5; m.STOP_SECONDS = 0.25\n"
            f"tempfile.tempdir = {str(self.runtime)!r}\n"
            "sys.exit(m.main())\n"
        )
        self.mode("success")

    def tearDown(self):
        # Tests must never silently erase artifacts while one of their children
        # could still write. The real parent is expected to reap every child.
        self.assert_no_children()
        self.temporary.cleanup()

    def executable(self, path, content):
        path.write_text(f"#!{sys.executable}\n" + content)
        path.chmod(0o700)

    def signing(self, mode="success"):
        self.executable(self.codesign,
            "import os, plistlib, sys\n"
            f"mode = {mode!r}\n"
            "if mode == 'flood':\n"
            "    while True: os.write(1, b'x' * 8192)\n"
            "if '--verify' in sys.argv: sys.exit(1 if mode == 'invalid-signature' else 0)\n"
            "if '--verbose=4' in sys.argv: print('Signature=' + ('Developer ID' if mode == 'not-adhoc' else 'adhoc'))\n"
            "else:\n"
            "    value = False if mode == 'no-entitlement' else (1 if mode == 'integer-entitlement' else True)\n"
            "    payload = {'com.apple.security.virtualization': value}\n"
            "    if mode == 'extra-entitlement': payload['com.apple.security.get-task-allow'] = True\n"
            "    sys.stdout.buffer.write(plistlib.dumps(payload))\n"
        )

    def mode(self, mode):
        common = COMMON.replace("__MODE__", repr(mode)).replace("__EVENTS__", repr(str(self.events)))
        for name, body in (("helper", HELPER), ("fixture", FIXTURE)):
            self.paths[name] = self.base / name
            self.executable(self.paths[name], common + body)

    def arguments(self):
        args = []
        for name in ("helper", "fixture", "kernel", "initramfs", "setup"):
            args.extend([f"--{name}", str(self.paths[name]), f"--{name}-sha256", harness.artifact.digest(self.paths[name])])
        for name in ("state", "root"):
            args.extend([f"--{name}", str(self.paths[name]), f"--{name}-uuid", self.uuids[name]])
        return args

    def start(self, args=None):
        return subprocess.Popen(
            [sys.executable, str(self.wrapper), *(self.arguments() if args is None else args)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "CODEWIRE_TEST_SECRET_CANARY": CANARY},
        )

    def finish(self, process, expected=0, deadline=12):
        try:
            output, errors = process.communicate(timeout=deadline)
        except subprocess.TimeoutExpired:
            process.kill()
            output, errors = process.communicate(timeout=2)
            self.fail("synthetic parent exceeded its fixed deadline")
        self.assertEqual(process.returncode, expected, (output, errors))
        self.assertNotIn(CANARY.encode(), output + errors)
        self.assertEqual(list(self.runtime.iterdir()), [])
        if expected == 0:
            self.assertEqual(output.decode().strip(), harness.SUCCESS)
            self.assertEqual(errors, b"")
        else:
            self.assertNotIn(b"PASS", output + errors)
            self.assertIn(b"private_retained=false", errors)
        self.assert_no_children()
        return output, errors

    def assert_no_children(self):
        if not self.events.exists():
            return
        for line in self.events.read_text().splitlines():
            if line.startswith("pid:"):
                with self.assertRaises(ProcessLookupError, msg=line):
                    os.kill(int(line[4:]), 0)

    def test_full_synthetic_lifecycle(self):
        self.finish(self.start())
        events = self.events.read_text().splitlines()
        for event in ("nine-descriptors-admitted", "started", "rust-transport-ready", "workload-gate-waited", "workload-complete", "kill-requested", "network-closed"):
            self.assertEqual(events.count(event), 1)
        self.assertLess(events.index("rust-transport-ready"), events.index("workload-gate-waited"))
        self.assertLess(events.index("workload-gate-waited"), events.index("workload-complete"))
        self.assertLess(events.index("workload-complete"), events.index("kill-requested"))

    def test_sigchld_is_actively_normalized_before_spawn(self):
        original = self.wrapper.read_text()
        for disposition in ("SIG_IGN", "SIG_DFL"):
            with self.subTest(disposition=disposition):
                injection = (
                    "import signal\n"
                    f"signal.signal(signal.SIGCHLD, signal.{disposition})\n"
                    "real_signal = signal.signal\n"
                    "normalized = False\n"
                    "def record_signal(signum, handler):\n"
                    "    global normalized\n"
                    "    result = real_signal(signum, handler)\n"
                    "    if signum == signal.SIGCHLD and handler == signal.SIG_DFL:\n"
                    "        normalized = True\n"
                    "    return result\n"
                    "signal.signal = record_signal\n"
                    "real_popen = m.subprocess.Popen\n"
                    "def checked_spawn(*args, **kwargs):\n"
                    "    assert normalized\n"
                    "    assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL\n"
                    "    return real_popen(*args, **kwargs)\n"
                    "m.subprocess.Popen = checked_spawn\n"
                )
                self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
                self.events.unlink(missing_ok=True)
                self.finish(self.start())

    def test_protocol_failures(self):
        cases = (
            "helper-eof", "malformed", "duplicate-admission", "progress-before-connected",
            "duplicate-network", "duplicate-progress-closed", "missing-progress-closed",
            "helper-exit", "short-seed", "early-ready", "early-armed", "early-closed",
            "rust-eof", "duplicate-ready", "duplicate-closed", "rust-exit",
            "early-workload", "duplicate-workload", "armed-before-workload",
            "coalesced-duplicate-workload", "coalesced-early-armed",
        )
        for mode in cases:
            with self.subTest(mode=mode):
                self.mode(mode)
                self.finish(self.start(), 1)

    def test_coalesced_readiness_and_workload_completion(self):
        self.mode("coalesced-ready-workload")
        self.finish(self.start())
        events = self.events.read_text().splitlines()
        self.assertLess(events.index("workload-complete"), events.index("kill-requested"))

    def test_workload_failure_or_missing_proof_never_arms_kill(self):
        for mode in ("workload-eof", "workload-failed", "missing-workload"):
            with self.subTest(mode=mode):
                self.mode(mode)
                self.events.unlink(missing_ok=True)
                _output, errors = self.finish(self.start(), 1)
                self.assertIn(b"phase=guest-workload", errors)
                events = self.events.read_text().splitlines()
                self.assertIn("workload-gate-waited", events)
                self.assertNotIn("kill-requested", events)
                self.assertNotIn("workload-complete", events)
                self.assertNotIn("premature-workload-control", events)

    def test_workload_cancellation_reaps_owned_children(self):
        self.mode("missing-workload")
        process = self.start()
        stop = time.monotonic() + 4
        while not self.events.exists() or "workload-waiting" not in self.events.read_text():
            if process.poll() is not None or time.monotonic() >= stop:
                self.finish(process, 143)
                self.fail("synthetic verifier did not reach workload phase")
            time.sleep(0.01)
        process.send_signal(signal.SIGTERM)
        _output, errors = self.finish(process, 143)
        self.assertIn(b"phase=guest-workload", errors)
        self.assertNotIn("kill-requested", self.events.read_text())
        self.assertNotIn("premature-workload-control", self.events.read_text())

    def test_signing_rejections(self):
        for mode in ("invalid-signature", "not-adhoc", "no-entitlement", "integer-entitlement", "extra-entitlement"):
            with self.subTest(mode=mode):
                self.signing(mode)
                self.finish(self.start(), 1)
                self.assertFalse(self.events.exists())

    def test_hash_path_and_identity_admission(self):
        args = self.arguments()
        args[args.index("--helper-sha256") + 1] = "0" * 64
        self.finish(self.start(args), 1)
        for flag, value in (
            ("--fixture-sha256", "A" * 64),
            ("--state-uuid", self.uuids["root"]),
            ("--state-uuid", str(uuid.uuid4())),
            ("--kernel", "relative"),
            ("--root", str(self.paths["state"])),
        ):
            with self.subTest(flag=flag, value=value):
                args = self.arguments()
                args[args.index(flag) + 1] = value
                self.finish(self.start(args), 1)
        alias = self.base / "hardlink"
        os.link(self.paths["state"], alias)
        args = self.arguments()
        args[args.index("--root") + 1] = str(alias)
        self.finish(self.start(args), 1)
        alias = self.base / "symlink"
        alias.symlink_to(self.paths["kernel"])
        args = self.arguments()
        args[args.index("--kernel") + 1] = str(alias)
        self.finish(self.start(args), 1)

    def test_cancellation_owned_children(self):
        for signum in harness.SIGNALS:
            with self.subTest(signal=signum):
                self.mode("wait")
                self.events.unlink(missing_ok=True)
                process = self.start()
                stop = time.monotonic() + 4
                while not self.events.exists() or "ready-to-signal" not in self.events.read_text():
                    if process.poll() is not None or time.monotonic() >= stop:
                        self.finish(process, 128 + signum)
                        self.fail("synthetic helper did not reach signal point")
                    time.sleep(0.01)
                process.send_signal(signum)
                self.finish(process, 128 + signum)

    def test_cancellation_in_launch_ownership_window(self):
        original = self.wrapper.read_text()
        for signum in harness.SIGNALS:
            with self.subTest(signal=signum):
                injection = (
                    "import os, signal\n"
                    "real_popen = m.subprocess.Popen\n"
                    "def inject(argv, **kwargs):\n"
                    "    child = real_popen(argv, **kwargs)\n"
                    "    if 'production-init-fixture' in argv:\n"
                    f"        os.kill(os.getpid(), {int(signum)})\n"
                    "    return child\n"
                    "m.subprocess.Popen = inject\n"
                )
                self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
                self.finish(self.start(), 128 + signum)

    def test_deadline_in_launch_ownership_window(self):
        original = self.wrapper.read_text()
        injection = (
            "import os, signal\n"
            "real_popen = m.subprocess.Popen\n"
            "def inject(argv, **kwargs):\n"
            "    child = real_popen(argv, **kwargs)\n"
            "    if 'production-init-fixture' in argv:\n"
            "        os.kill(os.getpid(), signal.SIGALRM)\n"
            "    return child\n"
            "m.subprocess.Popen = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start(), 1)

    def test_cleanup_escalates_for_owned_term_resistant_child(self):
        self.mode("ignore-term")
        process = self.start()
        stop = time.monotonic() + 4
        while not self.events.exists() or "ready-to-signal" not in self.events.read_text():
            if process.poll() is not None or time.monotonic() >= stop:
                self.finish(process, 143)
                self.fail("synthetic helper did not reach signal point")
            time.sleep(0.01)
        process.send_signal(signal.SIGTERM)
        self.finish(process, 143)

    def test_signal_at_committed_receipt_boundary(self):
        original = self.wrapper.read_text()
        injection = (
            "import builtins, os, signal\n"
            "def inject(*args, **kwargs):\n"
            "    if args and args[0] == m.SUCCESS:\n"
            "        os.kill(os.getpid(), signal.SIGTERM)\n"
            "    builtins.print(*args, **kwargs)\n"
            "m.print = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start())

    def test_signal_after_print_cannot_reverse_receipt(self):
        original = self.wrapper.read_text()
        injection = (
            "import builtins, os, signal\n"
            "def inject(*args, **kwargs):\n"
            "    builtins.print(*args, **kwargs)\n"
            "    if args and args[0] == m.SUCCESS:\n"
            "        os.kill(os.getpid(), signal.SIGTERM)\n"
            "m.print = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start())

    def test_signal_at_pending_snapshot_boundary(self):
        original = self.wrapper.read_text()
        for timing in ("before", "after"):
            with self.subTest(timing=timing):
                injection = (
                    "import os, signal\n"
                    "real_pending = m.signal.sigpending\n"
                    "def inject():\n"
                    f"    if {timing!r} == 'before': os.kill(os.getpid(), signal.SIGTERM)\n"
                    "    pending = real_pending()\n"
                    f"    if {timing!r} == 'after': os.kill(os.getpid(), signal.SIGTERM)\n"
                    f"    with open({str(self.events)!r}, 'a') as output: output.write('receipt-snapshot\\n')\n"
                    "    return pending\n"
                    "m.signal.sigpending = inject\n"
                )
                self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
                self.events.unlink(missing_ok=True)
                self.finish(self.start(), 143 if timing == "before" else 0)
                self.assertEqual(self.events.read_text().splitlines().count("receipt-snapshot"), 1)

    def test_signal_after_cleanup_before_receipt_commit(self):
        original = self.wrapper.read_text()
        injection = (
            "import os, signal\n"
            "real_cleanup = m.Run.cleanup\n"
            "def inject(self):\n"
            "    result = real_cleanup(self)\n"
            "    os.kill(os.getpid(), signal.SIGTERM)\n"
            "    return result\n"
            "m.Run.cleanup = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start(), 143)

    def test_second_signal_cannot_escape_finalizer(self):
        original = self.wrapper.read_text()
        injection = (
            "import os, signal\n"
            "real_cleanup = m.Run.cleanup\n"
            "def inject(self):\n"
            "    os.kill(os.getpid(), signal.SIGINT)\n"
            "    os.kill(os.getpid(), signal.SIGHUP)\n"
            "    return real_cleanup(self)\n"
            "m.Run.cleanup = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.mode("wait")
        process = self.start()
        stop = time.monotonic() + 4
        while not self.events.exists() or "ready-to-signal" not in self.events.read_text():
            if process.poll() is not None or time.monotonic() >= stop:
                self.finish(process, 143)
                self.fail("synthetic helper did not reach signal point")
            time.sleep(0.01)
        process.send_signal(signal.SIGTERM)
        self.finish(process, 143)

    def test_every_child_log_is_bounded(self):
        original = self.wrapper.read_text()
        # A flooding child can take longer than the harness's 0.25 s to leave
        # on a loaded host, and the parent then keeps its private directory, as
        # it must. Give stopping the product's own patience and more, with the
        # same 5 s working window; the run must still end clean.
        injection = (
            "m.STOP_SECONDS = 10; m.DEADLINE_SECONDS = 25\n"
            "real_cleanup = m.Run.cleanup\n"
            "def inject(self):\n"
            "    if self.directory is not None:\n"
            "        logs = list(self.directory.glob('child-*.log'))\n"
            "        assert logs and all(p.stat().st_size <= m.MAX_LOG_BYTES for p in logs)\n"
            f"        with open({str(self.events)!r}, 'a') as output: output.write('logs-bounded\\n')\n"
            "    return real_cleanup(self)\n"
            "m.Run.cleanup = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        for child in ("codesign", "seed", "verify", "helper"):
            with self.subTest(child=child):
                self.signing("flood" if child == "codesign" else "success")
                self.mode("flood-" + child)
                self.events.unlink(missing_ok=True)
                self.finish(self.start(), 1, deadline=45)
                self.assertIn("logs-bounded", self.events.read_text())

    def test_admitted_source_inode_survives_pathname_swap(self):
        original = self.wrapper.read_text()
        injection = (
            "import os\n"
            "real_copy = m.Run.copy\n"
            "def inject(self, descriptor, destination, size):\n"
            "    if destination.name == 'state':\n"
            f"        path = pathlib.Path({str(self.paths['state'])!r})\n"
            "        admitted = os.pread(descriptor, size, 0)\n"
            "        os.replace(path, path.with_name('old-state'))\n"
            "        replacement = bytearray(admitted); replacement[2048] ^= 255\n"
            "        path.write_bytes(replacement); path.chmod(0o600)\n"
            "        real_copy(self, descriptor, destination, size)\n"
            "        assert destination.read_bytes() == admitted\n"
            f"        with open({str(self.events)!r}, 'a') as output: output.write('held-inode-copied\\n')\n"
            "    else: real_copy(self, descriptor, destination, size)\n"
            "m.Run.copy = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start())
        self.assertIn("held-inode-copied", self.events.read_text())

    def test_private_source_metadata_required(self):
        for mode in (0o644, 0o660, 0o1600, 0o4600):
            with self.subTest(mode=mode):
                self.paths["state"].chmod(mode)
                self.finish(self.start(), 1)
        self.paths["state"].chmod(0o600)
        alias = self.base / "extra-link"
        os.link(self.paths["state"], alias)
        self.finish(self.start(), 1)

    def test_parser_errors_do_not_print_caller_strings(self):
        for args in (["--" + CANARY], [*self.arguments(), "--unknown", CANARY], ["--helper", CANARY]):
            with self.subTest(args=args):
                self.finish(self.start(args), 1)
        self.assertFalse(self.events.exists())

    def test_existing_interval_timer_is_rejected_unchanged(self):
        original = self.wrapper.read_text()
        injection = (
            "import signal\n"
            "signal.setitimer(signal.ITIMER_REAL, 10, 3)\n"
            "before = signal.getitimer(signal.ITIMER_REAL)\n"
            "result = m.main()\n"
            "after = signal.getitimer(signal.ITIMER_REAL)\n"
            "assert 0 < after[0] <= before[0] and before[0] - after[0] < 1 and after[1] == 3\n"
            "signal.setitimer(signal.ITIMER_REAL, 0)\n"
            "sys.exit(result)"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection))
        self.finish(self.start(), 1)
        self.assertFalse(self.events.exists())

    def test_inherited_blocked_signals_are_rejected_unchanged(self):
        original = self.wrapper.read_text()
        for signum in harness.OWNED_SIGNALS:
            with self.subTest(signal=signum):
                injection = (
                    "import signal\n"
                    f"signal.pthread_sigmask(signal.SIG_BLOCK, ({int(signum)},))\n"
                    "before = signal.pthread_sigmask(signal.SIG_BLOCK, ())\n"
                    "result = m.main()\n"
                    "assert signal.pthread_sigmask(signal.SIG_BLOCK, ()) == before\n"
                    "sys.exit(result)"
                )
                self.wrapper.write_text(original.replace("sys.exit(m.main())", injection))
                self.finish(self.start(), 1)
                self.assertFalse(self.events.exists())

    def test_real_short_deadline_expires_hung_child(self):
        self.mode("wait")
        original = self.wrapper.read_text()
        # Keep the ordinary bounded startup allowance. Starting the short timer
        # before Python child startup races the very wait state we must prove.
        # Leave the software deadline unchanged: only the real alarm handler
        # can produce the short-deadline evidence recorded below.
        injection = (
            "import signal, time\n"
            f"events = pathlib.Path({str(self.events)!r})\n"
            "real_remaining = m.Run.remaining\n"
            "real_signal = m.Run.signal\n"
            "armed = False\n"
            "def remaining(self):\n"
            "    global armed\n"
            "    budget = real_remaining(self)\n"
            "    if not armed and events.exists() and 'ready-to-signal' in events.read_text().splitlines():\n"
            "        armed = True\n"
            "        with events.open('a') as output: output.write('software-deadline:' + str(self.deadline) + '\\n')\n"
            "        with events.open('a') as output: output.write('deadline-armed:' + str(time.monotonic()) + '\\n')\n"
            "        signal.setitimer(signal.ITIMER_REAL, 0.25)\n"
            "    return budget\n"
            "def observed_signal(self, signum, frame):\n"
            "    if signum == signal.SIGALRM:\n"
            "        with events.open('a') as output: output.write('deadline-fired:' + str(time.monotonic()) + '\\n')\n"
            "        try:\n"
            "            return real_signal(self, signum, frame)\n"
            "        except m.FixtureFailure:\n"
            "            with events.open('a') as output: output.write('deadline-raised\\n')\n"
            "            raise\n"
            "    return real_signal(self, signum, frame)\n"
            "m.Run.remaining = remaining\n"
            "m.Run.signal = observed_signal\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start(), 1)
        events = self.events.read_text().splitlines()
        armed = [line for line in events if line.startswith("deadline-armed:")]
        fired = [line for line in events if line.startswith("deadline-fired:")]
        software = [line for line in events if line.startswith("software-deadline:")]
        self.assertEqual(len(armed), 1)
        self.assertEqual(len(fired), 1)
        self.assertEqual(len(software), 1)
        self.assertEqual(events.count("deadline-raised"), 1)
        self.assertLess(events.index("ready-to-signal"), events.index(armed[0]))
        self.assertLess(events.index(armed[0]), events.index(fired[0]))
        self.assertLess(float(fired[0].split(":")[1]), float(software[0].split(":")[1]))
        elapsed = float(fired[0].split(":")[1]) - float(armed[0].split(":")[1])
        self.assertGreaterEqual(elapsed, 0.20)
        self.assertLess(elapsed, 1.0)

    def test_real_deadline_interrupts_blocking_read(self):
        original = self.wrapper.read_text().replace("m.DEADLINE_SECONDS = 5; m.STOP_SECONDS = 0.25", "m.DEADLINE_SECONDS = 1.5; m.STOP_SECONDS = 0.1")
        injection = (
            "import os\n"
            "real_copy = m.Run.copy\n"
            "def inject(self, descriptor, destination, size):\n"
            "    if destination.name == 'state':\n"
            "        reader, writer = os.pipe(); self.fds.extend((reader, writer))\n"
            f"        with open({str(self.events)!r}, 'a') as output: output.write('blocked-read-entered\\n')\n"
            "        os.read(reader, 1)\n"
            "        raise AssertionError('blocking read returned without deadline')\n"
            "    real_copy(self, descriptor, destination, size)\n"
            "m.Run.copy = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        started = time.monotonic()
        self.finish(self.start(), 1)
        self.assertGreaterEqual(time.monotonic() - started, 1.1)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIn("blocked-read-entered", self.events.read_text())

    def test_repeated_alarm_at_finalizer_entry(self):
        original = self.wrapper.read_text()
        injection = (
            "import os, signal\n"
            "real_finalize = m.finalize\n"
            "def inject(run, result, prior_umask):\n"
            f"    with open({str(self.events)!r}, 'a') as output: output.write('finalizer-entry\\n')\n"
            "    os.kill(os.getpid(), signal.SIGALRM)\n"
            "    return real_finalize(run, result, prior_umask)\n"
            "m.finalize = inject\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        self.finish(self.start(), 1)
        self.assertEqual(self.events.read_text().splitlines().count("finalizer-entry"), 2)

    def test_frame_parser_and_production_bounds(self):
        payload = harness.canonical({"result": "progress-connected", "schemaVersion": 2})
        parser = harness.Frames()
        framed = harness.artifact.framed(payload)
        for byte in framed[:-1]:
            self.assertEqual(parser.feed(bytes([byte])), [])
        self.assertEqual(parser.feed(framed[-1:]), ["progress-connected"])
        for payload in (
            b'{"result":"guest-ready","schemaVersion":1}',
            b'{"result":"network-connected","schemaVersion":true}',
            b'{"result":"network-connected","schemaVersion":2,"extra":0}',
            b'{"result":"network-connected","schemaVersion":2,"schemaVersion":2}',
        ):
            with self.subTest(payload=payload), self.assertRaises(harness.FixtureFailure):
                harness.decode_result(payload)
        for size in (0, 257, 2**32 - 1):
            with self.subTest(size=size), self.assertRaises(harness.FixtureFailure):
                harness.Frames().feed(struct.pack(">I", size))
        args = harness.parser().parse_args(self.arguments())
        run = harness.Run()
        with self.assertRaises(harness.FixtureFailure):
            harness.prepare(run, args)  # 4KiB synthetic disks never pass real admission.
        self.assertIsNone(run.directory)
        self.assertTrue(run.cleanup())

    def test_cleanup_preserves_if_owned_group_unknown(self):
        run = harness.Run()
        run.directory = self.runtime / "retained"
        run.directory.mkdir(mode=0o700)
        (run.directory / "private").write_text("synthetic")
        run.children = [mock.Mock(pid=987654321)]
        with mock.patch.object(harness, "group_absent", return_value=False), mock.patch.object(harness.os, "killpg"), mock.patch.object(harness, "STOP_SECONDS", 0):
            self.assertFalse(run.cleanup())
        self.assertTrue((run.directory / "private").exists())
        # No actual child existed: test-owned fixture teardown is now safe.
        run.children = []
        self.assertTrue(run.cleanup())

    def test_cleanup_never_signals_reaped_or_recycled_group(self):
        for initial_status in (0, None):
            with self.subTest(initial_status=initial_status):
                run = harness.Run()
                run.directory = self.runtime / f"retained-{initial_status}"
                run.directory.mkdir(mode=0o700)
                (run.directory / "private").write_text("synthetic")
                child = mock.Mock(pid=987654321, returncode=initial_status, stdout=None)

                def reap():
                    child.returncode = 0
                    return 0

                child.poll.side_effect = reap
                run.children = [child]
                # A visible numeric group can now be unrelated. No real PID
                # churn or signals are needed to exercise the unsafe decision.
                with mock.patch.object(harness.os, "killpg") as killpg, mock.patch.object(harness, "STOP_SECONDS", 0):
                    self.assertFalse(run.cleanup())
                self.assertTrue(killpg.call_args_list)
                self.assertTrue(all(call.args == (child.pid, 0) for call in killpg.call_args_list))
                self.assertTrue((run.directory / "private").exists())
                run.children = []  # Only a synthetic child existed.
                self.assertTrue(run.cleanup())

    def test_cleanup_rechecks_unreaped_ownership_before_escalation(self):
        run = harness.Run()
        child = mock.Mock(pid=987654321, returncode=None, stdout=None)
        child.poll.return_value = None
        run.children = [child]
        signals = []

        def killpg(pid, signum):
            self.assertEqual(pid, child.pid)
            if signum:
                signals.append(signum)
                # TERM was authorized while the leader was unreaped. The next
                # poll reaps it, but the numeric group remains visible.
                child.poll.return_value = 0
                child.returncode = 0

        with mock.patch.object(harness.os, "killpg", side_effect=killpg), mock.patch.object(harness, "STOP_SECONDS", 0):
            self.assertFalse(run.cleanup())
        self.assertEqual(signals, [signal.SIGTERM])
        run.children = []
        self.assertTrue(run.cleanup())

    def test_reaped_visible_group_prevents_success_receipt(self):
        original = self.wrapper.read_text()
        injection = (
            "import types\n"
            "real_cleanup = m.Run.cleanup\n"
            "real_killpg = m.os.killpg\n"
            "def observe_group(pid, signum):\n"
            "    if pid != 987654321: return real_killpg(pid, signum)\n"
            "    if signum:\n"
            f"        with open({str(self.events)!r}, 'a') as output: output.write('unsafe-signal\\n')\n"
            "def cleanup_with_reaped_group(self):\n"
            "    self.children.append(types.SimpleNamespace(pid=987654321, returncode=0, stdout=None, poll=lambda: 0))\n"
            "    return real_cleanup(self)\n"
            "m.os.killpg = observe_group\n"
            "m.Run.cleanup = cleanup_with_reaped_group\n"
            "m.STOP_SECONDS = 0\n"
        )
        self.wrapper.write_text(original.replace("sys.exit(m.main())", injection + "sys.exit(m.main())"))
        process = self.start()
        output, errors = process.communicate(timeout=12)
        self.assertEqual(process.returncode, 1, (output, errors))
        self.assertEqual(output, b"")
        self.assertIn(b"private_retained=true", errors)
        self.assertNotIn(CANARY.encode(), output + errors)
        self.assertNotIn("unsafe-signal", self.events.read_text())
        self.assertEqual(len(list(self.runtime.iterdir())), 1)
        self.assert_no_children()


if __name__ == "__main__":
    unittest.main()
