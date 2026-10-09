#!/usr/bin/env python3
"""Focused fixed-probe guards and ordinary-owner Linux kernel/FS fixtures.

These exercise held real process descriptors and a fixed persistent Bash with
two synthetic version-printing test executables. No CW release, platform API,
Pod, provider, image installation or managed-agent result is claimed. Normal
fixture cleanup uses only pidfds for this test's own unreaped children.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "scripts/ci/verify/kind/cw_runtime_probe.py"
SPEC = importlib.util.spec_from_file_location("kind_cw_runtime_probe_tests", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
NONCE = "1" * 32
ENVIRONMENT = "12345678-1234-4234-8234-123456789abc"
CHILD = r'''import os
print("READY", flush=True)
if os.read(0,1)==b"E": os.execv("/bin/sleep",["/bin/sleep","30"])
'''


def frame(index=0, **changes):
    return {"op": "checkpoint", "phase": probe.PHASES[index], "sha256": "a" * 64,
            "size": 1, "version": "0.1.0"} | changes


def args():
    return argparse.Namespace(environment_id=ENVIRONMENT, nonce=NONCE,
                              daemon_sha256="c" * 64, daemon_size=100, daemon_version="0.1.0-ci",
                              workspace_sha256="a" * 64, workspace_size=200,
                              workspace_version="0.1.0-release-A", managed_peers_json=None)


def own_fd_count():
    return len(os.listdir("/proc/self/fd"))


class Guards(unittest.TestCase):
    def test_managed_stop_order_cannot_skip_live_admission_or_terminal_proof(self):
        ready, stopped, close = (b'{"op":"managed-stop-ready"}',
                                 b'{"op":"managed-stopped"}', b'{"op":"close"}')
        for state, accepted in ((None, close), ("live", ready), ("ready", stopped), ("complete", close)):
            for raw in (ready, stopped, close):
                if raw == accepted:
                    self.assertEqual(probe.decode_request(raw, 3, state)["op"], json.loads(raw)["op"])
                else:
                    with self.assertRaises(probe.Refused):
                        probe.decode_request(raw, 3, state)
        for raw in (ready, stopped):
            for index in (0, 1, 2, 4):
                with self.assertRaises(probe.Refused):
                    probe.decode_request(raw, index, "live")
        for raw in (b'{"op":"managed-stop-ready","pid":1}',
                    b'{"op":"managed-stopped","op":"managed-stopped"}'):
            with self.assertRaises(probe.Refused):
                probe.decode_request(raw, 3, "ready")

    def test_managed_witness_invalid_json_types_and_births_refuse_before_process_effects(self):
        driver = "22222222-2222-4222-8222-222222222222"
        value = {"session_id": "session-" + driver, "driver_id": driver,
                 "provider_sha256": "a" * 64, "provider_size": 1,
                 "peer": {"version": 1, "identity": {
                     "environment_id": ENVIRONMENT, "driver_id": driver,
                     "session_id": "session-" + driver, "instance_id": ENVIRONMENT,
                     "driver_started_at": "2026-10-05T00:00:00Z", "boot_id": ENVIRONMENT,
                     "driver_pid": 100, "driver_start_ticks": 100},
                     "guardian_pid": 101, "guardian_start_ticks": 101, "provider_pid": 102,
                     "cleanup_unknown": True, "finished_at": None, "exit_code": None, "error": None}}
        cases = ["é" * (16 * 1024 + 1), "[", "[]", '[{"peer":1,"peer":2}]']
        for field, bad in (("version", True), ("guardian_start_ticks", True)):
            changed = json.loads(json.dumps(value)); changed["peer"][field] = bad
            cases.append(json.dumps([changed] * 3))
        changed = json.loads(json.dumps(value)); changed["peer"]["identity"]["driver_start_ticks"] = True
        cases.append(json.dumps([changed] * 3))
        changed = json.loads(json.dumps(value)); changed["driver_id"] = "é"
        cases.append(json.dumps([changed] * 3))
        for raw in cases:
            admitted = args(); admitted.managed_peers_json = raw
            current = probe.Probe(admitted); current.boot = ENVIRONMENT
            with mock.patch.object(probe, "Process", side_effect=AssertionError("process effect")):
                with self.subTest(length=len(raw)), self.assertRaises(probe.Refused):
                    current.admit_managed(None)

    def test_closed_phase_order_and_close(self):
        for index in range(3):
            value = frame(index)
            self.assertEqual(probe.decode_request(probe.canonical(value), index), value)
        self.assertEqual(probe.decode_request(b'{"op":"close"}', 3), {"op": "close"})
        for index in range(3):
            with self.assertRaises(probe.Refused):
                probe.decode_request(b'{"op":"close"}', index)
        with self.assertRaises(probe.Refused):
            probe.decode_request(probe.canonical(frame()), 1)

    def test_unknown_duplicate_and_boolean_fields_refuse(self):
        cases = [
            b'{"op":"close","op":"close"}', b'{"op":"close","command":"id"}',
            probe.canonical(frame(size=True)), probe.canonical(frame(op="signal")),
            probe.canonical(frame(pid=123)), probe.canonical(frame(phase="future")),
            probe.canonical(frame(sha256="A" * 64)), probe.canonical(frame(version="unsafe\nvalue")),
            b'{"op":"checkpoint","size":NaN}', b'[]', b'null', b'\xff',
        ]
        for raw in cases:
            with self.subTest(raw_length=len(raw)), self.assertRaises(probe.Refused):
                probe.decode_request(raw, 0)

    def test_request_byte_size_and_identity_limits(self):
        for raw in (b"", b"x" * (probe.MAX_REQUEST + 1)):
            with self.assertRaises(probe.Refused):
                probe.decode_request(raw, 0)
        for change in ({"size": 0}, {"size": probe.MAX_EXECUTABLE + 1}, {"version": "x" * 129}):
            with self.assertRaises(probe.Refused):
                probe.decode_request(probe.canonical(frame(**change)), 0)

    def test_arguments_refuse_before_any_process_or_path_effect(self):
        valid = ["--environment-id", ENVIRONMENT, "--nonce", NONCE,
                 "--daemon-sha256", "c" * 64, "--daemon-size", "10", "--daemon-version", "0.1.0-ci",
                 "--workspace-sha256", "a" * 64, "--workspace-size", "20", "--workspace-version", "0.1.0-release-A"]
        self.assertEqual(probe.arguments(valid).daemon_size, 10)
        self.assertEqual(probe.arguments(valid).workspace_size, 20)
        def changed(flag, value):
            result = list(valid)
            result[result.index(flag) + 1] = value
            return result
        invalid = [valid + ["--nonce", NONCE], valid + ["--signal", "9"],
                   changed("--environment-id", "0" * 36), changed("--nonce", "../../foreign")]
        for role in ("daemon", "workspace"):
            for field, value in (("size", "0"), ("size", str(probe.MAX_EXECUTABLE + 1)),
                                 ("sha256", "A" * 64), ("version", "unsafe\nversion")):
                invalid.append(changed("--" + role + "-" + field, value))
            invalid.append(valid + ["--" + role + "-version", "0.1.0-ci"])
            missing = list(valid)
            offset = missing.index("--" + role + "-sha256")
            del missing[offset:offset + 2]
            invalid.append(missing)
        with mock.patch.object(probe, "Probe", side_effect=AssertionError("process effect")):
            for command in invalid:
                with self.subTest(arguments=len(command)), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        probe.main(command)
                    self.assertEqual(error.exception.code, 2)

    def test_cached_image_output_requires_exact_path_version_and_hash_without_reset(self):
        path, version = probe.IMAGE_ALIASES[0], "0.1.0-ci"
        raw = (f"CWRP_PATH_{NONCE}\n{path}\nCWRP_VERSION_{NONCE}\ncw {version}\n"
               f"CWRP_STATUS_{NONCE}=0\nCWRP_HASH_{NONCE}\n{path}\nCWRP_END_{NONCE}\n").encode()
        self.assertEqual(probe.shell_result(raw, NONCE, version), path)
        cache = (f"CWRC_PATH_{NONCE}\n{path}\nCWRC_HASH_{NONCE}\n{path}\nCWRC_END_{NONCE}\n").encode()
        self.assertEqual(probe.cache_result(cache, NONCE), path)
        for wrong in (cache.replace(path.encode(), probe.ENTRY.encode()), cache + b"extra\n"):
            with self.assertRaises(probe.Refused):
                probe.cache_result(wrong, NONCE)
        for wrong in (raw.replace(path.encode(), probe.ENTRY.encode()),
                      raw.replace(b"cw 0.1.0-ci", b"cw stale"),
                      raw.replace(b"=0\n", b"=1\n"), raw + b"trailing\n",
                      raw.replace(f"CWRP_HASH_{NONCE}\n{path}".encode(),
                                  f"CWRP_HASH_{NONCE}\n{probe.IMAGE_ALIASES[1]}".encode())):
            with self.assertRaises(probe.Refused):
                probe.shell_result(wrong, NONCE, version)
        source = SOURCE.read_text()
        self.assertEqual(source.count('"hash cw\\n"'), 1)
        self.assertNotIn("hash -r", source)
        self.assertNotIn("PATH=", source)
        self.assertLess(source.index("self.baseline_shell()"), source.index('self.emit("ready")'))

    def test_distinct_workspace_release_and_support_alias_identities_are_closed(self):
        admitted = args()
        workspace = (admitted.workspace_sha256, admitted.workspace_size, admitted.workspace_version)
        support = (admitted.daemon_sha256, admitted.daemon_size, admitted.daemon_version)
        self.assertNotEqual(workspace, support)
        self.assertEqual(probe.original_alias_identity("/usr/local/bin/cw", admitted), workspace)
        self.assertEqual(probe.original_alias_identity("/codewire/bin/cw", admitted), support)
        for path in (probe.ENTRY, "/usr/local/bin/../bin/cw", "/foreign/cw"):
            with self.assertRaises(probe.Refused):
                probe.original_alias_identity(path, admitted)

    def test_fixed_roles_match_both_rendered_template_supervisors(self):
        source = (ROOT / "crates/codewire-orchestration/src/sandbox/template/workspace.rs").read_text()
        def constant(name):
            match = re.search(r"const " + name + r': &str = ("(?:\\.|[^"\\])*");', source)
            self.assertIsNotNone(match)
            return json.loads(match.group(1))
        def rendered(function, end, **extra):
            body = source.split("pub(super) fn " + function + "(", 1)[1].split(end, 1)[0]
            literals = re.findall(r'format!\(\s*("(?:\\.|[^"\\])*")', body, re.DOTALL)
            self.assertTrue(literals)
            normalized = re.sub(r"\\\n\s*", "", literals[-1])
            return json.loads(normalized).format(ensure_user=constant("ENSURE_USER_CMD"),
                                                 wait_daemon=constant("WAIT_DAEMON_CMD"),
                                                 daemon_command=constant("HOSTED_DAEMON_CMD"), **extra)
        managed = rendered("managed_workspace_supervisor_command", "pub(super) fn custom_workspace_supervisor_command(")
        # An identity-free workspace's keepalive: the one image command the
        # platform renders for a non-first-party image ref.
        keepalive = rendered("custom_workspace_supervisor_command", "\n}\n", workload="(exec 'sleep' 'infinity')")
        self.assertEqual(managed, probe.SUPERVISOR_COMMAND)
        self.assertNotIn("workload_pid", probe.SUPERVISOR_COMMAND)
        self.assertEqual(keepalive, probe.KEEPALIVE_SUPERVISOR_COMMAND)
        self.assertEqual(probe.SUPERVISOR_ARGVS, tuple(b"sh\0-c\0" + command.encode() + b"\0"
                                                        for command in (managed, keepalive)))

    def test_embedded_source_bound_and_no_observer_signal_api(self):
        import ast
        raw = SOURCE.read_bytes()
        self.assertLessEqual(len(raw), 48 * 1024)
        tree = ast.parse(raw)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Attribute)
                            and node.func.attr in {"kill", "killpg", "send_signal", "pidfd_send_signal"}
                            for node in calls))
        self.assertNotIn("__file__", raw.decode())
        self.assertNotIn("os.environ", raw.decode())


@unittest.skipUnless(sys.platform == "linux", "Linux pidfd fixture; no Mac qualification")
class KernelAndFiles(unittest.TestCase):
    def setUp(self):
        self.assertEqual((os.geteuid(), os.getegid()), (probe.UID, probe.GID))
        self.assertTrue(hasattr(os, "pidfd_open"), "required Linux kernel custody unavailable")
        self.assertTrue(hasattr(signal, "pidfd_send_signal"), "required exact test-child cleanup unavailable")
        self.root = Path(tempfile.mkdtemp(prefix="cw-probe-test-", dir=ROOT / ".tmp"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root))
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.proof_root = self.home / ".local/state/codewire/cw-runtime-proof"
        self.patch = mock.patch.multiple(probe, HOME_ROOT=str(self.home), PROOF_ROOT=str(self.proof_root))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    @contextlib.contextmanager
    def child(self, command=None, **options):
        current = subprocess.Popen(command or [sys.executable, "-I", "-u", "-c", CHILD],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, **options)
        fd = os.pidfd_open(current.pid)
        try:
            if command is None:
                self.assertTrue(select.select([current.stdout.fileno()], [], [], 3)[0], "child ready bound")
                self.assertEqual(current.stdout.readline(64), b"READY\n")
            yield current
        finally:
            try:
                current.stdin.close()
                if not select.select([fd], [], [], 1)[0]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                self.assertTrue(select.select([fd], [], [], 3)[0], "owned test child did not terminate")
                current.wait(timeout=1)
            finally:
                os.close(fd)
                current.stdout.close()
                current.stderr.close()

    @contextlib.contextmanager
    def managed_family_fixture(self):
        # Three synthetic driver/guardian/provider trees. Their only normal
        # exit command is one byte through the original driver's stdin.
        program = '''import json,os,subprocess,sys
depth=int(sys.argv[1]); source=sys.argv[2]; child=None
if depth:
 child=subprocess.Popen([sys.executable,"-I","-u","-c",source,str(depth-1),source],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
 identities=json.loads(child.stdout.readline())
else: identities=[]
print(json.dumps([os.getpid()]+identities),flush=True)
os.read(0,1)
if child:
 child.stdin.write(b"E"); child.stdin.flush(); child.stdin.close(); child.wait(timeout=3)
'''
        current = probe.Probe(args())
        current.boot = ENVIRONMENT
        current.directory = probe.Directory(NONCE)
        current.index, current.sequence, current.phase = 3, 3, probe.PHASES[-1]
        try:
            with contextlib.ExitStack() as stack:
                families = []
                for index in range(3):
                    child = stack.enter_context(self.child([sys.executable, "-I", "-u", "-c", program, "2", program]))
                    self.assertTrue(select.select([child.stdout.fileno()], [], [], 3)[0])
                    pids = json.loads(child.stdout.readline(256))
                    self.assertEqual(len(pids), 3)
                    parent = None
                    for role, pid in zip(("driver", "guardian", "provider"), pids):
                        actor = probe.Process(pid, f"managed{index}-{role}", current.deadline,
                                              expected_parent=os.getpid() if parent is None else parent.pid,
                                              parent=parent)
                        current.managed[f"managed{index}-{role}"] = actor
                        parent = actor
                    families.append(child)
                current.managed_cleanup = "live"
                yield current, families
        finally:
            current.close()

    def test_managed_stop_retains_nine_original_kernel_handles_until_normal_family_exit(self):
        with self.managed_family_fixture() as (current, families):
            events = []
            original = {name: actor.identity.copy() for name, actor in current.managed.items()}
            with mock.patch.object(current, "output", side_effect=events.append):
                with self.assertRaises(probe.Refused):
                    current.complete_managed_stop()
                current.prepare_managed_stop()
                self.assertFalse(events[-1].get("managed_terminal", False))
                self.assertTrue(all(not actor.terminal() for actor in current.managed.values()))
                for child in families:
                    child.stdin.write(b"E"); child.stdin.flush()
                current.complete_managed_stop()
                self.assertTrue(events[-1]["managed_terminal"])
                self.assertEqual(events[-1]["managed"], original)
                self.assertTrue(all(actor.terminal() for actor in current.managed.values()))
                for child in families:
                    self.assertEqual(child.wait(timeout=3), 0)
                with self.assertRaises(probe.Refused):
                    current.prepare_managed_stop()

    def test_managed_actor_exit_during_ready_output_refuses_before_ack_is_written(self):
        with self.managed_family_fixture() as (current, families):
            original_output = current.output
            original_write = probe.os.write
            def no_ready_bytes(fd, data):
                if fd == 1:
                    raise AssertionError("ready ACK written")
                return original_write(fd, data)
            def exit_before_write(body):
                self.assertEqual(current.managed_cleanup, "live")
                families[0].stdin.write(b"E"); families[0].stdin.flush()
                self.assertEqual(families[0].wait(timeout=3), 0)
                # Execute the real bounded output/verify path. No ready byte
                # may be written after one of the original handles is dead.
                original_output(body)
            with mock.patch.object(current, "output", side_effect=exit_before_write), \
                    mock.patch.object(probe.os, "write", side_effect=no_ready_bytes):
                with self.assertRaises(probe.Refused) as caught:
                    current.prepare_managed_stop()
                self.assertEqual(caught.exception.check, "pidfd-live")
                self.assertEqual(current.managed_cleanup, "live")

    def test_actual_child_identity_is_held_and_close_leaks_no_descriptors(self):
        before = own_fd_count()
        with self.child() as child:
            held = probe.Process(child.pid, "shell", time.monotonic() + 5,
                                 expected_parent=os.getpid(), expected_path=os.path.realpath(sys.executable))
            try:
                identity = dict(held.identity)
                held.verify()
                self.assertEqual(held.identity, identity)
                self.assertEqual(identity["pid"], child.pid)
                self.assertFalse(held.terminal())
            finally:
                held.close()
        self.assertEqual(own_fd_count(), before)

    def test_actual_child_wrong_parent_role_digest_and_size_refuse_without_signals(self):
        with self.child() as child:
            before = own_fd_count()
            for expected in ({"expected_parent": os.getpid() + 1}, {"expected_argv": b"foreign\0"},
                             {"expected_digest": "0" * 64}, {"expected_size": 0}):
                with self.subTest(field=next(iter(expected))), self.assertRaises(probe.Refused):
                    probe.Process(child.pid, "shell", time.monotonic() + 5, **expected)
                self.assertEqual(own_fd_count(), before)
                fd = os.pidfd_open(child.pid)
                try:
                    self.assertFalse(select.select([fd], [], [], 0)[0])
                finally:
                    os.close(fd)

    def test_actual_process_exit_refuses_even_while_birth_is_still_reserved(self):
        with self.child() as child:
            held = probe.Process(child.pid, "shell", time.monotonic() + 5)
            try:
                child.stdin.write(b"X"); child.stdin.flush()
                self.assertTrue(select.select([held.pidfd], [], [], 3)[0])
                with self.assertRaises(probe.Refused):
                    held.verify()
            finally:
                held.close()

    def test_actual_same_birth_exec_change_refuses(self):
        with self.child() as child:
            held = probe.Process(child.pid, "shell", time.monotonic() + 5)
            try:
                original = held.identity["start_ticks"]
                child.stdin.write(b"E"); child.stdin.flush()
                deadline = time.monotonic() + 3
                while os.readlink(f"/proc/{child.pid}/exe") == held.identity["executable"]:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                self.assertEqual(probe.birth(probe.read_at(held.proc, "stat"))[1], original)
                with self.assertRaises(probe.Refused):
                    held.verify()
            finally:
                held.close()

    def test_corrupt_birth_and_terminal_ancestor_refuse_without_child_admission(self):
        with self.child() as child:
            held = probe.Process(child.pid, "shell", time.monotonic() + 5)
            try:
                held.identity["start_ticks"] += 1
                with self.assertRaises(probe.Refused):
                    held.verify()
                with mock.patch.object(probe.os, "pidfd_open", side_effect=AssertionError("child admitted")):
                    with self.assertRaises(probe.Refused):
                        probe.Process(child.pid, "session", time.monotonic() + 5, parent=held)
            finally:
                held.close()

    def test_fixed_child_has_kernel_parent_death_and_no_new_privileges(self):
        child_code = ("import ctypes,json; c=ctypes.CDLL(None); s=ctypes.c_int(); "
                      "assert c.prctl(2,ctypes.byref(s),0,0,0)==0; "
                      "print(json.dumps({'signal':s.value,'nnp':c.prctl(39,0,0,0,0)}),flush=True)")
        with self.child([sys.executable, "-I", "-u", "-c", child_code],
                        preexec_fn=probe.child_confinement(os.getpid())) as child:
            self.assertTrue(select.select([child.stdout.fileno()], [], [], 3)[0])
            self.assertEqual(json.loads(child.stdout.readline(128)), {"signal": 9, "nnp": 1})

    def test_real_private_create_only_checkpoint_retains_exact_bytes(self):
        directory = probe.Directory(NONCE)
        try:
            body = {"event": "ready", "nonce": NONCE}
            result = directory.write("000-ready.json", body)
            expected = probe.canonical(body) + b"\n"
            path = Path(result["path"])
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(result["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(result["bytes"], len(expected))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            with self.assertRaises(FileExistsError):
                directory.write("000-ready.json", {"event": "changed"})
            self.assertEqual(path.read_bytes(), expected)
        finally:
            directory.close()

    def test_shared_home_volume_root_is_an_anchor_but_proof_ancestry_stays_private(self):
        # A Kubernetes home volume is root-owned 0777 (local-path) or a setgid
        # 2775 fsGroup root; the proof ancestry below it is still private.
        for nonce, mode in (("3" * 32, 0o777), ("4" * 32, 0o2775)):
            self.home.chmod(mode)
            probe.Directory(nonce).close()
            self.assertEqual(stat.S_IMODE((self.proof_root / nonce).stat().st_mode), 0o700)
        local = self.home / ".local"
        self.assertEqual(stat.S_IMODE(local.stat().st_mode), 0o700)
        local.chmod(0o777)
        with self.assertRaises(probe.Refused):
            probe.Directory("5" * 32)
        self.assertFalse((self.proof_root / ("5" * 32)).exists())
        local.chmod(0o700)
        self.home.chmod(0o700)

    def test_existing_nonce_and_writable_parent_are_not_adopted_or_chmodded(self):
        directory = probe.Directory(NONCE)
        directory.close()
        before = own_fd_count()
        mode = (self.proof_root / NONCE).stat().st_mode
        with self.assertRaises(probe.Refused):
            probe.Directory(NONCE)
        self.assertEqual(own_fd_count(), before)
        self.assertEqual((self.proof_root / NONCE).stat().st_mode, mode)
        self.proof_root.chmod(0o720)
        with self.assertRaises(probe.Refused):
            probe.Directory("2" * 32)
        self.assertEqual(stat.S_IMODE(self.proof_root.stat().st_mode), 0o720)
        self.assertFalse((self.proof_root / ("2" * 32)).exists())

    def test_replaced_proof_parent_and_linked_or_fifo_file_refuse(self):
        directory = probe.Directory(NONCE)
        try:
            external = self.root / "sentinel"
            external.write_bytes(b"preserve")
            os.link(external, directory.path + "/000-ready.json")
            with self.assertRaises(FileExistsError):
                directory.write("000-ready.json", {"event": "changed"})
            self.assertEqual(external.read_bytes(), b"preserve")
            os.mkfifo(directory.path + "/001-checkpoint.json", 0o600)
            with self.assertRaises(FileExistsError):
                directory.write("001-checkpoint.json", {"event": "changed"})
            renamed = self.proof_root / "retained"
            Path(directory.path).rename(renamed)
            Path(directory.path).symlink_to(renamed, target_is_directory=True)
            with self.assertRaises(probe.Refused):
                directory.verify()
        finally:
            directory.close()

    def test_unknown_fsync_ack_preserves_created_checkpoint(self):
        directory = probe.Directory(NONCE)
        try:
            real = probe.os.fsync
            def fail_directory(fd):
                if fd == directory.fd:
                    raise OSError("synthetic ACK loss")
                return real(fd)
            with mock.patch.object(probe.os, "fsync", side_effect=fail_directory):
                with self.assertRaises(OSError):
                    directory.write("000-ready.json", {"event": "ready"})
            self.assertEqual(Path(directory.path + "/000-ready.json").read_bytes(), b'{"event":"ready"}\n')
        finally:
            directory.close()

    def test_real_persistent_shell_caches_image_before_test_A_B_A_without_path_or_hash_reset(self):
        entry = self.home / ".local/bin/cw"
        entry.parent.mkdir(parents=True, mode=0o700)
        versions = self.home / ".local/share/codewire/cli/versions"
        versions.mkdir(parents=True, mode=0o700)
        identities = []
        for version in ("0.1.0-fixture-A", "0.1.0-fixture-B"):
            raw = ("#!/usr/bin/python3\nprint(" + repr("cw " + version) + ")\n").encode()
            checksum = hashlib.sha256(raw).hexdigest()
            member = versions / checksum
            member.mkdir(mode=0o700)
            (member / "cw").write_bytes(raw)
            (member / "cw").chmod(0o555)
            identities.append({"sha256": checksum, "size": len(raw), "version": version})
        image_bin = self.home / "image-bin"
        image_bin.mkdir(mode=0o755)
        image = image_bin / "cw"
        # Test-executable witness only: production selection is independently
        # exercised by Rust intake fixtures and the mandatory real Pod journey.
        image_bytes = ("#!/usr/bin/python3\nimport os\nentry=" + repr(str(entry)) + "\n"
                       "if os.path.lexists(entry): os.execv(entry,[entry,'--version'])\n"
                       "print('cw 0.1.0-release-A')\n").encode()
        image.write_bytes(image_bytes)
        image.chmod(0o555)
        environment = {"PATH": str(entry.parent) + ":" + str(image_bin) + ":/usr/bin:/bin", "HOME": str(self.home), "LC_ALL": "C"}
        child = subprocess.Popen(["/bin/bash", "--noprofile", "--norc"], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                 preexec_fn=probe.child_confinement(os.getpid()))
        fd = os.pidfd_open(child.pid)
        input_read, input_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        argument = args()
        argument.workspace_sha256 = hashlib.sha256(image_bytes).hexdigest()
        argument.workspace_size = len(image_bytes)
        current = probe.Probe(argument)
        current.deadline = time.monotonic() + 15
        current.input_fd = input_read
        events = []
        try:
            current.child = child
            current.actors["session"] = probe.Process(os.getpid(), "session", current.deadline)
            current.actors["shell"] = probe.Process(child.pid, "shell", current.deadline,
                                                     expected_parent=os.getpid(), expected_argv=probe.SHELL_ARGV,
                                                     parent=current.actors["session"])
            current.directory = probe.Directory(NONCE)
            for stream in (child.stdin, child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
            original = dict(current.actors["shell"].identity)
            with mock.patch.multiple(probe, ENTRY=str(entry), VERSIONS=str(versions),
                                     WORKSPACE_ALIAS=str(image), IMAGE_ALIASES=(str(image), probe.SUPPORT_ALIAS),
                                     IMAGE_OWNER=probe.UID), \
                    mock.patch.object(current, "output", side_effect=events.append):
                current.baseline_shell()
                self.assertFalse(entry.exists())
                self.assertEqual(current.selection["logical_path"], str(image))
                self.assertEqual(current.selection["sha256"], argument.workspace_sha256)
                self.assertNotEqual(current.selection["sha256"], argument.daemon_sha256)
                self.assertEqual(current.selection["version"], argument.workspace_version)
                current.settle()
                current.emit("ready")
                for index, identity in enumerate((identities[0], identities[1], identities[0])):
                    next_entry = entry.with_name("next-cw")
                    next_entry.symlink_to(versions / identity["sha256"] / "cw")
                    next_entry.replace(entry)
                    current.shell_check(frame(index, **identity))
                    self.assertEqual(current.selection["sha256"], identity["sha256"])
                    self.assertEqual(current.selection["logical_path"], str(image))
                    self.assertEqual(current.actors["shell"].identity, original)
                    current.phase = probe.PHASES[index]
                    current.sequence += 1
                    current.index += 1
                    current.emit("checkpoint")
                with self.assertRaises(probe.Refused):
                    current.shell_check(frame(version="stale-version", **{k: v for k, v in identities[0].items() if k != "version"}))
                # Public Attach cannot half-close stdin. The still-open private
                # pipe models that transport while the production close path
                # sends its one fixed exit command and reaps its exact child.
                current.finish()
                self.assertEqual(child.returncode, 0)
                self.assertTrue(current.actors["shell"].terminal())
                self.assertEqual([event["event"] for event in events],
                                 ["ready", "checkpoint", "checkpoint", "checkpoint", "closed"])
                self.assertEqual([event["sequence"] for event in events], list(range(5)))
                self.assertTrue(events[-1]["shell_terminal"])
                saved = Path(events[-1]["evidence"]["path"]).read_bytes()
                self.assertEqual(saved, probe.canonical({key: value for key, value in events[-1].items()
                                                        if key != "evidence"}) + b"\n")
                self.assertEqual(hashlib.sha256(saved).hexdigest(), events[-1]["evidence"]["sha256"])
        finally:
            try:
                child.stdin.close()
                if not select.select([fd], [], [], 1)[0]:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                self.assertTrue(select.select([fd], [], [], 3)[0])
                child.wait(timeout=1)
            finally:
                os.close(fd)
                os.close(input_read)
                os.close(input_write)
                # Probe.close expects stdin still represented, closing twice is harmless.
                current.close()

    def test_value_blind_refusal_does_not_include_shell_or_exception_material(self):
        current = probe.Probe(args())
        current.directory = probe.Directory(NONCE)
        outputs = []
        try:
            with mock.patch.object(current, "output", side_effect=lambda value, **_: outputs.append(value)):
                self.assertEqual(current.failed(OSError("synthetic-secret-never-log")), 2)
            self.assertNotIn("synthetic-secret", json.dumps(outputs))
            self.assertEqual(outputs[0]["check"], "observer-io")
            self.assertIsNone(outputs[0]["actor"])
            self.assertTrue(Path(outputs[0]["evidence"]["path"]).exists())
        finally:
            current.close()


if __name__ == "__main__":
    unittest.main()
