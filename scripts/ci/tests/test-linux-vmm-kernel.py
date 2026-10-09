#!/usr/bin/env python3
"""Pinned configuration and actual Linux build-family refusal tests; no VM."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("kernel_builder", ROOT / "scripts/ci/verify/build-linux-vmm-kernel.py")
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)


class Configuration(unittest.TestCase):
    def setUp(self):
        self.pins = json.loads((kernel.INPUTS / "provenance.json").read_text())
        self.config = (kernel.INPUTS / "x86_64.config").read_bytes()

    def test_actual_config_is_only_the_required_feature_change(self):
        baseline = kernel.configuration(self.config, self.pins)
        self.assertIn(b"# CONFIG_PROC_CHILDREN is not set\n", baseline)
        self.assertEqual(len(self.config.split(b"CONFIG_PROC_CHILDREN=y\n")), 2)

    def test_exact_old_qualified_config_is_refused(self):
        baseline = self.config.replace(b"CONFIG_PROC_CHILDREN=y\n", b"# CONFIG_PROC_CHILDREN is not set\n")
        with self.assertRaisesRegex(ValueError, "config differs"):
            kernel.configuration(baseline, self.pins)

    def test_unadmitted_kernel_surface_and_duplicate_flag_are_refused(self):
        for changed in [self.config + b"CONFIG_PROC_CHILDREN=y\n",
                        self.config.replace(b"# CONFIG_CHECKPOINT_RESTORE is not set\n", b"CONFIG_CHECKPOINT_RESTORE=y\n"),
                        self.config.replace(b"CONFIG_PROC_FS=y\n", b"# CONFIG_PROC_FS is not set\n")]:
            with self.subTest(size=len(changed)), self.assertRaises(ValueError):
                kernel.configuration(changed, self.pins)

    def test_original_compatibility_patch_and_distinct_release_are_pinned(self):
        self.assertEqual(kernel.digest(kernel.INPUTS / "dax.patch"), self.pins["patch_sha256"])
        self.assertEqual(self.pins["release"], "6.18.48-codewire2")


class FileCustody(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="kernel-input-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.input = self.root / "input"

    def test_streamed_hash_and_empty_log_bound(self):
        raw = b"kernel-source" * 100000
        self.input.write_bytes(raw)
        self.assertEqual(kernel.digest(self.input, len(raw)), hashlib.sha256(raw).hexdigest())
        self.input.write_bytes(b"")
        self.assertEqual(kernel.digest(self.input, allow_empty=True), hashlib.sha256(b"").hexdigest())
        with self.assertRaises(ValueError):
            kernel.regular(self.input)

    def test_fifo_symlink_hardlink_and_oversize_are_refused(self):
        os.mkfifo(self.input)
        with self.assertRaises(ValueError):
            kernel.regular(self.input)
        self.input.unlink()
        other = self.root / "other"; other.write_bytes(b"abc")
        self.input.symlink_to(other)
        with self.assertRaises(OSError):
            kernel.regular(self.input)
        self.input.unlink()
        os.link(other, self.input)
        with self.assertRaises(ValueError):
            kernel.regular(self.input)
        self.input.unlink()
        self.input.write_bytes(b"abc")
        with self.assertRaises(ValueError):
            kernel.digest(self.input, maximum=2)

    def test_path_replacement_during_held_read_is_refused(self):
        original_read = os.read
        for reader in (kernel.regular, kernel.digest):
            self.input.write_bytes(b"abc")
            replacement = self.root / "replacement"; replacement.write_bytes(b"abc")
            swapped = False
            def read(descriptor, count):
                nonlocal swapped
                result = original_read(descriptor, count)
                if not swapped:
                    replacement.replace(self.input)
                    swapped = True
                return result
            with self.subTest(reader=reader.__name__), mock.patch.object(os, "read", read), \
                    self.assertRaisesRegex(ValueError, "input changed"):
                reader(self.input)

    def test_private_output_rejects_writable_parent_and_existing_leaf(self):
        output = self.root / "build"
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "output parent"):
            kernel.admit_output(output)
        self.root.chmod(0o700)
        kernel.admit_output(output)
        kernel.private_directory(output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(ValueError, "fresh canonical"):
            kernel.admit_output(output)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux custody required")
class KernelCustody(unittest.TestCase):
    def setUp(self):
        kernel.arm_custody()
        kernel.STOP = None
        self.tmp = tempfile.TemporaryDirectory(prefix="kernel-custody-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "LC_ALL": "C"}

    def run_command(self, script, timeout=5):
        return kernel.run_owned([sys.executable, "-c", script], self.root, self.environment,
                                self.root / "output.log", time.monotonic() + timeout,
                                grace=0.1, cleanup_bound=5)

    def no_children(self):
        self.assertEqual(kernel.children(), set())
        with self.assertRaises(ChildProcessError):
            os.waitpid(-1, os.WNOHANG | kernel.WALL)

    def test_success_observes_actual_echild(self):
        result = self.run_command("print('kernel-tool-output')")
        self.assertEqual(result["exit"], 0)
        self.assertFalse(result["cleanup_unknown"])
        self.no_children()

    def test_admission_preserves_an_existing_terminal_child(self):
        child = os.fork()
        if child == 0:
            os._exit(37)
        try:
            before = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
            with self.assertRaisesRegex(ValueError, "existing children"):
                kernel.arm_custody()
            after = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT)
            self.assertEqual(before, after)
            self.assertEqual(after.si_status, 37)
        finally:
            os.waitpid(child, 0)
        self.no_children()

    def test_command_failure_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "command failed"):
            self.run_command("raise SystemExit(7)")
        self.no_children()

    def test_timeout_joins_sigterm_ignoring_detached_compiler(self):
        script = """import os,signal,time
if os.fork()==0:
 os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True: time.sleep(1)
time.sleep(30)
"""
        with self.assertRaisesRegex(ValueError, "command failed"):
            self.run_command(script, timeout=0.2)
        self.no_children()

    def test_unexpected_surviving_compiler_is_refused_after_cleanup(self):
        script = """import os,signal,time
if os.fork()==0:
 os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True: time.sleep(1)
time.sleep(0.1)
"""
        with self.assertRaisesRegex(ValueError, "command failed"):
            self.run_command(script)
        self.no_children()

    def test_cancellation_joins_the_actual_detached_family(self):
        previous = signal.signal(signal.SIGALRM, kernel.on_signal)
        signal.setitimer(signal.ITIMER_REAL, 0.2)
        try:
            with self.assertRaisesRegex(ValueError, '"interrupted": true'):
                self.run_command("""import os,signal,time
if os.fork()==0:
 os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True: time.sleep(1)
time.sleep(30)
""")
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            kernel.STOP = None
        self.no_children()

    def test_initial_binding_error_still_joins_the_family(self):
        ready = self.root / "ready"
        original_bind = kernel.bind_child
        first = True
        def bind(pid):
            nonlocal first
            if first:
                first = False
                bound = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < bound:
                    time.sleep(0.01)
                self.assertTrue(ready.exists(), "detached fixture did not become ready")
                raise ValueError("injected initial binding error")
            return original_bind(pid)
        with mock.patch.object(kernel, "bind_child", bind), \
                self.assertRaisesRegex(ValueError, "injected initial binding error"):
            self.run_command("""import os,signal,time
if os.fork()==0:
 os.setsid(); signal.signal(signal.SIGTERM,signal.SIG_IGN)
 open('ready','w').close()
 while True: time.sleep(1)
time.sleep(30)
""")
        self.no_children()


if __name__ == "__main__":
    unittest.main()
