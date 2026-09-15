#!/usr/bin/env python3
"""Synthetic resource-ownership tests, never attach a real image."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("mount_fixture", Path(__file__).with_name("mount_fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FakeFixture(fixture.Fixture):
    def __init__(self, root, fault=None):
        super().__init__(root)
        self.fault = fault
        self.calls = []
        self.attached = False
        self.mounted_inode = None

    def entity(self):
        return {"mount-point": str(self.mountpoint), "dev-entry": "/dev/disk91s1"}

    def command(self, argv, timeout):
        self.calls.append(argv)
        if argv[1] == "create":
            self.image.touch()
        elif argv[1] == "attach":
            self.mountpoint.rename(self.root / "covered")
            self.mountpoint.mkdir(mode=0o700)
            self.mountpoint.chmod(0o755)
            self.mounted_inode = self.mountpoint.stat().st_ino
            self.attached = True
            if self.fault == "attach-timeout":
                raise RuntimeError("attach timeout")
            if self.fault == "malformed":
                return b"not a plist"
            entities = [self.entity()]
            if self.fault == "multiple":
                entities.append(self.entity())
            return plistlib.dumps({"system-entities": entities})
        elif argv[1] == "info":
            images = [{"image-path": str(self.image), "system-entities": [self.entity()]}] if self.attached else []
            return plistlib.dumps({"images": images})
        elif argv[1] == "detach":
            if self.fault == "detach":
                raise RuntimeError("detach failed")
            self.mountpoint.rmdir()
            (self.root / "covered").rename(self.mountpoint)
            self.attached = False
        else:
            if self.mountpoint.stat().st_mode & 0o777 != 0o700:
                raise RuntimeError("child ran before private mode preparation")
            if self.fault == "child":
                raise RuntimeError("child failed")
            if self.fault == "replace":
                self.mountpoint.rename(self.root / "unexpected")
                self.mountpoint.mkdir(mode=0o700)
            if self.fault == "zero-tests":
                return b"test result: ok. 0 passed; 0 failed; 0 ignored;"
            return b"test result: ok. 1 passed; 0 failed; 0 ignored;"
        return b""

    def synthetic_mount_stat(self, metadata):
        values = list(metadata)
        if metadata.st_ino == self.mounted_inode:
            values[2] += 1  # st_dev: synthetic cross-filesystem identity, not native proof.
        return os.stat_result(values)


class FixtureTests(unittest.TestCase):
    def test_success_and_all_ambiguous_failures(self):
        for fault in [None, "malformed", "multiple", "attach-timeout", "chmod", "child", "zero-tests", "detach", "replace"]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="cw-mount-synthetic-") as parent:
                root = Path(parent) / "owned"
                root.mkdir(mode=0o700)
                proof = FakeFixture(root, fault)
                original_fstat, original_stat = os.fstat, os.stat
                chmod = mock.patch.object(fixture.os, "fchmod", side_effect=OSError("synthetic chmod failure")) if fault == "chmod" else contextlib.nullcontext()
                with mock.patch.object(fixture.os, "fstat", side_effect=lambda fd: proof.synthetic_mount_stat(original_fstat(fd))), \
                     mock.patch.object(fixture.os, "stat", side_effect=lambda *args, **kwargs: proof.synthetic_mount_stat(original_stat(*args, **kwargs))), \
                     chmod, contextlib.redirect_stdout(io.StringIO()):
                    if fault is None:
                        proof.execute("/synthetic-test")
                    else:
                        with self.assertRaises(Exception):
                            proof.execute("/synthetic-test")
                self.assertEqual(root.exists(), fault is not None)
                detaches = [argv for argv in proof.calls if argv[1] == "detach"]
                self.assertEqual(len(detaches), 1 if fault in (None, "detach") else 0)
                if fault == "chmod":
                    self.assertFalse(any(argv[0] == "/synthetic-test" for argv in proof.calls))
                for argv in detaches:
                    self.assertEqual(argv, ["/usr/bin/hdiutil", "detach", str(proof.mountpoint)])
                create = proof.calls[0]
                self.assertEqual(create, ["/usr/bin/hdiutil", "create", "-size", "64m", "-fs", "APFS",
                    "-type", "UDIF", "-volname", "cw-path-proof", "-uid", str(os.getuid()),
                    "-gid", str(os.getgid()), "-mode", "0700", str(proof.image)])
                self.assertNotIn("-format", create)  # Mutually exclusive with -type.
                self.assertEqual(proof.calls[1], ["/usr/bin/hdiutil", "attach", str(proof.image),
                    "-nobrowse", "-noautoopen", "-owners", "on", "-mountpoint", str(proof.mountpoint), "-plist"])

    def test_image_association_and_detachment_require_exact_ownership(self):
        record = {"image-path": "/owned/volume.dmg", "system-entities": [
            {"dev-entry": "/dev/disk91"},
            {"dev-entry": "/dev/disk92s1", "mount-point": "/owned/mounted"}]}
        fixture.image_record({"images": [record]}, Path("/owned/volume.dmg"), Path("/owned/mounted"), "/dev/disk92s1")
        for image, mount, device in [("/wrong", "/owned/mounted", "/dev/disk92s1"),
                                     ("/owned/volume.dmg", "/wrong", "/dev/disk92s1"),
                                     ("/owned/volume.dmg", "/owned/mounted", "/dev/disk91")]:
            with self.assertRaises(RuntimeError):
                fixture.image_record({"images": [record]}, Path(image), Path(mount), device)
        with self.assertRaises(RuntimeError):
            fixture.detached({"images": [record]}, Path("/owned/volume.dmg"), Path("/owned/mounted"))
        fixture.detached({"images": []}, Path("/owned/volume.dmg"), Path("/owned/mounted"))

    def test_timeout_reaps_only_owned_child_and_retains_logs(self):
        self.check_interrupted_child("timeout")

    def test_exception_after_spawn_reaps_only_owned_child(self):
        self.check_interrupted_child("io-error")

    def test_cancellation_after_spawn_reaps_only_owned_child(self):
        self.check_interrupted_child("cancel")

    def test_cancellation_immediately_after_spawn_reaps_owned_child(self):
        self.check_interrupted_child("spawn-cancel")

    def check_interrupted_child(self, failure):
        with tempfile.TemporaryDirectory() as parent:
            proof = fixture.Fixture(Path(parent))
            children = []
            original = fixture.subprocess.Popen
            def spawn(*args, **kwargs):
                child = original(*args, **kwargs)
                child.kill = mock.Mock(wraps=child.kill)
                child.wait = mock.Mock(wraps=child.wait)
                children.append(child)
                return child
            error = OSError("synthetic selector I/O error") if failure == "io-error" else InterruptedError("synthetic cancellation")
            selector = mock.patch.object(fixture.selectors, "DefaultSelector", side_effect=error) if failure in ("io-error", "cancel") else contextlib.nullcontext()
            cancellation = mock.patch.object(fixture, "check_cancelled", side_effect=[None, InterruptedError("post-spawn cancellation")]) if failure == "spawn-cancel" else contextlib.nullcontext()
            with mock.patch.object(fixture.subprocess, "Popen", side_effect=spawn), selector, cancellation, \
                 contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises((RuntimeError, OSError)):
                    proof.command([sys.executable, "-c", "import time; time.sleep(30)"], -1)
            child, = children
            child.kill.assert_called_once_with()
            child.wait.assert_called_once_with(timeout=5)
            self.assertIsNotNone(child.returncode)
            self.assertTrue((Path(parent) / "command-01.out").exists())

    def test_late_terminal_observation_cannot_pass_deadline(self):
        with tempfile.TemporaryDirectory() as parent, contextlib.redirect_stdout(io.StringIO()):
            proof = fixture.Fixture(Path(parent))
            child = mock.Mock(returncode=0, stdout=io.BytesIO(), stderr=io.BytesIO())
            child.poll.return_value = 0
            with mock.patch.object(fixture.subprocess, "Popen", return_value=child), \
                 mock.patch.object(fixture.selectors, "DefaultSelector") as selector:
                selector.return_value.__enter__.return_value.get_map.return_value = {}
                with self.assertRaisesRegex(RuntimeError, "time bound"):
                    proof.command(["/synthetic", "late"], -1)
            child.kill.assert_not_called()

    def test_output_capture_and_logs_are_bounded(self):
        with tempfile.TemporaryDirectory() as parent, contextlib.redirect_stdout(io.StringIO()):
            proof = fixture.Fixture(Path(parent))
            with self.assertRaisesRegex(RuntimeError, "output bound"):
                proof.command([sys.executable, "-c", "import os; os.write(1, b'x' * (2 * 1024 * 1024))"], 5)
            self.assertLessEqual((Path(parent) / "command-01.out").stat().st_size, fixture.LIMIT)


if __name__ == "__main__":
    unittest.main()
