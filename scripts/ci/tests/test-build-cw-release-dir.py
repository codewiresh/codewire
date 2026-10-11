#!/usr/bin/env python3
"""Focused build-cw.py --release-dir fixtures; never run Cargo or cw.

The release directory is checked against scripts/dev/test-cli-update.py's own
reader, so the producer and the update journey cannot drift apart.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("build_cw", ROOT / "scripts/dev/build-cw.py")
journey = load("cli_update_journey", ROOT / "scripts/dev/test-cli-update.py")


def identity_for(data, version="0.1.0-journey.a"):
    return {"package_version": version, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
            "source_revision": "a" * 40, "source_tree_sha256": "b" * 64, "target": "x86_64-unknown-linux-gnu"}


class ReleaseDirectory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.data = b"\x7fELF fixture executable bytes"
        self.identity = identity_for(self.data)

    def test_writes_the_shape_the_update_journey_reads(self):
        directory = self.parent / "A"
        build.write_release_dir(directory, self.data, self.identity)
        self.assertEqual(sorted(os.listdir(directory)), ["cw", "cw-runtime.json"])
        self.assertEqual(stat.S_IMODE(directory.lstat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / "cw").lstat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE((directory / "cw-runtime.json").lstat().st_mode), 0o400)
        self.assertEqual((directory / "cw").read_bytes(), self.data)
        self.assertEqual((directory / "cw-runtime.json").read_bytes(), build.release.canonical(self.identity))
        resolved, identity = journey.release(directory, self.identity["sha256"])
        self.assertEqual(resolved, directory.resolve())
        self.assertEqual(identity, self.identity)

    def test_a_and_b_differ_by_version_and_bytes(self):
        other = self.data + b" built as B"
        build.write_release_dir(self.parent / "A", self.data, self.identity)
        build.write_release_dir(self.parent / "B", other, identity_for(other, "0.1.0-journey.b"))
        a = json.loads((self.parent / "A/cw-runtime.json").read_text())
        b = json.loads((self.parent / "B/cw-runtime.json").read_text())
        self.assertNotEqual(a["sha256"], b["sha256"])
        self.assertNotEqual(a["package_version"], b["package_version"])

    def test_existing_path_is_refused_untouched(self):
        directory = self.parent / "A"
        directory.mkdir()
        (directory / "keep").write_text("owner data\n")
        with self.assertRaises(FileExistsError):
            build.write_release_dir(directory, self.data, self.identity)
        self.assertEqual(os.listdir(directory), ["keep"])

    def test_bytes_that_differ_from_the_identity_create_nothing(self):
        directory = self.parent / "A"
        with self.assertRaises(build.release.ReleaseError):
            build.write_release_dir(directory, self.data + b"!", self.identity)
        self.assertFalse(directory.exists())

    def test_partial_write_is_removed(self):
        directory = self.parent / "A"
        real = build.release.write_new
        calls = []

        def failing(path, data, mode=0o644):
            calls.append(Path(path).name)
            if Path(path).name == "cw-runtime.json":
                raise OSError("disk full")
            return real(path, data, mode)

        with mock.patch.object(build.release, "write_new", failing), self.assertRaises(OSError):
            build.write_release_dir(directory, self.data, self.identity)
        self.assertEqual(calls, ["cw", "cw-runtime.json"])
        self.assertFalse(directory.exists())

    def build_with(self, argv):
        """Run main with Cargo, Git and admission replaced; return the build command and admission."""
        rustc = "rustc 1.93.0 (254b59607 2026-01-19)"

        def check_output(command, **kwargs):
            return "host: x86_64-unknown-linux-gnu\n" if command[-1] == "-vV" else rustc + "\n"

        admitted = {}

        def admit(root, binary, depinfo, target, *rest):
            admitted.update(binary=binary, depinfo=depinfo, target=target)
            return self.data, dict(self.identity, target=target), 1

        target_dir = self.parent / "target"
        with mock.patch.dict(os.environ, {"CARGO_TARGET_DIR": str(target_dir), "CODEWIRE_VERSION": "0.1.0-journey.a"}), \
                mock.patch.object(build.subprocess, "check_output", check_output), \
                mock.patch.object(build.subprocess, "run") as run, \
                mock.patch.object(build.release, "head_revision", return_value="a" * 40), \
                mock.patch.object(build.release, "source_tree_sha256", return_value="b" * 64), \
                mock.patch.object(build.release, "admit_build", admit), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(build.main(argv), 0)
        return run.call_args.args[0], admitted, target_dir

    def test_release_target_cross_compiles_with_zigbuild(self):
        directory = self.parent / "A"
        command, admitted, target_dir = self.build_with(
            ["--profile", "ci", "--target", "x86_64-unknown-linux-musl", "--release-dir", str(directory)])
        self.assertEqual(command[1:4], ["zigbuild", "--target", "x86_64-unknown-linux-musl"])
        self.assertEqual(admitted["binary"], target_dir / "x86_64-unknown-linux-musl/ci/cw")
        self.assertEqual(admitted["target"], "x86_64-unknown-linux-musl")
        identity = json.loads((directory / "cw-runtime.json").read_text())
        self.assertEqual(identity["target"], "x86_64-unknown-linux-musl")

    def test_default_target_is_the_host_build(self):
        command, admitted, target_dir = self.build_with(["--profile", "ci", "--output", str(self.parent / "cw")])
        self.assertEqual(command[1], "build")
        self.assertNotIn("--target", command)
        self.assertEqual(admitted["binary"], target_dir / "ci/cw")
        self.assertEqual(admitted["target"], "x86_64-unknown-linux-gnu")

    def test_exactly_one_destination_before_any_build(self):
        for argv in ([], ["--output", str(self.parent / "cw"), "--release-dir", str(self.parent / "A")]):
            with self.subTest(argv=argv), mock.patch.object(build.subprocess, "check_output") as probe, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                build.main(argv)
            self.assertEqual(raised.exception.code, 2)
            probe.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2 if "-v" in sys.argv else 1)
