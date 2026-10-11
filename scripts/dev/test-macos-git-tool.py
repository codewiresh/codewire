#!/usr/bin/env python3
"""Portable tests for macos-git-tool.py; the Mac toolchain is mocked."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name("macos-git-tool.py").resolve()
SPEC = importlib.util.spec_from_file_location("macos_git_tool", SOURCE)
assert SPEC and SPEC.loader
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)

STOCK = ("\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
         "\t/usr/lib/libcurl.4.dylib (compatibility version 7.0.0)\n")


class FakeMac:
    """`tar`, `xcrun`, `make`, `otool`, `lipo`, `codesign` and the built git."""

    def __init__(self):
        self.calls = []
        self.libraries = STOCK
        self.version = b"git version 2.56.0\n"

    def run(self, argv, cwd=None, env=None, **_kwargs):
        self.calls.append((list(argv), env))
        stdout = b""
        if argv[0] == "/usr/bin/tar":
            (Path(argv[-1]) / ("git-" + tool.VERSION)).mkdir()
        elif argv[:2] == ["/usr/bin/xcrun", "--show-sdk-path"]:
            stdout = b"/synthetic/sdk\n"
        elif argv[:2] == ["/usr/bin/xcrun", "--show-sdk-version"]:
            stdout = b"26.4\n"
        elif argv[0] == "/usr/bin/make":
            for target, _name in tool.TARGETS:
                (Path(cwd) / target).write_bytes(b"\xcf\xfa\xed\xfe" + target.encode())
        elif argv[0] == "/usr/bin/otool":
            stdout = (argv[-1] + ":\n" + self.libraries).encode()
        elif argv[0] == "/usr/bin/lipo":
            stdout = b"arm64\n"
        elif argv[:2] == ["/usr/bin/env", "-i"]:
            stdout = self.version
        return subprocess.CompletedProcess(argv, 0, stdout=stdout)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="cw-git-tool-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.root)
        self.archive = self.root / tool.SOURCE_NAME
        self.archive.write_bytes(b"synthetic git source")
        self.mac = FakeMac()
        for patch in (
            mock.patch.object(tool.platform, "system", return_value="Darwin"),
            mock.patch.object(tool.platform, "machine", return_value="arm64"),
            mock.patch.object(tool, "SOURCE_SHA256", hashlib.sha256(b"synthetic git source").hexdigest()),
            mock.patch.object(tool.subprocess, "run", side_effect=self.mac.run),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def test_builds_the_pinned_bundle_in_a_cleared_environment(self):
        output = self.root / "out"
        result = tool.build(self.archive, output)
        bundle = output / "bundle"
        self.assertEqual(sorted(path.name for path in bundle.iterdir()), ["git", "git-remote-https"])
        for name in ("git", "git-remote-https"):
            program = bundle / name
            self.assertEqual(stat.S_IMODE(program.stat().st_mode), 0o500)
            self.assertEqual(result["tools"][name], hashlib.sha256(program.read_bytes()).hexdigest())
        self.assertEqual(json.loads((output / "result.json").read_text())["version"], "2.56.0")
        make = next((argv, env) for argv, env in self.mac.calls if argv[0] == "/usr/bin/make")
        self.assertEqual(make[0], ["/usr/bin/make", "-j8", "SDKROOT=/synthetic/sdk", *tool.MAKE_FLAGS,
                                   "git", "git-remote-http"])
        self.assertIn("NO_RUST=1", tool.MAKE_FLAGS)
        self.assertEqual(set(make[1]), {"PATH", "LC_ALL", "HOME", "TMPDIR", "SDKROOT"})
        self.assertEqual(make[1]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        for program in (bundle / "git", bundle / "git-remote-https"):
            checked = [argv for argv, _env in self.mac.calls if argv[-1] == str(program)]
            self.assertEqual([argv[0] for argv in checked],
                             ["/usr/bin/otool", "/usr/bin/lipo", "/usr/bin/codesign"])

    def test_refuses_an_unofficial_archive_or_a_reused_output(self):
        self.archive.write_bytes(b"changed source")
        with self.assertRaisesRegex(tool.BuildError, "is not the official git-2.56.0.tar.xz"):
            tool.build(self.archive, self.root / "out")
        self.assertFalse((self.root / "out").exists())
        self.archive.write_bytes(b"synthetic git source")
        (self.root / "used").mkdir()
        with self.assertRaisesRegex(tool.BuildError, "new absolute directory"):
            tool.build(self.archive, self.root / "used")
        self.assertEqual(self.mac.calls, [])

    def test_refuses_a_non_stock_library_or_another_version(self):
        self.mac.libraries = STOCK + "\t/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib (x)\n"
        with self.assertRaisesRegex(tool.BuildError, "links beyond the stock system libraries"):
            tool.build(self.archive, self.root / "one")
        self.mac.libraries = STOCK
        self.mac.version = b"git version 2.39.5 (Apple Git-154)\n"
        with self.assertRaisesRegex(tool.BuildError, "not git 2.56.0"):
            tool.build(self.archive, self.root / "two")

    def test_refuses_another_host(self):
        with mock.patch.object(tool.platform, "machine", return_value="x86_64"), \
                self.assertRaisesRegex(tool.BuildError, "Apple Silicon"):
            tool.build(self.archive, self.root / "out")


if __name__ == "__main__":
    unittest.main()
