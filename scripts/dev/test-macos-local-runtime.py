#!/usr/bin/env python3
"""Portable tests for macos-local-runtime.py; swift and codesign are mocked."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("macos-local-runtime.py").resolve()
REPOSITORY = SOURCE.parents[2]
SPEC = importlib.util.spec_from_file_location("macos_local_runtime", SOURCE)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def elf(machine: int = 183, interpreter: bool = False) -> bytes:
    """A minimal little-endian ELF64 executable with one program header."""
    header = bytearray(64)
    header[:6] = b"\x7fELF\x02\x01"
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (1).to_bytes(2, "little")
    program = bytearray(56)
    program[:4] = (3 if interpreter else 1).to_bytes(4, "little")
    return bytes(header + program) + b"payload"


def guest_root(**overrides) -> bytes:
    parts = {"init": elf() + b"init", "busybox": elf() + b"busybox", "runc": elf() + b"runc"}
    parts.update(overrides)
    return runtime.canonical_guest_root(parts["init"], parts["busybox"], parts["runc"])


def kernel_image() -> bytes:
    image = bytearray(4096)
    image[0x38:0x3C] = b"ARM\x64"
    return bytes(image)


def macho(tag: bytes) -> bytes:
    words = (0xFEEDFACF, 0x0100000C, 0, 2)
    return b"".join(word.to_bytes(4, "little") for word in words) + tag


SIGNATURE = b"\nFAKE-ADHOC-SIGNATURE\n"


class FakeTools:
    """In-process stand-ins for `swift build` and `/usr/bin/codesign`."""

    def __init__(self, scratch: Path):
        self.bin = scratch / "swift-bin"
        self.calls = []
        self.helper = macho(b"helper-one")
        self.signed_entitlements = None

    def run(self, argv, **_kwargs):
        self.calls.append(list(argv))
        if argv[0] == runtime.SWIFT:
            if argv[-1] == "--show-bin-path":
                return subprocess.CompletedProcess(argv, 0, stdout=str(self.bin).encode() + b"\n")
            self.bin.mkdir(exist_ok=True)
            (self.bin / runtime.PRODUCT).write_bytes(self.helper)
            return subprocess.CompletedProcess(argv, 0, stdout=None)
        if argv[0] == runtime.CODESIGN and argv[1] == "--force":
            target = Path(argv[-1])
            plist = Path(argv[argv.index("--entitlements") + 1]).read_bytes()
            entitlements = self.signed_entitlements if self.signed_entitlements is not None else plist
            target.write_bytes(target.read_bytes() + SIGNATURE + entitlements)
            return subprocess.CompletedProcess(argv, 0, stdout=None)
        if argv[0] == runtime.CODESIGN and argv[1] == "-d":
            data = Path(argv[-1]).read_bytes()
            if SIGNATURE not in data:
                return subprocess.CompletedProcess(argv, 1, stdout=b"")
            return subprocess.CompletedProcess(argv, 0, stdout=data.split(SIGNATURE, 1)[1])
        raise AssertionError("unexpected command %r" % (argv,))


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(os.path.realpath(tempfile.mkdtemp(prefix="cw-macos-runtime-test-")))
        self.addCleanup(shutil.rmtree, self.scratch)
        self.home = self.scratch / "home"
        self.home.mkdir()
        self.inputs = self.scratch / "inputs"
        self.inputs.mkdir()
        self.kernel = self.inputs / "Image"
        self.kernel.write_bytes(kernel_image())
        self.initramfs = self.inputs / "initramfs.cpio"
        self.initramfs.write_bytes(guest_root())
        self.e2fsprogs = self.scratch / "e2fsprogs" / "sbin"
        self.e2fsprogs.mkdir(parents=True)
        for program in runtime.E2FSPROGS_PROGRAMS:
            (self.e2fsprogs / program).write_bytes(b"")
        self.tools = FakeTools(self.scratch)
        self.environ = {"HOME": str(self.home)}
        self.parent = self.home / ".cache/codewire/local-vmm-v1"
        self.root = self.parent / "artifacts"
        self.lock = self.parent / "artifacts.lock.json"
        for patch in (
            mock.patch.object(runtime.platform, "system", return_value="Darwin"),
            mock.patch.object(runtime.platform, "machine", return_value="arm64"),
            mock.patch.object(runtime, "E2FSPROGS_DIRECTORIES", (str(self.e2fsprogs),)),
            mock.patch.object(runtime.subprocess, "run", side_effect=self.tools.run),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def install(self, *extra, kernel=None, initramfs=None):
        argv = ["--kernel", str(kernel if kernel is not None else self.kernel),
                "--initramfs", str(initramfs if initramfs is not None else self.initramfs), *extra]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = runtime.main(argv, environ=self.environ)
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_installed(self, root, lock):
        document = json.loads(lock.read_text())
        self.assertEqual(list(document), ["schema_version", "vz_runner", "kernel", "initramfs"])
        self.assertEqual(document["schema_version"], 1)
        for key, name, mode in runtime.ARTIFACTS:
            installed = root / name
            data = installed.read_bytes()
            self.assertEqual(document[key], {"path": name, "size": len(data),
                                             "sha256": hashlib.sha256(data).hexdigest(),
                                             "architecture": "aarch64"})
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), mode)
            self.assertEqual(installed.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o400)
        for directory in (root, lock.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(sorted(path.name for path in root.iterdir()),
                         sorted(name for _, name, _ in runtime.ARTIFACTS))
        self.assertEqual(sorted(path.name for path in lock.parent.iterdir()),
                         sorted([root.name, lock.name]))
        self.assertEqual((root / "kernel").read_bytes(), self.kernel.read_bytes())
        self.assertEqual((root / "initramfs").read_bytes(), self.initramfs.read_bytes())
        return document

    def snapshot(self, directory):
        return {str(path.relative_to(directory)): path.read_bytes()
                for path in sorted(directory.rglob("*")) if path.is_file()}

    def test_installs_signed_helper_kernel_and_guest_root_with_darwin_lock(self):
        status, stdout, stderr = self.install()
        self.assertEqual(status, 0, stderr)
        document = self.assert_installed(self.root, self.lock)
        helper = (self.root / runtime.PRODUCT).read_bytes()
        self.assertTrue(helper.startswith(self.tools.helper))
        self.assertTrue(helper.endswith(runtime.ENTITLEMENTS.read_bytes()))
        package = str(runtime.PACKAGE)
        self.assertEqual(self.tools.calls[0], ["swift", "build", "-c", "release", "--package-path", package])
        self.assertEqual(self.tools.calls[1][-1], "--show-bin-path")
        sign = self.tools.calls[2]
        self.assertEqual(sign[:7], ["/usr/bin/codesign", "--force", "--sign", "-",
                                    "--identifier", "codewire-vz-runner", "--entitlements"])
        self.assertEqual(sign[7], str(REPOSITORY / "crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist"))
        self.assertEqual(self.tools.calls[3][:5], ["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml"])
        self.assertIn("lock %s written" % self.lock, stdout)
        self.assertIn(document["vz_runner"]["sha256"], stdout)

        status, stdout, stderr = self.install()
        self.assertEqual(status, 0, stderr)
        self.assertIn("lock %s unchanged" % self.lock, stdout)
        self.assertEqual(json.loads(self.lock.read_text()), document)

    def test_different_lock_requires_replace(self):
        self.assertEqual(self.install()[0], 0)
        before = self.snapshot(self.parent)
        self.tools.helper = macho(b"helper-two")
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("already pins different artifacts; rerun with --replace", stderr)
        self.assertEqual(self.snapshot(self.parent), before)

        status, stdout, stderr = self.install("--replace")
        self.assertEqual(status, 0, stderr)
        self.assertIn("lock %s replaced" % self.lock, stdout)
        document = self.assert_installed(self.root, self.lock)
        self.assertTrue((self.root / runtime.PRODUCT).read_bytes().startswith(macho(b"helper-two")))
        self.assertNotEqual(document, json.loads(before["artifacts.lock.json"]))

    def test_unrecognized_lock_requires_replace(self):
        self.root.mkdir(mode=0o700, parents=True)
        self.parent.chmod(0o700)
        self.lock.write_bytes(b"not json")
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("--replace", stderr)
        self.assertEqual(self.lock.read_bytes(), b"not json")
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.install("--replace")[0], 0)
        self.assert_installed(self.root, self.lock)

    def test_linux_lock_is_left_untouched_even_with_replace(self):
        self.root.mkdir(mode=0o700, parents=True)
        self.parent.chmod(0o700)
        (self.root / "vmlinux").write_bytes(b"linux kernel")
        linux = json.dumps({"schema_version": 1, "cloud_hypervisor": {}, "kernel": {},
                            "initramfs": {}}).encode()
        self.lock.write_bytes(linux)
        self.lock.chmod(0o400)
        before = self.snapshot(self.parent)
        for extra in ((), ("--replace",)):
            status, _stdout, stderr = self.install(*extra)
            self.assertEqual(status, 1)
            self.assertIn("Linux (Cloud Hypervisor) artifact lock and is left untouched", stderr)
            self.assertEqual(self.snapshot(self.parent), before)
        self.assertEqual(self.tools.calls, [])

    def test_artifact_environment_overrides_are_honored(self):
        custom = self.scratch / "custom"
        self.environ.update({runtime.ROOT_ENV: str(custom / "blobs"),
                             runtime.LOCK_ENV: str(custom / "runtime.lock.json")})
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 0, stderr)
        self.assert_installed(custom / "blobs", custom / "runtime.lock.json")
        self.assertFalse((self.home / ".cache").exists())

    def test_one_override_keeps_the_other_default(self):
        self.environ[runtime.ROOT_ENV] = str(self.parent / "alternate")
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 0, stderr)
        self.assert_installed(self.parent / "alternate", self.lock)

    def test_invalid_artifact_locations_fail_before_effects(self):
        cases = (
            ({runtime.ROOT_ENV: "relative/artifacts"}, "must be an absolute path"),
            ({runtime.ROOT_ENV: str(self.scratch / "a/artifacts"),
              runtime.LOCK_ENV: str(self.scratch / "b/artifacts.lock.json")}, "share one parent"),
            ({"HOME": ""}, "HOME is not set"),
        )
        for overrides, message in cases:
            with self.subTest(message=message):
                environ = dict(self.environ, **overrides)
                with mock.patch.object(self, "environ", environ):
                    status, _stdout, stderr = self.install()
                self.assertEqual(status, 1)
                self.assertIn(message, stderr)
        link = self.scratch / "linked-home"
        link.symlink_to(self.home)
        self.environ["HOME"] = str(link)
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("canonical path without symbolic links", stderr)
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(self.tools.calls, [])

    def test_private_directory_modes_are_required(self):
        self.parent.mkdir(parents=True)
        self.parent.chmod(0o755)
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("must be a directory you own with mode 0700 (chmod 700 %s)" % self.parent, stderr)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_missing_e2fsprogs_fails_before_effects(self):
        (self.e2fsprogs / "resize2fs").unlink()
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("e2fsprogs is missing", stderr)
        self.assertIn("brew install e2fsprogs", stderr)
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(self.tools.calls, [])

    def test_missing_or_invalid_inputs_fail_before_effects(self):
        cases = (
            ({"kernel": ""}, "KERNEL is required: make macos-local-runtime KERNEL="),
            ({"initramfs": ""}, "INITRAMFS is required"),
            ({"kernel": "Image"}, "KERNEL must be an absolute path"),
            ({"kernel": self.inputs / "absent"}, "KERNEL does not exist"),
            ({"initramfs": self.inputs}, "INITRAMFS must be a non-empty regular file"),
        )
        for arguments, message in cases:
            with self.subTest(message=message):
                status, _stdout, stderr = self.install(**arguments)
                self.assertEqual(status, 1)
                self.assertIn(message, stderr)
        compressed = self.inputs / "Image.gz"
        compressed.write_bytes(b"\x1f\x8b" + bytes(4094))
        status, _stdout, stderr = self.install(kernel=compressed)
        self.assertIn("not an uncompressed arm64 Linux kernel Image", stderr)
        noncanonical = self.inputs / "extra.cpio"
        noncanonical.write_bytes(guest_root() + bytes(512))
        status, _stdout, stderr = self.install(initramfs=noncanonical)
        self.assertEqual(status, 1)
        self.assertIn("not the exact canonical archive", stderr)
        self.assertIn("--verify-root --target aarch64-unknown-linux-musl", stderr)
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual(self.tools.calls, [])

    def test_wrong_host_fails_before_effects(self):
        with mock.patch.object(runtime.platform, "system", return_value="Linux"), \
                mock.patch.object(runtime.platform, "machine", return_value="x86_64"):
            status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("need an Apple Silicon Mac (this host is Linux x86_64)", stderr)
        self.assertEqual(self.tools.calls, [])

    def test_helper_must_carry_exactly_the_developer_entitlements(self):
        self.tools.signed_entitlements = plistlib.dumps(
            {"com.apple.security.virtualization": True, "com.apple.security.get-task-allow": True})
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("does not carry exactly developer-entitlements.plist", stderr)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(self.lock.exists())

    def test_helper_must_be_thin_arm64_macho(self):
        self.tools.helper = b"\xca\xfe\xba\xbe" + bytes(60)
        status, _stdout, stderr = self.install()
        self.assertEqual(status, 1)
        self.assertIn("not a thin arm64 Mach-O executable", stderr)
        self.assertEqual(list(self.root.iterdir()), [])


class GuestRootTests(unittest.TestCase):
    def check(self, data):
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(data)
            stream.flush()
            runtime.check_initramfs(Path(stream.name))

    def test_admits_only_the_exact_canonical_arm64_root(self):
        self.check(guest_root())
        rejected = {
            "x86_64 init": guest_root(init=elf(machine=62)),
            "dynamic BusyBox": guest_root(busybox=elf(interpreter=True)),
            "x86_64 runc": guest_root(runc=elf(machine=62)),
            "trailing data": guest_root() + bytes(512),
            "probe-only archive": b"070701" + bytes(104),
        }
        for label, data in rejected.items():
            with self.subTest(label):
                with self.assertRaises(runtime.InstallError):
                    self.check(data)

    def test_refuses_an_embedded_cw_runtime(self):
        archive = bytearray(guest_root()[:-512].rstrip(b"\0"))
        trailer = archive.rfind(b"070701")
        entry = bytearray()
        runtime.newc_append(entry, 99, 0o100444, runtime.CW_RUNTIME_PROVENANCE_ENTRY + b"\0", b"{}")
        archive[trailer:trailer] = entry
        with self.assertRaisesRegex(runtime.InstallError, "embeds a cw runtime"):
            self.check(bytes(archive))

    def test_canonical_layout(self):
        archive = guest_root()
        self.assertEqual(len(archive) % 512, 0)
        self.assertEqual(runtime.newc_entry(archive, b"bin/sh"), b"busybox")
        self.assertEqual(runtime.newc_entry(archive, b"init"), elf() + b"init")
        self.assertIsNone(runtime.newc_entry(archive, b"missing"))
        # dev/null is character device 1:3 at inode 2, before /init.
        header = archive[archive.find(b"070701", 1):][:110]
        self.assertEqual(header[6:22], b"00000002000021b6")
        self.assertEqual(header[78:94], b"0000000100000003")


class SourceContractTests(unittest.TestCase):
    """The duplicated admission constants must follow their Rust sources."""

    def read(self, relative):
        return (REPOSITORY / relative).read_text()

    def test_python_3_9_syntax(self):
        ast.parse(SOURCE.read_text(), feature_version=(3, 9))

    def test_guest_root_layout_follows_newc_rs(self):
        source = self.read("crates/codewire-vmm-guest-probe/src/newc.rs")
        constants = dict(re.findall(r"^const (\w+): \w+ = (0o[0-7]+|\d+);$", source, re.MULTILINE))
        for name in ("INIT_MODE", "DIRECTORY_MODE", "SYMLINK_MODE", "NULL_DEVICE_MODE", "ARCHIVE_BLOCK"):
            self.assertEqual(getattr(runtime, name), int(constants[name], 0), name)
        applets = re.search(r"BASIC_BUSYBOX_APPLETS: &\[&str\] = &\[(.*?)\];", source, re.DOTALL)
        self.assertEqual(runtime.BASIC_BUSYBOX_APPLETS, tuple(re.findall(r'"([^"]*)"', applets.group(1))))
        body = source.split("pub fn canonical_guest_root_newc_with_cw(", 1)[1].split("for applet in", 1)[0]
        entries = re.findall(r'append_named_entry\(\s*&mut archive,\s*inode,\s*(\w+),\s*"([^"]+)"', body)
        self.assertEqual(entries, [("DIRECTORY_MODE", "bin"), ("DIRECTORY_MODE", "sbin"),
                                   ("DIRECTORY_MODE", "run"), ("INIT_MODE", "init"),
                                   ("INIT_MODE", "bin/busybox"), ("INIT_MODE", "sbin/runc")])
        self.assertIn('append_named_entry(archive, 1, DIRECTORY_MODE, "dev", &[], 0);', source)
        self.assertIn('append_entry(archive, 2, NULL_DEVICE_MODE, b"dev/null\\0", &[], 0, (1, 3));', source)
        self.assertRegex(source, r'SYMLINK_MODE,\s*&format!\("bin/\{applet\}"\),\s*b"busybox",\s*7,')
        self.assertIn('const TRAILER_NAME: &[u8] = b"TRAILER!!!\\0";', source)
        cw_runtime = self.read("crates/codewire-vmm-guest-probe/src/cw_runtime.rs")
        self.assertIn('CW_RUNTIME_PROVENANCE_ENTRY: &[u8] = b"codewire-cw/provenance.json";', cw_runtime)

    def test_admission_and_paths_follow_the_runtime(self):
        artifact = self.read("crates/codewire-local-vmm/src/artifact.rs")
        self.assertIn('ArtifactArchitecture::Aarch64 => bytes.len() >= 0x3c && &bytes[0x38..0x3c] == b"ARM\\x64"', artifact)
        self.assertIn("const INITRAMFS_LIMIT: u64 = 512 * 1024 * 1024;", artifact)
        self.assertIn("Self::Aarch64 => 183,", artifact)
        self.assertRegex(artifact, r"pub vz_runner: ArtifactSpec,\s*pub kernel: ArtifactSpec,\s*pub initramfs: ArtifactSpec,")
        self.assertIn("Some(if executable { 0o500 } else { 0o400 })", artifact)
        darwin = self.read("crates/codewire-local-vmm/src/darwin/mod.rs")
        directories = re.search(r"E2FSPROGS_DIRECTORIES: \[&str; \d+\] = \[(.*?)\];", darwin, re.DOTALL)
        self.assertEqual(runtime.E2FSPROGS_DIRECTORIES, tuple(re.findall(r'"([^"]+)"', directories.group(1))))
        self.assertIn('Command::new("/usr/bin/codesign")', darwin)
        native = self.read("crates/codewire-cli/src/commands/native.rs")
        self.assertIn('NATIVE_ARTIFACT_ROOT_ENV: &str = "%s";' % runtime.ROOT_ENV, native)
        self.assertIn('NATIVE_ARTIFACT_LOCK_ENV: &str = "%s";' % runtime.LOCK_ENV, native)
        self.assertIn('home.join(".cache").join("codewire").join("local-vmm-v1")', native)
        self.assertIn('artifact_parent.join("artifacts.lock.json")', native)
        self.assertTrue(runtime.ENTITLEMENTS.is_file())
        self.assertEqual(plistlib.loads(runtime.ENTITLEMENTS.read_bytes()),
                         {"com.apple.security.virtualization": True})


if __name__ == "__main__":
    unittest.main()
