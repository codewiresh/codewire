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


def cw_runtime(directory: Path, target: str = "aarch64-unknown-linux-musl", payload: bytes = None,
               corrupt: bool = False) -> Path:
    """A sealed runtime pack and lock in the shape cw-runtime-image.py pack writes."""
    payload = elf() + b"cw" if payload is None else payload
    index = "1" * 64
    provenance = json.dumps({"schema_version": 1, "image_index_sha256": index,
                             "payload": {"target": target, "sha256": hashlib.sha256(payload).hexdigest(),
                                         "size": len(payload)}}).encode()
    pack = b"CWRPACK1" + len(provenance).to_bytes(8, "little") + len(payload).to_bytes(8, "little")
    pack += provenance + payload
    lock = {"schema_version": 1, "image_index_sha256": index,
            "pack": {"path": "runtime.pack", "size": len(pack), "sha256": hashlib.sha256(pack).hexdigest()}}
    directory.mkdir()
    (directory / "runtime.pack").write_bytes(pack[:-1] + b"X" if corrupt else pack)
    (directory / "cw-runtime.lock.json").write_text(json.dumps(lock) + "\n")
    return directory


def kernel_image() -> bytes:
    image = bytearray(4096)
    image[0x38:0x3C] = b"ARM\x64"
    return bytes(image)


def macho(tag: bytes) -> bytes:
    words = (0xFEEDFACF, 0x0100000C, 0, 2)
    return b"".join(word.to_bytes(4, "little") for word in words) + tag


SIGNATURE = b"\nFAKE-ADHOC-SIGNATURE\n"


REVISION = "c" * 40


class FakeTools:
    """In-process stand-ins for `swift build`, `/usr/bin/codesign`, git and cw."""

    def __init__(self, scratch: Path):
        self.bin = scratch / "swift-bin"
        self.calls = []
        self.helper = macho(b"helper-one")
        self.signed_entitlements = None
        self.cw_status = 0
        self.installed = None

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
        if argv[:2] == ["git", "-C"] and argv[3:] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(argv, 0, stdout=REVISION.encode() + b"\n")
        if argv[1:4] == ["setup", "--local", "--from"]:
            release = Path(argv[4])
            self.installed = {str(path.relative_to(release)): path.read_bytes()
                              for path in sorted(release.rglob("*")) if path.is_file()}
            return subprocess.CompletedProcess(argv, self.cw_status, stdout=None)
        raise AssertionError("unexpected command %r" % (argv,))


class PackTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(os.path.realpath(tempfile.mkdtemp(prefix="cw-macos-runtime-test-")))
        self.addCleanup(shutil.rmtree, self.scratch)
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
        self.release = self.scratch / "release"
        for patch in (
            mock.patch.object(runtime.platform, "system", return_value="Darwin"),
            mock.patch.object(runtime.platform, "machine", return_value="arm64"),
            mock.patch.object(runtime, "E2FSPROGS_DIRECTORIES", (str(self.e2fsprogs),)),
            mock.patch.object(runtime.subprocess, "run", side_effect=self.tools.run),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def main(self, *extra, kernel=None, initramfs=None):
        argv = ["--kernel", str(kernel if kernel is not None else self.kernel),
                "--initramfs", str(initramfs if initramfs is not None else self.initramfs), *extra]
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = runtime.main(argv)
        return status, stdout.getvalue(), stderr.getvalue()

    def pack(self, *extra, **inputs):
        return self.main("--pack", str(self.release), *extra, **inputs)

    def assert_release(self, files, cw_runtime=None):
        """`files` maps release-relative paths to bytes; returns the document."""
        document = json.loads(files[runtime.LOCAL_RUNTIME_DOCUMENT])
        self.assertEqual(document["schema"], "codewire.cw.local-runtime/v1")
        self.assertEqual(document["source_revision"], REVISION)
        self.assertEqual(list(document["targets"]), ["macos-aarch64"])
        target = document["targets"]["macos-aarch64"]
        lock = target["lock"]
        self.assertEqual(list(lock), ["schema_version", "vz_runner", "kernel", "initramfs"])
        self.assertEqual(lock["schema_version"], 1)
        blobs = {name[len("blobs/sha256/"):]: data for name, data in files.items()
                 if name.startswith("blobs/sha256/")}
        for key, name, _mode in runtime.ARTIFACTS:
            data = blobs[lock[key]["sha256"]]
            self.assertEqual(lock[key], {"path": name, "size": len(data),
                                         "sha256": hashlib.sha256(data).hexdigest(),
                                         "architecture": "aarch64"})
        self.assertEqual(blobs[lock["kernel"]["sha256"]], self.kernel.read_bytes())
        self.assertEqual(blobs[lock["initramfs"]["sha256"]], self.initramfs.read_bytes())
        helper = blobs[lock["vz_runner"]["sha256"]]
        self.assertTrue(helper.startswith(self.tools.helper))
        self.assertTrue(helper.endswith(runtime.ENTITLEMENTS.read_bytes()))
        if cw_runtime is None:
            self.assertNotIn("cw_runtime", target)
            self.assertEqual(len(blobs), 3)
        else:
            for name, key in ((runtime.CW_RUNTIME_LOCK, "lock"), (runtime.CW_RUNTIME_PACK, "pack")):
                data = (cw_runtime / name).read_bytes()
                self.assertEqual(target["cw_runtime"][key], {"sha256": hashlib.sha256(data).hexdigest(),
                                                             "size": len(data)})
                self.assertEqual(blobs[target["cw_runtime"][key]["sha256"]], data)
        return document

    def snapshot(self):
        return {str(path.relative_to(self.release)): path.read_bytes()
                for path in sorted(self.release.rglob("*")) if path.is_file()}

    def test_packs_the_signed_helper_kernel_and_guest_root(self):
        status, stdout, stderr = self.pack()
        self.assertEqual(status, 0, stderr)
        self.assert_release(self.snapshot())
        self.assertEqual(stat.S_IMODE(self.release.stat().st_mode), 0o700)
        package = str(runtime.PACKAGE)
        # The revision is resolved before anything is built.
        self.assertEqual(self.tools.calls[0], ["git", "-C", str(REPOSITORY), "rev-parse", "HEAD"])
        self.assertEqual(self.tools.calls[1], ["swift", "build", "-c", "release", "--package-path", package])
        self.assertEqual(self.tools.calls[2][-1], "--show-bin-path")
        sign = [call for call in self.tools.calls if call[:2] == ["/usr/bin/codesign", "--force"]][0]
        self.assertEqual(sign[:7], ["/usr/bin/codesign", "--force", "--sign", "-",
                                    "--identifier", "codewire-vz-runner", "--entitlements"])
        self.assertEqual(sign[7], str(REPOSITORY / "crates/codewire-local-vmm/macos-vz-runner/developer-entitlements.plist"))
        self.assertIn("packed %s (source %s)" % (self.release, REVISION), stdout)
        self.assertIsNone(self.tools.installed, "--pack must not install")
        # A pack never reuses an existing directory.
        status, _stdout, stderr = self.pack()
        self.assertEqual(status, 1)
        self.assertIn("already exists; pack into a new directory", stderr)

    def live_guest_root(self):
        self.initramfs.write_bytes(guest_root(init=elf() + b"init" + runtime.LIVE_RUNTIME_CAPABILITY_MARKER))

    def test_a_tree_without_git_names_its_revision(self):
        status, _stdout, stderr = self.pack("--source-revision", "d" * 40)
        self.assertEqual(status, 0, stderr)
        document = json.loads((self.release / runtime.LOCAL_RUNTIME_DOCUMENT).read_text())
        self.assertEqual(document["source_revision"], "d" * 40)
        self.assertFalse(any(call[:1] == ["git"] for call in self.tools.calls))
        status, _stdout, stderr = self.main("--pack", str(self.scratch / "other"), "--source-revision", "main")
        self.assertEqual(status, 1)
        self.assertIn("must be a 40-character commit", stderr)
        self.assertFalse((self.scratch / "other").exists())

    def test_installs_through_cw_setup_local(self):
        status, _stdout, stderr = self.main("--replace", "--cw", "/opt/dev/cw")
        self.assertEqual(status, 0, stderr)
        install = [call for call in self.tools.calls if call[1:3] == ["setup", "--local"]]
        self.assertEqual(len(install), 1)
        self.assertEqual(install[0][0], "/opt/dev/cw")
        self.assertEqual(install[0][3], "--from")
        self.assertEqual(install[0][5:], ["--replace"])
        self.assert_release(self.tools.installed)
        self.assertFalse(Path(install[0][4]).exists(), "the packed release is temporary")
        self.tools.cw_status = 1
        status, _stdout, stderr = self.main()
        self.assertEqual(status, 1)
        self.assertIn("command exited 1: cw setup --local --from", stderr)

    def test_packs_a_sealed_arm64_cw_runtime(self):
        self.live_guest_root()
        source = cw_runtime(self.inputs / "runtime")
        status, _stdout, stderr = self.pack("--cw-runtime", str(source))
        self.assertEqual(status, 0, stderr)
        self.assert_release(self.snapshot(), cw_runtime=source)

    def test_invalid_cw_runtime_or_guest_root_fails_before_effects(self):
        self.live_guest_root()
        cases = {
            "x86_64 target": (cw_runtime(self.inputs / "x86", target="x86_64-unknown-linux-musl"), None,
                              "provenance does not bind this image and a aarch64-unknown-linux-musl payload"),
            "x86_64 payload": (cw_runtime(self.inputs / "elf", payload=elf(machine=62) + b"cw"), None,
                               "payload is not a static aarch64 ELF"),
            "corrupted pack": (cw_runtime(self.inputs / "corrupt", corrupt=True), None,
                               "does not match its lock's size and SHA-256"),
            "no live publisher": (cw_runtime(self.inputs / "valid"), guest_root(init=elf() + b"init"),
                                  "has no trusted live cw publisher"),
        }
        (self.inputs / "empty").mkdir()
        cases["missing pack"] = (self.inputs / "empty", None, "cw-runtime.lock.json is missing")
        for label, (source, root, message) in cases.items():
            with self.subTest(label):
                initramfs = None
                if root is not None:
                    initramfs = self.inputs / "old-initramfs.cpio"
                    initramfs.write_bytes(root)
                status, _stdout, stderr = self.pack("--cw-runtime", str(source), initramfs=initramfs)
                self.assertEqual(status, 1)
                self.assertIn(message, stderr)
                self.assertFalse(self.release.exists())
                self.assertEqual(self.tools.calls, [])
        status, _stdout, stderr = self.pack("--cw-runtime", "relative")
        self.assertEqual(status, 1)
        self.assertIn("CW_RUNTIME must be an absolute directory", stderr)
        status, _stdout, stderr = self.main("--pack", "relative")
        self.assertEqual(status, 1)
        self.assertIn("--pack must be an absolute path", stderr)

    def test_missing_e2fsprogs_fails_before_effects(self):
        (self.e2fsprogs / "resize2fs").unlink()
        status, _stdout, stderr = self.main()
        self.assertEqual(status, 1)
        self.assertIn("e2fsprogs is missing", stderr)
        self.assertIn("brew install e2fsprogs", stderr)
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
                status, _stdout, stderr = self.main(**arguments)
                self.assertEqual(status, 1)
                self.assertIn(message, stderr)
        compressed = self.inputs / "Image.gz"
        compressed.write_bytes(b"\x1f\x8b" + bytes(4094))
        status, _stdout, stderr = self.main(kernel=compressed)
        self.assertIn("not an uncompressed arm64 Linux kernel Image", stderr)
        noncanonical = self.inputs / "extra.cpio"
        noncanonical.write_bytes(guest_root() + bytes(512))
        status, _stdout, stderr = self.main(initramfs=noncanonical)
        self.assertEqual(status, 1)
        self.assertIn("not the exact canonical archive", stderr)
        self.assertIn("--verify-root --target aarch64-unknown-linux-musl", stderr)
        self.assertEqual(self.tools.calls, [])

    def test_wrong_host_fails_before_effects(self):
        with mock.patch.object(runtime.platform, "system", return_value="Linux"), \
                mock.patch.object(runtime.platform, "machine", return_value="x86_64"):
            status, _stdout, stderr = self.main()
        self.assertEqual(status, 1)
        self.assertIn("need an Apple Silicon Mac (this host is Linux x86_64)", stderr)
        self.assertEqual(self.tools.calls, [])

    def test_helper_must_carry_exactly_the_developer_entitlements(self):
        self.tools.signed_entitlements = plistlib.dumps(
            {"com.apple.security.virtualization": True, "com.apple.security.get-task-allow": True})
        status, _stdout, stderr = self.pack()
        self.assertEqual(status, 1)
        self.assertIn("does not carry exactly developer-entitlements.plist", stderr)
        self.assertFalse((self.release / runtime.LOCAL_RUNTIME_DOCUMENT).exists())
        self.assertIsNone(self.tools.installed)

    def test_helper_must_be_thin_arm64_macho(self):
        self.tools.helper = b"\xca\xfe\xba\xbe" + bytes(60)
        status, _stdout, stderr = self.pack()
        self.assertEqual(status, 1)
        self.assertIn("not a thin arm64 Mach-O executable", stderr)
        self.assertFalse((self.release / runtime.LOCAL_RUNTIME_DOCUMENT).exists())


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

    def test_release_directory_follows_the_installer(self):
        installer = self.read("crates/codewire-local-vmm/src/runtime_install.rs")
        self.assertIn('LOCAL_RUNTIME_SCHEMA: &str = "%s";' % runtime.LOCAL_RUNTIME_SCHEMA, installer)
        self.assertIn('LOCAL_RUNTIME_DOCUMENT: &str = "%s";' % runtime.LOCAL_RUNTIME_DOCUMENT, installer)
        self.assertIn('format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)', installer)
        self.assertEqual(runtime.TARGET, "macos-aarch64")
        self.assertIn('.join("blobs").join("sha256").join(sha256)', installer)
        self.assertIn('CW_RUNTIME_LOCK: &str = "%s";' % runtime.CW_RUNTIME_LOCK, installer)
        self.assertIn('CW_RUNTIME_PACK: &str = "%s";' % runtime.CW_RUNTIME_PACK, installer)

    def test_admission_and_paths_follow_the_runtime(self):
        artifact = self.read("crates/codewire-local-vmm/src/artifact.rs")
        self.assertIn('ArtifactArchitecture::Aarch64 => bytes.len() >= 0x3c && &bytes[0x38..0x3c] == b"ARM\\x64"', artifact)
        self.assertIn("const INITRAMFS_LIMIT: u64 = 512 * 1024 * 1024;", artifact)
        self.assertIn("Self::Aarch64 => 183,", artifact)
        self.assertRegex(artifact, r"pub vz_runner: ArtifactSpec,\s*pub kernel: ArtifactSpec,\s*pub initramfs: ArtifactSpec,")
        self.assertIn("Some(if executable { 0o500 } else { 0o400 })", artifact)
        installer = self.read("crates/codewire-local-vmm/src/runtime_install.rs")
        self.assertIn("const EXECUTABLE_MODE: u32 = 0o500;", installer)
        self.assertIn("const DATA_MODE: u32 = 0o400;", installer)
        darwin = self.read("crates/codewire-local-vmm/src/darwin/mod.rs")
        directories = re.search(r"E2FSPROGS_DIRECTORIES: \[&str; \d+\] = \[(.*?)\];", darwin, re.DOTALL)
        self.assertEqual(runtime.E2FSPROGS_DIRECTORIES, tuple(re.findall(r'"([^"]+)"', directories.group(1))))
        self.assertIn('Command::new("/usr/bin/codesign")', darwin)
        cw_runtime = self.read("crates/codewire-local-vmm/src/cw_runtime.rs")
        for program in runtime.E2FSPROGS_PROGRAMS:
            self.assertTrue(program in cw_runtime or program in self.read("crates/codewire-local-vmm/src/runner.rs")
                            or program in self.read("crates/codewire-local-vmm/src/workspace.rs"), program)
        self.assertIn('lock.pack.path != Path::new("%s")' % runtime.CW_RUNTIME_PACK, cw_runtime)
        config = self.read("crates/codewire-local-vmm/src/supervisor_config.rs")
        self.assertIn('with_file_name("%s")' % runtime.CW_RUNTIME_LOCK, config)
        probe = self.read("crates/codewire-vmm-guest-probe/src/cw_runtime.rs")
        self.assertIn('CW_RUNTIME_PACK_MAGIC: &[u8; 8] = b"%s";' % runtime.CW_RUNTIME_PACK_MAGIC.decode(), probe)
        self.assertIn('pub const CW_RUNTIME_TARGET: &str = "%s";' % runtime.CW_RUNTIME_TARGET, probe)
        self.assertIn("CW_RUNTIME_MAX_PROVENANCE: usize = 16 * 1024;", probe)
        self.assertIn("CW_RUNTIME_MAX_BYTES: usize = 256 * 1024 * 1024;", probe)
        live = self.read("crates/codewire-vmm-guest-probe/src/cw_runtime_live.rs")
        self.assertIn('LIVE_RUNTIME_CAPABILITY_MARKER: &[u8] = b"%s\\0";'
                      % runtime.LIVE_RUNTIME_CAPABILITY_MARKER[:-1].decode(), live)
        self.assertTrue(runtime.ENTITLEMENTS.is_file())
        self.assertEqual(plistlib.loads(runtime.ENTITLEMENTS.read_bytes()),
                         {"com.apple.security.virtualization": True})


if __name__ == "__main__":
    unittest.main()
