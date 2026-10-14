#!/usr/bin/env python3
"""Synthetic tests for linux-local-runtime.py: nothing is built, downloaded or run."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile

SOURCE = Path(__file__).with_name("linux-local-runtime.py").resolve()
REPOSITORY = SOURCE.parents[2]
SPEC = importlib.util.spec_from_file_location("linux_local_runtime", SOURCE)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
sys.path.insert(0, str(REPOSITORY / "scripts/ci/tests"))
import cw_release_fixtures as fx  # noqa: E402

release = runtime.release
macos = runtime.macos
REVISION = "c" * 40
X86_64 = "x86_64-unknown-linux-musl"
AARCH64 = "aarch64-unknown-linux-musl"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf(machine: int = 62, interpreter: bool = False, needed: bool = False, tag: bytes = b"") -> bytes:
    """A little-endian ELF64 executable: a load segment, and optionally an
    interpreter or a dynamic table naming a shared library."""
    headers = 2 if needed else 1
    body = bytearray(64 + 56 * headers)
    body[:8] = b"\x7fELF\x02\x01\x01\x00"
    struct.pack_into("<HH", body, 16, 3, machine)
    struct.pack_into("<Q", body, 32, 64)
    struct.pack_into("<HH", body, 54, 56, headers)
    struct.pack_into("<I", body, 64, 3 if interpreter else 1)
    if needed:
        dynamic = len(body)
        struct.pack_into("<I", body, 64 + 56, 2)
        struct.pack_into("<Q", body, 64 + 56 + 8, dynamic)
        struct.pack_into("<Q", body, 64 + 56 + 32, 32)
        body += struct.pack("<qQqQ", 1, 1, 0, 0)
    return bytes(body) + b"payload" + tag


def bzimage(release_name: str = runtime.KERNEL_RELEASE) -> bytes:
    image = bytearray(8192)
    image[510:512] = b"\x55\xaa"
    image[0x202:0x206] = b"HdrS"
    image[0x400:0x400 + len(release_name)] = release_name.encode()
    return bytes(image)


def guest_root(machine: int = 62, live: bool = True, **overrides) -> bytes:
    init = elf(machine, tag=b"init" + (macos.LIVE_RUNTIME_CAPABILITY_MARKER if live else b""))
    parts = {"init": init, "busybox": elf(machine, tag=b"busybox"), "runc": elf(machine, tag=b"runc")}
    parts.update(overrides)
    return macos.canonical_guest_root(parts["init"], parts["busybox"], parts["runc"])


def cw_runtime(directory: Path, target: str = X86_64, revision: str = REVISION, payload: bytes = None,
               record_target: str = None) -> Path:
    """A sealed runtime pack and lock in the shape cw-runtime-image.py pack writes."""
    if payload is None:
        payload = fx.executable(record_target or target, revision=revision)
    index = "1" * 64
    provenance = json.dumps({"schema_version": 1, "image_index_sha256": index,
                             "payload": {"target": target, "source_revision": revision, "sha256": sha(payload),
                                         "size": len(payload)}}).encode()
    pack = b"CWRPACK1" + struct.pack("<QQ", len(provenance), len(payload)) + provenance + payload
    lock = {"schema_version": 1, "image_index_sha256": index,
            "pack": {"path": "runtime.pack", "size": len(pack), "sha256": sha(pack)}}
    directory.mkdir()
    (directory / "runtime.pack").write_bytes(pack)
    (directory / "cw-runtime.lock.json").write_text(json.dumps(lock) + "\n")
    return directory


def virtiofsd_zip(members) -> bytes:
    buffer = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        # A duplicated member is one of the refused shapes.
        warnings.simplefilter("ignore", UserWarning)
        for name, data in members:
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFREG | 0o755) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data)
    return buffer.getvalue()


MEMBER = "target/x86_64-unknown-linux-musl/release/virtiofsd"


class Inputs:
    """Synthetic pinned inputs, and pins that name exactly them."""

    def __init__(self, base: Path):
        self.base = base
        self.pins = copy.deepcopy(runtime.sources.load_pins())
        self.directory = base / "inputs"
        self.directory.mkdir()
        self.kernel = self.write("vmlinuz-6.18.48-codewire2", bzimage())
        self.initramfs = self.write("initramfs.cpio", guest_root())
        self.set_cloud_hypervisor(elf(tag=b"cloud-hypervisor"))
        self.set_virtiofsd(elf(tag=b"virtiofsd"))
        self.cw_runtime = cw_runtime(self.directory / "cw-runtime")
        self.components = self.directory / "sources"
        self.components.mkdir()
        entries = [{"name": "busybox", "version": "1.37.0", "license": "GPL-2.0-only", "file": "busybox.tar.bz2"},
                   {"name": "cloud-hypervisor", "version": "53.0", "license": "Apache-2.0 AND BSD-3-Clause",
                    "file": "cloud-hypervisor-v53.0.tar.xz"}]
        for entry in entries:
            (self.components / entry["file"]).write_bytes(("source of %s\n" % entry["name"]).encode())
        (self.components / "components.json").write_text(json.dumps(entries))

    def write(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        if path.exists():
            path.unlink()
        path.write_bytes(data)
        return path

    def set_cloud_hypervisor(self, data: bytes, pin: bool = True) -> None:
        self.cloud_hypervisor = self.write("cloud-hypervisor-static", data)
        if pin:
            self.pins["linux_runtime"]["cloud_hypervisor"].update(sha256=sha(data), size=len(data))

    def set_virtiofsd(self, data: bytes, members=None, pin: bool = True) -> None:
        archive = virtiofsd_zip(members if members is not None else [(MEMBER, data)])
        self.virtiofsd_zip = self.write("virtiofsd-v1.14.0.zip", archive)
        if pin:
            self.pins["linux_runtime"]["virtiofsd"].update(sha256=sha(archive), member_sha256=sha(data),
                                                           member_size=len(data))


class PackTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.path.realpath(tempfile.mkdtemp(prefix="cw-linux-runtime-test-")))
        self.addCleanup(shutil.rmtree, self.base)
        self.inputs = Inputs(self.base)
        self.output = self.base / "linux-x86_64"

    def pack(self, **changes):
        inputs = self.inputs
        arguments = {"kernel": inputs.kernel, "initramfs": inputs.initramfs,
                     "cloud_hypervisor_path": inputs.cloud_hypervisor, "virtiofsd_zip": inputs.virtiofsd_zip,
                     "cw_runtime": inputs.cw_runtime, "output": self.output, "revision": REVISION,
                     "components": [inputs.components], "pins": inputs.pins}
        arguments.update(changes)
        with contextlib.redirect_stdout(io.StringIO()):
            return runtime.pack(**arguments)

    def refused(self, message: str, **changes) -> None:
        with self.assertRaisesRegex(runtime.PackError, message):
            self.pack(**changes)
        self.assertFalse(self.output.exists(), "a refused pack writes nothing")

    def test_packs_the_linux_target(self):
        document = self.pack()
        self.assertEqual(document, (self.output / "local-runtime.json").read_bytes())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        value = release.parse_canonical(document)
        self.assertEqual(value["schema"], "codewire.cw.local-runtime/v1")
        self.assertEqual(value["source_revision"], REVISION)
        self.assertEqual(list(value["targets"]), ["linux-x86_64"])
        target = value["targets"]["linux-x86_64"]
        lock = target["lock"]
        # The Linux ArtifactLock and LinuxLock shape, with the releases
        # admission requires and the names cw installs.
        self.assertEqual(sorted(lock), ["cloud_hypervisor", "initramfs", "kernel", "schema_version", "virtiofsd"])
        self.assertEqual(lock["schema_version"], 1)
        blobs = self.output / "blobs/sha256"
        inputs = self.inputs
        virtiofsd = elf(tag=b"virtiofsd")
        for key, path, data, version in (
            ("cloud_hypervisor", "cloud-hypervisor", inputs.cloud_hypervisor.read_bytes(), "v53.0"),
            ("virtiofsd", "virtiofsd", virtiofsd, "v1.14.0"),
            ("kernel", "kernel", inputs.kernel.read_bytes(), None),
            ("initramfs", "initramfs", inputs.initramfs.read_bytes(), None),
        ):
            expected = {"path": path, "size": len(data), "sha256": sha(data), "architecture": "x86_64"}
            if version:
                expected["version"] = version
            self.assertEqual(lock[key], expected, key)
            self.assertEqual((blobs / sha(data)).read_bytes(), data)
        for key, name in (("lock", "cw-runtime.lock.json"), ("pack", "runtime.pack")):
            data = (inputs.cw_runtime / name).read_bytes()
            self.assertEqual(target["cw_runtime"][key], {"sha256": sha(data), "size": len(data)})
        self.assertEqual([component["name"] for component in target["components"]], ["busybox", "cloud-hypervisor"])
        loaded = release.load_local_runtime_dir(self.output)
        self.assertEqual(loaded[0], document)
        self.assertEqual(len(loaded[1]), 8)
        # A pack never reuses an existing directory.
        with self.assertRaisesRegex(runtime.PackError, "already exists"):
            self.pack()

    def test_versions_follow_artifact_admission(self):
        artifact = (REPOSITORY / "crates/codewire-local-vmm/src/artifact.rs").read_text()
        for key, constant in (("cloud_hypervisor", "CLOUD_HYPERVISOR_RELEASE"), ("virtiofsd", "VIRTIOFSD_RELEASE")):
            version = re.search(r'pub const %s: &str = "([^"]+)";' % constant, artifact).group(1)
            self.assertEqual(self.inputs.pins["linux_runtime"][key]["version"], version)
        # Executables are installed 0500 and data 0400, by these lock keys.
        self.assertIn("Some(if executable { 0o500 } else { 0o400 })", artifact)
        self.assertEqual([key for key, _name in runtime.EXECUTABLES], ["cloud_hypervisor", "virtiofsd"])
        decoder = (REPOSITORY / "crates/codewire-cw-release/src/local_runtime.rs").read_text()
        linux_lock = re.search(r"struct LinuxLock \{(.*?)\}", decoder, re.S).group(1)
        self.assertEqual(re.findall(r"(\w+):", linux_lock),
                         ["schema_version", "cloud_hypervisor", "virtiofsd", "kernel", "initramfs"])

    def test_cloud_hypervisor_must_be_the_pinned_static_build(self):
        pin = self.inputs.pins["linux_runtime"]["cloud_hypervisor"]
        self.inputs.set_cloud_hypervisor(elf(tag=b"another build"), pin=False)
        self.refused("is not the pinned Cloud Hypervisor v53.0")
        for data, message in ((elf(interpreter=True), "dynamic interpreter"),
                              (elf(needed=True), "names a shared library"),
                              (elf(machine=183), "is not a static x86_64-unknown-linux-musl ELF")):
            self.inputs.set_cloud_hypervisor(data)
            with self.subTest(message=message):
                self.refused(message)
        self.assertEqual(sorted(pin), ["origin", "release", "sha256", "size", "url", "version"])

    def test_virtiofsd_is_exactly_the_pinned_member_of_the_pinned_zip(self):
        good = elf(tag=b"virtiofsd")
        # A zip other than the pinned one.
        self.inputs.set_virtiofsd(good, members=[(MEMBER, good), ("README", b"x")], pin=False)
        self.refused("is not the pinned virtiofsd v1.14.0 archive")
        for members, message in (
            ([("virtiofsd", good)], "holds no single target/x86_64-unknown-linux-musl/release/virtiofsd"),
            ([(MEMBER, good), (MEMBER, good)], "holds no single"),
        ):
            with self.subTest(message=message):
                self.inputs.set_virtiofsd(good, members=members)
                self.refused(message)
        # The pinned member's bytes must be the pinned digest.
        self.inputs.set_virtiofsd(good)
        self.inputs.pins["linux_runtime"]["virtiofsd"]["member_sha256"] = "0" * 64
        self.refused("differs from its pin")
        for data, message in ((elf(interpreter=True), "dynamic interpreter"),
                              (elf(needed=True), "names a shared library")):
            with self.subTest(message=message):
                self.inputs.set_virtiofsd(data)
                self.refused(message)
        # A member that is not a regular file.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as bundle:
            info = zipfile.ZipInfo(MEMBER)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(info, good)
        self.inputs.write("virtiofsd-v1.14.0.zip", buffer.getvalue())
        self.inputs.pins["linux_runtime"]["virtiofsd"].update(sha256=sha(buffer.getvalue()), member_sha256=sha(good))
        self.refused("is not the pinned regular file")

    def test_the_kernel_is_the_pinned_x86_64_release(self):
        arm64 = bytearray(4096)
        arm64[0x38:0x3C] = b"ARM\x64"
        for data, message in ((bytes(arm64), "is not an x86 bzImage"),
                              (bzimage("6.18.48-codewire1"), "is not the 6.18.48-codewire2 kernel")):
            with self.subTest(message=message):
                self.refused(message, kernel=self.inputs.write("kernel", data))

    def test_the_guest_root_is_the_canonical_x86_64_root(self):
        cases = (
            (guest_root(machine=183), "it has no x86_64 /init"),
            (guest_root(busybox=elf(interpreter=True)), "lacks static x86_64"),
            (guest_root(runc=elf(needed=True)), "lacks static x86_64"),
            (guest_root(live=False), "no trusted live cw publisher"),
            (guest_root() + b"\0" * 512, "not the exact canonical archive"),
        )
        for data, message in cases:
            with self.subTest(message=message):
                self.refused(message, initramfs=self.inputs.write("root.cpio", data))
        # A root that embeds a cw: the release's cw runtime is its own pack.
        archive = bytearray()
        macos.newc_append(archive, 1, macos.INIT_MODE, macos.CW_RUNTIME_PROVENANCE_ENTRY + b"\0", b"{}")
        macos.newc_append(archive, 0, 0, macos.TRAILER)
        self.refused("it embeds a cw", initramfs=self.inputs.write("root.cpio", bytes(archive)))

    def test_the_cw_runtime_is_a_sealed_x86_64_cw_of_this_revision(self):
        document, _files = fx.local_runtime(REVISION)
        for name, kwargs, message in (
            ("aarch64", {"target": AARCH64}, "provenance does not bind"),
            ("revision", {"revision": "d" * 40}, "provenance does not bind"),
            ("record target", {"record_target": "aarch64-unknown-linux-musl"}, "is not a static x86_64"),
            ("dynamic", {"payload": fx.executable(X86_64, static=False, revision=REVISION)}, "dynamic interpreter"),
            ("no record", {"payload": elf(tag=b"\0" * 64)}, "build record is invalid"),
            ("record revision", {"payload": fx.executable(X86_64, revision="e" * 40)}, "build record names"),
            ("embeds a runtime", {"payload": fx.executable(X86_64, revision=REVISION, embedded=document)},
             "embeds a local runtime document; build it without CODEWIRE_LOCAL_RUNTIME"),
        ):
            with self.subTest(name):
                directory = cw_runtime(self.base / ("cw-" + name.replace(" ", "-")), **kwargs)
                self.refused(message, cw_runtime=directory)
        corrupt = cw_runtime(self.base / "cw-corrupt")
        pack = (corrupt / "runtime.pack").read_bytes()
        (corrupt / "runtime.pack").write_bytes(pack[:-1] + b"X")
        self.refused("does not match its lock", cw_runtime=corrupt)

    def test_components_are_published_as_listed(self):
        (self.inputs.components / "components.json").write_text(json.dumps([{"name": "busybox"}]))
        self.refused("malformed entry")


class CheckCommandTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.path.realpath(tempfile.mkdtemp(prefix="cw-linux-runtime-check-")))
        self.addCleanup(shutil.rmtree, self.base)

    def main(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = runtime.main(list(argv))
        return status, stdout.getvalue(), stderr.getvalue()

    def test_checks_each_release_target(self):
        for target in (X86_64, AARCH64):
            directory = cw_runtime(self.base / target, target=target)
            status, stdout, stderr = self.main("check-cw-runtime", "--dir", str(directory), "--target", target,
                                               "--source-revision", REVISION)
            with self.subTest(target=target):
                self.assertEqual(status, 0, stderr)
                self.assertIn("cw runtime %s pack sha256=" % target, stdout)
        directory = cw_runtime(self.base / "wrong", target=AARCH64)
        status, _stdout, stderr = self.main("check-cw-runtime", "--dir", str(directory), "--target", X86_64,
                                            "--source-revision", REVISION)
        self.assertEqual(status, 1)
        self.assertIn("provenance does not bind", stderr)
        status, _stdout, stderr = self.main("check-cw-runtime", "--dir", str(directory), "--target", AARCH64,
                                            "--source-revision", "main")
        self.assertEqual(status, 1)
        self.assertIn("must be a 40-character commit", stderr)


if __name__ == "__main__":
    result = unittest.main(argv=[sys.argv[0], "-v"], exit=False).result
    print("test-linux-local-runtime: tests=%d failures=%d errors=%d"
          % (result.testsRun, len(result.failures), len(result.errors)))
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)
