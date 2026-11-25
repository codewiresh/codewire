#!/usr/bin/env python3
"""scripts/ci/images/workspace-disk-inputs.py: both hand-offs round-trip with
their modes, give the same bytes for the same files, and refuse a changed tar,
a changed or unlocked artifact, a wrong mode, a link, or a disk with an extra
file. No network or VM is used."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
loader = importlib.machinery.SourceFileLoader("workspace_disk_inputs",
                                              str(ROOT / "scripts/ci/images/workspace-disk-inputs.py"))
spec = importlib.util.spec_from_loader("workspace_disk_inputs", loader)
wdi = importlib.util.module_from_spec(spec)
loader.exec_module(wdi)

FILES = {"cloud_hypervisor": ("cloud-hypervisor", b"ch"), "virtiofsd": ("virtiofsd", b"vfs"),
         "kernel": ("vmlinux", b"kernel"), "initramfs": ("initramfs.cpio", b"root")}


def runtime(root):
    artifacts = root / "artifacts"
    artifacts.mkdir(parents=True)
    lock = {"schema_version": 1}
    for key, (name, data) in FILES.items():
        (artifacts / name).write_bytes(data)
        (artifacts / name).chmod(0o500 if key in wdi.EXECUTABLES else 0o400)
        lock[key] = {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    (root / "artifacts.lock").write_text(json.dumps(lock))
    (root / "artifacts.lock").chmod(0o400)
    artifacts.chmod(0o700)
    root.chmod(0o700)
    return root


class Base(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.work = Path(self.temporary.name)
        self.runtime = runtime(self.work / "runtime")
        self.smoke = self.work / "smoke"
        self.smoke.write_bytes(b"#!/bin/sh\n")
        self.smoke.chmod(0o755)

    def tearDown(self):
        for path in [self.work, *self.work.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o700)
        self.temporary.cleanup()


class Inputs(Base):
    def test_a_round_trip_keeps_every_mode(self):
        digest = wdi.pack_inputs(self.runtime, self.smoke, self.work / "in.tar")
        wdi.unpack_inputs(self.work / "in.tar", digest, self.work / "out")
        out = self.work / "out"
        self.assertEqual(wdi.mode(out / wdi.SMOKE), 0o500)
        self.assertEqual(wdi.mode(out / "runtime" / "artifacts" / "cloud-hypervisor"), 0o500)
        self.assertEqual(wdi.mode(out / "runtime" / "artifacts" / "vmlinux"), 0o400)
        self.assertEqual(wdi.mode(out / "runtime"), 0o700)

    def test_the_same_files_give_the_same_bytes(self):
        self.assertEqual(wdi.pack_inputs(self.runtime, self.smoke, self.work / "a.tar"),
                         wdi.pack_inputs(self.runtime, self.smoke, self.work / "b.tar"))

    def test_another_tar_is_refused(self):
        digest = wdi.pack_inputs(self.runtime, self.smoke, self.work / "in.tar")
        with self.assertRaisesRegex(wdi.Refused, "not the one the job output names"):
            wdi.unpack_inputs(self.work / "in.tar", "0" * 64, self.work / "out")
        with self.assertRaisesRegex(wdi.Refused, "64 lowercase hex"):
            wdi.unpack_inputs(self.work / "in.tar", digest.upper(), self.work / "out2")

    def test_a_runtime_off_its_lock_is_refused(self):
        artifact = self.runtime / "artifacts" / "vmlinux"
        artifact.chmod(0o600)
        artifact.write_bytes(b"changed")
        artifact.chmod(0o400)
        with self.assertRaisesRegex(wdi.Refused, "not the locked bytes"):
            wdi.pack_inputs(self.runtime, self.smoke, self.work / "in.tar")

    def test_a_wrong_mode_is_refused(self):
        (self.runtime / "artifacts" / "virtiofsd").chmod(0o755)
        with self.assertRaisesRegex(wdi.Refused, "not mode 500"):
            wdi.pack_inputs(self.runtime, self.smoke, self.work / "in.tar")

    def test_an_unlocked_file_is_refused(self):
        extra = self.runtime / "artifacts" / "extra"
        self.runtime.joinpath("artifacts").chmod(0o700)
        extra.write_bytes(b"x")
        with self.assertRaisesRegex(wdi.Refused, "does not name"):
            wdi.pack_inputs(self.runtime, self.smoke, self.work / "in.tar")

    def test_a_link_in_the_tar_is_refused(self):
        tar = self.work / "link.tar"
        with tarfile.open(tar, "w") as archive:
            info = tarfile.TarInfo(wdi.SMOKE)
            info.type, info.linkname = tarfile.SYMTYPE, "/bin/sh"
            archive.addfile(info)
        digest = wdi.sha256_file(tar)
        with self.assertRaisesRegex(wdi.Refused, "not a regular file or directory"):
            wdi.unpack_inputs(tar, digest, self.work / "out")

    def test_a_setuid_member_is_refused(self):
        tar = self.work / "setuid.tar"
        with tarfile.open(tar, "w") as archive:
            info = tarfile.TarInfo(wdi.SMOKE)
            info.size, info.mode = 1, 0o4500
            archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(wdi.Refused, "mode beyond 0777"):
            wdi.unpack_inputs(tar, wdi.sha256_file(tar), self.work / "out")

    def test_an_unexpected_member_is_refused(self):
        tar = self.work / "extra.tar"
        with tarfile.open(tar, "w") as archive:
            info = tarfile.TarInfo("runtime/../escape")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(wdi.Refused, "not a member this hand-off carries"):
            wdi.unpack_inputs(tar, wdi.sha256_file(tar), self.work / "out")


class Disk(Base):
    def disk(self, names):
        directory = self.work / "disk"
        directory.mkdir()
        for name in names:
            (directory / name).write_bytes(name.encode())
        return directory

    def test_a_disk_round_trips(self):
        directory = self.disk(["config.json", "image.raw", "record.json"])
        digest = wdi.pack_disk(directory, self.work / "disk.tar")
        wdi.unpack_disk(self.work / "disk.tar", digest, self.work / "out")
        self.assertEqual(sorted(os.listdir(self.work / "out")), ["config.json", "image.raw", "record.json"])
        self.assertEqual((self.work / "out" / "image.raw").read_bytes(), b"image.raw")

    def test_an_extra_file_is_refused(self):
        directory = self.disk(["config.json", "image.raw", "record.json", "extra"])
        with self.assertRaisesRegex(wdi.Refused, "exactly a built disk's files"):
            wdi.pack_disk(directory, self.work / "disk.tar")

    def test_a_disk_file_with_another_mode_is_refused(self):
        tar = self.work / "mode.tar"
        with tarfile.open(tar, "w") as archive:
            for name in ("config.json", "image.raw", "record.json"):
                info = tarfile.TarInfo(name)
                info.size, info.mode = 1, 0o755 if name == "image.raw" else 0o644
                archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(wdi.Refused, "image.raw is not mode 0644"):
            wdi.unpack_disk(tar, wdi.sha256_file(tar), self.work / "out")

    def test_a_short_disk_tar_is_refused(self):
        tar = self.work / "short.tar"
        with tarfile.open(tar, "w") as archive:
            info = tarfile.TarInfo("image.raw")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        with self.assertRaisesRegex(wdi.Refused, "exactly a built disk's files"):
            wdi.unpack_disk(tar, wdi.sha256_file(tar), self.work / "out")


if __name__ == "__main__":
    unittest.main()
