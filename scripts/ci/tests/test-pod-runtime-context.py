#!/usr/bin/env python3
"""The standard pod-runtime image's context and the workspace disk's line (#5602).

Credential-free: the local runtime and the cw are the release fixtures'
synthetic bytes, never run. Nothing builds an image or boots a VM.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).parent))
import cw_release_fixtures as fixture  # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


context = load("pod_runtime_context_test", ROOT / "scripts/ci/images/pod-runtime-context.py")
release = context.release
DISK = ROOT / "scripts/ci/images/workspace-disk.sh"
FAILURES = (context.ContextError, release.ReleaseError)


class Context(unittest.TestCase):
    def setUp(self):
        self.base = fixture.scratch("pod-runtime-context-")
        self.addCleanup(shutil.rmtree, self.base)
        document, files = fixture.local_runtime(fixture.REVISION)
        fixture.write_local_runtime(self.base / "dist", document, files)
        self.runtime = release.local_runtime_paths(self.base / "dist")[0]
        self.target = json.loads(document)["targets"]["linux-x86_64"]
        self.files = files
        self.cw = self.base / "cw"
        self.cw.write_bytes(fixture.executable("x86_64-unknown-linux-musl", tag=b"host cw"))
        self.output = self.base / "context"

    def test_the_context_holds_the_linux_target_at_the_runtimes_paths_and_modes(self):
        self.assertEqual(context.assemble(self.runtime, self.cw, self.output), fixture.REVISION)
        found = {str(path.relative_to(self.output)): stat.S_IMODE(path.lstat().st_mode)
                 for path in self.output.rglob("*")}
        self.assertEqual(found, {
            "cw": 0o755, "runtime": 0o700, "runtime/artifacts": 0o700,
            "runtime/artifacts/cloud-hypervisor": 0o500, "runtime/artifacts/virtiofsd": 0o500,
            "runtime/artifacts/kernel": 0o400, "runtime/artifacts/initramfs": 0o400,
            "runtime/artifacts.lock": 0o400, "runtime/cw-runtime.lock.json": 0o400,
            "runtime/runtime.pack": 0o400})
        lock = self.target["lock"]
        self.assertEqual((self.output / "runtime/artifacts.lock").read_bytes(), release.canonical(lock))
        for key in ("cloud_hypervisor", "virtiofsd", "kernel", "initramfs"):
            self.assertEqual((self.output / "runtime/artifacts" / lock[key]["path"]).read_bytes(),
                             self.files[lock[key]["sha256"]])
        sealed = self.target["cw_runtime"]
        self.assertEqual((self.output / "runtime/cw-runtime.lock.json").read_bytes(),
                         self.files[sealed["lock"]["sha256"]])
        self.assertEqual((self.output / "runtime/runtime.pack").read_bytes(), self.files[sealed["pack"]["sha256"]])
        self.assertEqual((self.output / "cw").read_bytes(), self.cw.read_bytes())

    def test_without_a_cw_the_context_takes_the_sealed_runtimes_own_cw(self):
        context.assemble(self.runtime, None, self.output)
        sealed = self.target["cw_runtime"]
        _, payload = release.decode_pack(self.files[sealed["pack"]["sha256"]])
        self.assertEqual((self.output / "cw").read_bytes(), payload)
        self.assertEqual(stat.S_IMODE((self.output / "cw").lstat().st_mode), 0o755)

    def test_a_cw_from_another_source_than_the_runtime_is_refused(self):
        self.cw.write_bytes(fixture.executable("x86_64-unknown-linux-musl", revision="d" * 40))
        with self.assertRaisesRegex(context.ContextError, "built from d+, but the runtime from a+"):
            context.assemble(self.runtime, self.cw, self.output)
        self.assertFalse(self.output.exists())

    def test_a_cw_for_another_target_is_refused(self):
        self.cw.write_bytes(fixture.executable("aarch64-unknown-linux-musl"))
        with self.assertRaisesRegex(context.ContextError, "aarch64-unknown-linux-musl cw"):
            context.assemble(self.runtime, self.cw, self.output)

    def test_a_cw_without_a_build_record_is_refused(self):
        self.cw.write_bytes(b"\x7fELF" + bytes(4092))
        with self.assertRaisesRegex(release.ReleaseError, "no cw build record"):
            context.assemble(self.runtime, self.cw, self.output)

    def test_a_blob_that_differs_from_its_digest_is_refused_before_anything_is_written(self):
        digest = self.target["lock"]["kernel"]["sha256"]
        blob = self.runtime / "blobs/sha256" / digest
        blob.write_bytes(b"X" + blob.read_bytes()[1:])
        with self.assertRaisesRegex(release.ReleaseError, "differs from its digest"):
            context.assemble(self.runtime, self.cw, self.output)
        self.assertFalse(self.output.exists())

    def test_a_runtime_without_the_linux_target_is_refused(self):
        document = json.loads((self.runtime / release.LOCAL_RUNTIME_NAME).read_bytes())
        del document["targets"]["linux-x86_64"]
        shutil.rmtree(self.base / "dist")
        kept = set(release.local_runtime_blobs(release.canonical(document)))
        fixture.write_local_runtime(self.base / "dist", release.canonical(document),
                                    {name: data for name, data in self.files.items()
                                     if (name, len(data)) in kept})
        with self.assertRaisesRegex(context.ContextError, "no linux-x86_64 target"):
            context.assemble(self.runtime, self.cw, self.output)

    def test_an_existing_output_is_never_written_into(self):
        self.output.mkdir()
        with self.assertRaisesRegex(context.ContextError, "already exists"):
            context.assemble(self.runtime, self.cw, self.output)
        self.assertEqual(list(self.output.iterdir()), [])


class DiskLine(unittest.TestCase):
    DISK_REF = "registry.example.com/codewire/workspace-disk@sha256:" + "1" * 64
    MANIFEST = "2" * 64

    def setUp(self):
        self.base = fixture.scratch("workspace-disk-line-")
        self.addCleanup(shutil.rmtree, self.base)
        self.dir = self.base / "disk"
        self.dir.mkdir()
        self.record = {"schema_version": 1, "image_disk_id": "3" * 64, "build_id": "4" * 32,
                       "format_version": 1, "architecture": "amd64", "manifest_sha256": self.MANIFEST,
                       "disk_bytes": 4096}
        (self.dir / "record.json").write_text(json.dumps(self.record))
        (self.dir / "config.json").write_text("{}")
        (self.dir / "image.raw").write_bytes(bytes(4096))

    def line(self, image, disk=None):
        return subprocess.run([str(DISK), "line", "--disk", disk or self.DISK_REF, "--image", image,
                               "--dir", str(self.dir)], capture_output=True, text=True, check=False)

    def test_the_line_names_the_disk_its_ids_and_the_image_it_was_built_from(self):
        image = "registry.example.com/codewire/workspace@sha256:" + self.MANIFEST
        result = self.line(image)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.DISK_REF} {'3' * 64} {'4' * 32} {image}\n")

    def test_an_index_reference_pairs_through_the_index_the_disk_holds(self):
        index = b'{"manifests":[]}'
        (self.dir / "index.json").write_bytes(index)
        image = "registry.example.com/codewire/workspace@sha256:" + hashlib.sha256(index).hexdigest()
        result = self.line(image)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.endswith(f" {image}\n"))

    def test_another_image_is_refused(self):
        result = self.line("registry.example.com/codewire/workspace@sha256:" + "5" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("was not built from", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_references_not_pinned_by_digest_are_refused(self):
        for image, disk in (("registry.example.com/codewire/workspace:latest", None),
                            ("registry.example.com/codewire/workspace@sha256:" + self.MANIFEST,
                             "registry.example.com/codewire/workspace-disk:kind")):
            result = self.line(image, disk)
            self.assertNotEqual(result.returncode, 0, (image, disk))
            self.assertIn("must be pinned by digest", result.stderr)

    def test_a_directory_with_other_files_is_refused(self):
        (self.dir / "Dockerfile").write_text("FROM scratch\n")
        result = self.line("registry.example.com/codewire/workspace@sha256:" + self.MANIFEST)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not hold exactly a built disk's files", result.stderr)


if __name__ == "__main__":
    unittest.main()
