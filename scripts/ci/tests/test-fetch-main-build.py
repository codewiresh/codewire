#!/usr/bin/env python3
"""scripts/dev/fetch-main-build without a registry: its image choice and its cw extraction.

The registry, cosign and planner calls are replaced with stand-ins; the
layout is a synthetic OCI image. No network, Docker or build is used.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
loader = importlib.machinery.SourceFileLoader("fetch_main_build", str(ROOT / "scripts/dev/fetch-main-build"))
spec = importlib.util.spec_from_loader("fetch_main_build", loader)
fmb = importlib.util.module_from_spec(spec)
loader.exec_module(fmb)

A, B, C, D = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)


def layer(files, whiteout=False, markers=()):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for marker in (("usr/local/bin/.wh.cw",) if whiteout else ()) + tuple(markers):
            info = tarfile.TarInfo(marker)
            tar.addfile(info, io.BytesIO(b""))
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue())


def layout(root, layers):
    blobs = root / "blobs/sha256"
    blobs.mkdir(parents=True)
    descriptors = []
    for data in layers:
        digest = hashlib.sha256(data).hexdigest()
        (blobs / digest).write_bytes(data)
        descriptors.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": f"sha256:{digest}", "size": len(data)})
    manifest = json.dumps({"schemaVersion": 2, "layers": descriptors}).encode()
    digest = hashlib.sha256(manifest).hexdigest()
    (blobs / digest).write_bytes(manifest)
    (root / "index.json").write_text(json.dumps({"manifests": [{"digest": f"sha256:{digest}"}]}))
    return root


class Extraction(unittest.TestCase):
    def test_the_last_layer_wins_and_a_whiteout_removes_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = layout(root / "one", [layer({fmb.CW_PATH: b"old"}), layer({fmb.CW_PATH: b"new"})])
            self.assertEqual(fmb.extract_cw(image), b"new")
            gone = layout(root / "two", [layer({fmb.CW_PATH: b"old"}), layer({}, whiteout=True)])
            with self.assertRaisesRegex(fmb.Refused, "holds no"):
                fmb.extract_cw(gone)

    def test_a_parent_or_opaque_whiteout_hides_lower_copies_but_not_its_own(self):
        markers = ["usr/local/bin/.wh..wh..opq", "usr/local/.wh.bin", "usr/.wh.local", ".wh.usr",
                   "usr/local/.wh..wh..opq"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number, marker in enumerate(markers):
                hidden = layout(root / f"hidden-{number}",
                                [layer({fmb.CW_PATH: b"old"}), layer({}, markers=[marker])])
                with self.assertRaisesRegex(fmb.Refused, "holds no", msg=marker):
                    fmb.extract_cw(hidden)
                kept = layout(root / f"kept-{number}",
                              [layer({fmb.CW_PATH: b"old"}), layer({fmb.CW_PATH: b"new"}, markers=[marker])])
                self.assertEqual(fmb.extract_cw(kept), b"new", marker)

    def test_a_cw_that_is_not_a_regular_file_is_refused(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            info = tarfile.TarInfo(fmb.CW_PATH)
            info.type = tarfile.SYMTYPE
            info.linkname = "/bin/sh"
            tar.addfile(info)
        with tempfile.TemporaryDirectory() as temporary:
            image = layout(Path(temporary), [gzip.compress(buffer.getvalue())])
            with self.assertRaisesRegex(fmb.Refused, "not a regular file"):
                fmb.extract_cw(image)


class Choice(unittest.TestCase):
    """SHA A, then its first-parent ancestors B, C and D."""

    def setUp(self):
        self.saved = {name: getattr(fmb, name) for name in ("git", "digest_of", "signed", "fingerprint")}
        fmb.git = lambda *args: "\n".join([A, B, C, D])
        self.images, self.signatures, self.fingerprints = {}, set(), {}
        fmb.digest_of = lambda sha, auth: self.images.get(sha)
        fmb.signed = lambda sha, digest, config: sha in self.signatures
        fmb.fingerprint = lambda sha: self.fingerprints[sha]

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(fmb, name, value)

    def choose(self):
        return fmb.choose(A, None, None)

    def test_the_commit_s_own_signed_image(self):
        self.images[A], self.signatures = "sha256:" + "1" * 64, {A}
        self.assertEqual(self.choose()[:2], (A, "sha256:" + "1" * 64))

    def test_an_ancestor_with_the_same_inputs(self):
        self.images[C] = "sha256:" + "3" * 64
        self.signatures = {C}
        self.fingerprints = {A: "f" * 64, C: "f" * 64}
        built, digest, why = self.choose()
        self.assertEqual((built, digest), (C, "sha256:" + "3" * 64))
        self.assertIn("equal at both commits", why)

    def test_an_unsigned_image_is_skipped(self):
        self.images = {A: "sha256:" + "1" * 64, B: "sha256:" + "2" * 64}
        self.signatures = {B}
        self.fingerprints = {A: "f" * 64, B: "f" * 64}
        self.assertEqual(self.choose()[0], B)

    def test_the_newest_signed_ancestor_with_other_inputs_refuses(self):
        self.images = {B: "sha256:" + "2" * 64, C: "sha256:" + "3" * 64}
        self.signatures = {B, C}
        self.fingerprints = {A: "f" * 64, B: "e" * 64, C: "f" * 64}
        with self.assertRaisesRegex(fmb.Refused, "inputs differ"):
            self.choose()

    def test_no_signed_image_refuses(self):
        with self.assertRaisesRegex(fmb.Refused, "no signed daemon image"):
            self.choose()


class Output(unittest.TestCase):
    def test_the_registry_comes_from_the_environment(self):
        saved = fmb.os.environ.get("CODEWIRE_IMAGE_REGISTRY")
        try:
            fmb.os.environ["CODEWIRE_IMAGE_REGISTRY"] = "registry.example.com"
            self.assertEqual(fmb.repository(), "registry.example.com/codewire/daemon")
            for value in ("", "https://registry.example.com", "registry.example.com/codewire"):
                fmb.os.environ["CODEWIRE_IMAGE_REGISTRY"] = value
                with self.assertRaisesRegex(fmb.Refused, "CODEWIRE_IMAGE_REGISTRY"):
                    fmb.repository()
        finally:
            if saved is None:
                fmb.os.environ.pop("CODEWIRE_IMAGE_REGISTRY", None)
            else:
                fmb.os.environ["CODEWIRE_IMAGE_REGISTRY"] = saved

    def test_a_noexec_output_is_refused_before_any_download(self):
        calls = []
        saved = fmb.auth_file
        fmb.auth_file = lambda: calls.append("auth") or Path("/nonexistent")
        try:
            noexec = Path("/dev/shm") if Path("/dev/shm").is_dir() else None
            if noexec is None or not fmb.os.statvfs(noexec).f_flag & fmb.os.ST_NOEXEC:
                self.skipTest("no noexec filesystem to test against")
            with tempfile.TemporaryDirectory(dir=noexec) as temporary:
                with self.assertRaisesRegex(fmb.Refused, "noexec"):
                    fmb.fetch_cw(A, Path(temporary) / "target/ci/cw")
        finally:
            fmb.auth_file = saved
        self.assertEqual(calls, [])

    def test_a_cw_it_did_not_write_is_never_replaced(self):
        calls = []
        saved = fmb.auth_file
        fmb.auth_file = lambda: calls.append("auth") or Path("/nonexistent")
        try:
            with tempfile.TemporaryDirectory(dir=ROOT / ".tmp" if (ROOT / ".tmp").is_dir() else None) as temporary:
                if fmb.os.statvfs(temporary).f_flag & fmb.os.ST_NOEXEC:
                    self.skipTest("no exec-capable scratch directory")
                path = Path(temporary) / "target/ci/cw"
                path.parent.mkdir(parents=True)
                path.write_bytes(b"a branch build")
                with self.assertRaisesRegex(fmb.Refused, "not a main build"):
                    fmb.fetch_cw(A, path)
                # A record whose hash no longer matches is a later build's file.
                fmb.provenance(path).write_text(json.dumps({"sha256": "0" * 64}))
                with self.assertRaisesRegex(fmb.Refused, "not a main build"):
                    fmb.fetch_cw(A, path)
                self.assertEqual(path.read_bytes(), b"a branch build")
                fmb.provenance(path).write_text(
                    json.dumps({"sha256": hashlib.sha256(b"a branch build").hexdigest()}))
                self.assertTrue(fmb.written_here(path))
        finally:
            fmb.auth_file = saved
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
