#!/usr/bin/env python3
"""scripts/dev/fetch-main-build without a registry: its image choices, its cw and runtime extraction, and its writes.

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
import os
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


RUNTIME = "opt/codewire/runtime"
REAL_RELEASE = fmb.cw_release()
ARTIFACT_BYTES = {"cloud-hypervisor": b"vmm", "virtiofsd": b"fs", "kernel": b"kern", "initramfs": b"root"}
KEYS = {"cloud_hypervisor": "cloud-hypervisor", "virtiofsd": "virtiofsd", "kernel": "kernel", "initramfs": "initramfs"}


def artifacts_lock(overrides=None):
    lock = {"schema_version": 1}
    for key, name in KEYS.items():
        data = (overrides or {}).get(name, ARTIFACT_BYTES[name])
        lock[key] = {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return REAL_RELEASE.canonical(lock)


def tree_layer(entries, markers=()):
    """A layer holding directories (value None) and files, plus whiteout MARKERS."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for marker in markers:
            tar.addfile(tarfile.TarInfo(marker), io.BytesIO(b""))
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            else:
                info.size, info.mode = len(data), 0o644
                tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue())


def runtime_entries(lock=None, artifacts=None, extra=None):
    entries = {RUNTIME: None, f"{RUNTIME}/artifacts": None,
               f"{RUNTIME}/artifacts.lock": lock if lock is not None else artifacts_lock(),
               f"{RUNTIME}/cw-runtime.lock.json": b"{}", f"{RUNTIME}/runtime.pack": b"pack"}
    for name, data in (artifacts or ARTIFACT_BYTES).items():
        entries[f"{RUNTIME}/artifacts/{name}"] = data
    entries.update(extra or {})
    return entries


class Release:
    """cw_release with the sealed-pack check recorded instead of run: the
    fixtures hold no real pack. parse_canonical and canonical stay real."""

    def __init__(self):
        self.real = REAL_RELEASE
        self.packs = []

    def __getattr__(self, name):
        return getattr(self.real, name)

    def check_cw_runtime_pack(self, lock, pack, target, revision):
        self.packs.append((lock, pack, target, revision))
        return b"cw"


class RuntimeTree(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.saved = fmb.cw_release
        self.release = Release()
        fmb.cw_release = lambda: self.release

    def tearDown(self):
        fmb.cw_release = self.saved
        self.temporary.cleanup()

    def tree(self, layers):
        self.count = getattr(self, "count", 0) + 1
        files = self.root / f"files-{self.count}"
        files.mkdir()
        return fmb.stacked_tree(layout(self.root / f"layout-{self.count}", layers), RUNTIME, files)

    def test_the_runtime_is_checked_with_its_modes_and_sealed_source(self):
        files = fmb.check_runtime(self.tree([tree_layer(runtime_entries())]), A)
        modes = {name: mode for name, (_, mode) in files.items()}
        self.assertEqual(modes, {"": 0o700, "artifacts": 0o700, "artifacts.lock": 0o400,
                                 "cw-runtime.lock.json": 0o400, "runtime.pack": 0o400,
                                 "artifacts/cloud-hypervisor": 0o500, "artifacts/virtiofsd": 0o500,
                                 "artifacts/kernel": 0o400, "artifacts/initramfs": 0o400})
        self.assertEqual(self.release.packs, [(b"{}", b"pack", fmb.CW_TARGET, A)])

    def test_an_artifact_off_its_lock_is_refused(self):
        changed = dict(ARTIFACT_BYTES, kernel=b"other")
        with self.assertRaisesRegex(fmb.Refused, "kernel does not match"):
            fmb.check_runtime(self.tree([tree_layer(runtime_entries(artifacts=changed))]), A)

    def test_a_file_no_lock_names_is_refused(self):
        entries = runtime_entries(extra={f"{RUNTIME}/artifacts/extra": b"x"})
        with self.assertRaisesRegex(fmb.Refused, "artifacts/extra"):
            fmb.check_runtime(self.tree([tree_layer(entries)]), A)

    def test_a_link_in_the_runtime_is_refused(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            info = tarfile.TarInfo(f"{RUNTIME}/artifacts/kernel")
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/shadow"
            tar.addfile(info)
        with self.assertRaisesRegex(fmb.Refused, "not a regular file or directory"):
            self.tree([gzip.compress(buffer.getvalue())])

    def test_whiteouts_hide_lower_layers_only(self):
        lower = tree_layer(runtime_entries(extra={f"{RUNTIME}/artifacts/old": b"gone"}))
        upper = tree_layer({}, markers=(f"{RUNTIME}/artifacts/.wh.old",))
        files = fmb.check_runtime(self.tree([lower, upper]), A)
        self.assertNotIn("artifacts/old", files)

        # An opaque marker in the runtime directory hides every lower entry;
        # the same layer's own entries survive it.
        replaced = tree_layer(runtime_entries(), markers=(f"{RUNTIME}/.wh..wh..opq",))
        tree = self.tree([lower, replaced])
        self.assertNotIn(f"{RUNTIME}/artifacts/old", tree)
        self.assertIn(f"{RUNTIME}/artifacts/kernel", tree)

        # A whiteout of a parent hides the whole lower runtime.
        removed = tree_layer({}, markers=("opt/.wh.codewire",))
        self.assertEqual(self.tree([lower, removed]), {})


class RuntimeChoice(unittest.TestCase):
    """SHA A, with first-parent ancestors B, C and D."""

    def setUp(self):
        names = ("git", "digest_of", "signed_sources", "fingerprint", "repository")
        self.saved = {name: getattr(fmb, name) for name in names}
        fmb.git = lambda *args: "\n".join([A, B, C, D])
        fmb.repository = lambda name="daemon": f"registry.example.com/codewire/{name}"
        self.tags, self.sources, self.fingerprints = {}, {}, {}
        fmb.digest_of = lambda tag, auth, image=None: self.tags.get(tag)
        fmb.signed_sources = lambda digest, config, image: self.sources.get(digest, set())
        fmb.fingerprint = lambda sha, artifact=fmb.ARTIFACT: self.fingerprints[sha]

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(fmb, name, value)

    def test_the_commit_s_own_signed_image(self):
        self.fingerprints = {A: "f" * 64}
        self.tags = {A: "sha256:" + "1" * 64}
        self.sources = {"sha256:" + "1" * 64: {A}}
        self.assertEqual(fmb.choose_runtime(A, None, None)[:2], (A, "sha256:" + "1" * 64))

    def test_an_fp_tag_counts_only_with_an_equal_recomputed_fingerprint(self):
        self.fingerprints = {A: "f" * 64, C: "f" * 64}
        self.tags = {"fp-" + "f" * 64: "sha256:" + "3" * 64}
        self.sources = {"sha256:" + "3" * 64: {C}}
        built, digest, why = fmb.choose_runtime(A, None, None)
        self.assertEqual((built, digest), (C, "sha256:" + "3" * 64))
        self.assertIn("fingerprint equal", why)

    def test_a_lying_fp_tag_is_refused(self):
        # The tag names SHA's fingerprint, but its signed source's inputs differ.
        self.fingerprints = {A: "f" * 64, C: "e" * 64}
        self.tags = {"fp-" + "f" * 64: "sha256:" + "3" * 64}
        self.sources = {"sha256:" + "3" * 64: {C}}
        with self.assertRaisesRegex(fmb.Refused, "no signed pod-runtime image"):
            fmb.choose_runtime(A, None, None)

    def test_a_source_off_the_first_parent_history_is_refused(self):
        self.fingerprints = {A: "f" * 64, "e" * 40: "f" * 64}
        self.tags = {"fp-" + "f" * 64: "sha256:" + "3" * 64}
        self.sources = {"sha256:" + "3" * 64: {"e" * 40}}
        with self.assertRaisesRegex(fmb.Refused, "no signed pod-runtime image"):
            fmb.choose_runtime(A, None, None)

    def test_an_unsigned_image_is_refused(self):
        self.fingerprints = {A: "f" * 64}
        self.tags = {A: "sha256:" + "1" * 64}
        with self.assertRaisesRegex(fmb.Refused, "no signed pod-runtime image"):
            fmb.choose_runtime(A, None, None)


class Writing(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".tmp" if (ROOT / ".tmp").is_dir() else None)
        self.root = Path(self.temporary.name)
        self.saved = fmb.cw_release
        fmb.cw_release = lambda: Release()

    def tearDown(self):
        fmb.cw_release = self.saved
        self.temporary.cleanup()

    def files(self):
        self.count = getattr(self, "count", 0) + 1
        staged = self.root / f"staged-{self.count}"
        staged.mkdir()
        tree = fmb.stacked_tree(layout(self.root / f"layout-{self.count}", [tree_layer(runtime_entries())]),
                                RUNTIME, staged)
        return fmb.check_runtime(tree, A)

    def test_the_runtime_is_renamed_into_place_with_its_modes_and_record(self):
        directory = self.root / "target/ci/runtime"
        directory.parent.mkdir(parents=True)
        fmb.write_runtime(directory, self.files(), {"built_from": A})
        self.assertFalse((self.root / "target/ci/.runtime.partial").exists())
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "artifacts").stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "artifacts/virtiofsd").stat().st_mode & 0o777, 0o500)
        self.assertEqual((directory / "artifacts/kernel").stat().st_mode & 0o777, 0o400)
        self.assertEqual((directory / "artifacts/kernel").read_bytes(), b"kern")
        self.assertTrue(fmb.runtime_written_here(directory))

        # It replaces its own runtime, but never one changed since it wrote it.
        fmb.write_runtime(directory, self.files(), {"built_from": A})
        os.chmod(directory, 0o700)
        (directory / "branch-file").write_bytes(b"x")
        self.assertFalse(fmb.runtime_written_here(directory))
        with self.assertRaisesRegex(fmb.Refused, "not a runtime this helper wrote"):
            fmb.write_runtime(directory, self.files(), {"built_from": A})
        self.assertTrue((directory / "branch-file").exists())
        self.assertFalse((self.root / "target/ci/.runtime.partial").exists())

    def test_a_cw_built_during_the_download_is_not_overwritten(self):
        path = self.root / "target/ci/cw"
        path.parent.mkdir(parents=True)
        fmb.write_cw(path, b"first main build", {"built_from": A})
        self.assertTrue(fmb.written_here(path))
        path.write_bytes(b"a cargo build that landed meanwhile")
        with self.assertRaisesRegex(fmb.Refused, "changed during the download"):
            fmb.write_cw(path, b"second main build", {"built_from": A})
        self.assertEqual(path.read_bytes(), b"a cargo build that landed meanwhile")
        self.assertFalse(path.with_name(".cw.partial").exists())


if __name__ == "__main__":
    unittest.main()
