#!/usr/bin/env python3
"""Credential-free OCI/context intake tests; synthetic executables never run."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("cw_image_context", ROOT / "scripts/ci/images/prepare-cw-image-context.py")
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)
sys.path.insert(0, str(Path(__file__).parent))
import cw_release_fixtures as fixture  # noqa: E402

LEGACY_READ_WITNESS = False
REFUSALS = (context.Refused, context.release.ReleaseError, OSError, ValueError, tarfile.TarError)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, data, mode=0o400):
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(data)
    path.chmod(mode)


class Intake(unittest.TestCase):
    def setUp(self):
        parent = ROOT / ".tmp"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-context-test-", dir=parent)
        self.base = Path(self.temporary.name)
        self.cw = fixture.executable(context.image.TARGET)
        self.payload = context.release.make_identity(self.cw, context.image.TARGET, fixture.VERSION,
                                                    fixture.REVISION, fixture.TREE, fixture.RUSTC)
        binary = self.base / "synthetic-cw"
        write(binary, self.cw, 0o500)
        descriptor = self.base / "artifact.json"
        write(descriptor, context.release.canonical({k: v for k, v in self.payload.items() if k != "size"}
                                                   | {"path": str(binary)}))
        with contextlib.redirect_stdout(io.StringIO()):
            context.image.build(descriptor, self.base / "asset")
        self.archive = self.base / "asset/cw.oci.tar"
        image_receipt = json.loads((self.base / "asset/image.json").read_bytes())
        self.producer = self.base / "producer.json"
        # Deliberately not successful compiler proof: this helper cannot turn
        # externally supplied JSON into source/build qualification.
        write(self.producer, b'{"fixture":"external evidence only","status":"failed"}\n')
        self.request = {"schema_version": 1, "image": self.pin(self.archive),
                        "index_sha256": image_receipt["index_sha256"], "payload": self.payload,
                        "producer_receipt": self.pin(self.producer)}
        self.request_path, self.output = self.base / "request.json", self.base / "context"
        self.save_request()

    def tearDown(self):
        context.STOP = None
        self.temporary.cleanup()

    def pin(self, path):
        raw = path.read_bytes()
        return {"path": str(path), "sha256": sha(raw), "size": len(raw)}

    def save_request(self, request=None, raw=None):
        write(self.request_path, raw if raw is not None else context.release.canonical(request or self.request))
        self.request_sha = sha(self.request_path.read_bytes())

    def prepare(self):
        return context.prepare(str(self.request_path), self.request_sha, str(self.output))

    def refuses_before_output(self):
        with self.assertRaises(REFUSALS):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.with_name(self.output.name + ".context.json").exists())

    def test_actual_shared_producer_context_and_postbuild_reopen(self):
        with self.prepare() as admitted:
            self.assertEqual(set(os.listdir(self.output)), {"cw", "provenance.json"})
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            self.assertEqual((self.output / "cw").read_bytes(), self.cw)
            self.assertEqual(stat.S_IMODE((self.output / "cw").stat().st_mode), 0o500)
            self.assertEqual(stat.S_IMODE((self.output / "provenance.json").stat().st_mode), 0o400)
            receipt, receipt_pin = admitted.receipt_path, admitted.receipt_sha256
            model = json.loads(receipt.read_bytes())
            self.assertEqual(model["payload"], self.payload)
            self.assertEqual(model["provenance"]["payload"], self.payload)
            self.assertEqual(model["provenance"]["image_index_sha256"], self.request["index_sha256"])
            self.assertIs(model["producer_semantics_verified"], False)
            self.assertEqual(model["claim"], context.CLAIM)
            self.assertEqual(model["inputs"]["producer_receipt"]["sha256"], self.pin(self.producer)["sha256"])
            for _ in range(3):
                admitted.revalidate()  # A fresh anchored enumeration each time.
        before = {p: p.read_bytes() for p in (receipt, self.output / "cw", self.output / "provenance.json")}
        with context.verify(str(receipt), receipt_pin) as reopened:
            reopened.revalidate()
            self.assertEqual(reopened.payload, self.payload)
            self.assertEqual(reopened.receipt_sha256, receipt_pin)
            self.assertIsNotNone(reopened.receipt_file.fd)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_closed_canonical_request_before_effects(self):
        for changes in ({"schema_version": True}, {"schema_version": 1.0}, {"schema_version": 2},
                        {"extra": 1}, {"index_sha256": "A" * 64}, {"image": {"path": "relative"}},
                        {"producer_receipt": self.request["producer_receipt"] | {"size": True}}):
            with self.subTest(changes=changes):
                self.save_request(self.request | changes)
                self.refuses_before_output()
        raw = context.release.canonical(self.request)
        for changed in (b" " + raw, raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                        b"[]\n", raw.rstrip(b"\n"), b"{" * 10000):
            with self.subTest(raw=changed[:30]):
                self.save_request(raw=changed)
                self.refuses_before_output()

    def test_request_and_archive_sha_size_index_pins(self):
        for field, changes in (("image", {"sha256": "0" * 64}), ("image", {"size": self.archive.stat().st_size - 1}),
                               ("producer_receipt", {"sha256": "0" * 64})):
            with self.subTest(field=field, changes=changes):
                self.save_request(self.request | {field: self.request[field] | changes})
                self.refuses_before_output()
        self.save_request(self.request | {"index_sha256": "0" * 64})
        self.refuses_before_output()
        self.save_request()
        with self.assertRaises(REFUSALS):
            context.prepare(str(self.request_path), "0" * 64, str(self.output))
        self.assertFalse(self.output.exists())

    def test_expected_complete_identity_not_only_image_internal_consistency(self):
        for changes in ({"package_version": "v0.4.3"}, {"source_revision": "c" * 40},
                        {"source_tree_sha256": "d" * 64}, {"rustc": "rustc 1.93.0 (other)"},
                        {"target": "aarch64-unknown-linux-gnu"}, {"sha256": "0" * 64},
                        {"size": len(self.cw) + 1}, {"protocol_version": True}, {"record_version": 2}):
            with self.subTest(changes=changes):
                self.save_request(self.request | {"payload": self.payload | changes})
                self.refuses_before_output()

    def test_corrupt_or_incomplete_oci_bytes_refused_with_updated_archive_pin(self):
        original = self.archive.read_bytes()
        damaged = bytearray(original)
        position = original.index(self.cw)
        damaged[position + len(self.cw) - 1] ^= 1
        for raw in (bytes(damaged), b"not an archive", original.rstrip(b"\0")):
            with self.subTest(kind=raw[:12]):
                write(self.archive, raw)
                self.save_request(self.request | {"image": self.pin(self.archive)})
                self.refuses_before_output()

    def test_incoming_full_record_and_static_elf_checks_are_shared(self):
        for raw in (fixture.executable(context.image.TARGET, static=False),
                    fixture.executable(context.image.TARGET, record=fixture.build_record() * 2),
                    fixture.executable(context.image.TARGET, record=b"no build record")):
            with self.subTest(kind=sha(raw)):
                metadata = self.payload | {"sha256": sha(raw), "size": len(raw)}
                layer = context.image.tar_bytes([(name, 0o555, None) for name in context.image.DIRECTORIES]
                                               + [(context.image.CW_PATH, 0o555, raw),
                                                  (context.image.META_PATH, 0o444, context.image.encode(metadata))])
                # Reuse the existing hostile-image package fixture to keep its
                # descriptor/layer closure identical to the owning consumer.
                spec = importlib.util.spec_from_file_location("cw_hostile_image", ROOT / "scripts/dev/test-cw-runtime-image.py")
                hostile = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(hostile)
                package = hostile.Admission()
                package.setUp()
                archive, index_pin = package.package(layer=layer)
                write(self.archive, archive)
                self.save_request(self.request | {"image": self.pin(self.archive), "index_sha256": index_pin,
                                                  "payload": metadata})
                self.refuses_before_output()

    def test_producer_evidence_structural_bounds_without_success_semantics(self):
        for raw in (b"", b"broken", b"{}", b"[]", b'{"same":1,"same":2}',
                    b'{"n":NaN}', b'{"n":[Infinity]}', b" " * (context.MAX_DOCUMENT + 1)):
            with self.subTest(raw=raw[:30]):
                write(self.producer, raw)
                self.save_request(self.request | {"producer_receipt": self.pin(self.producer)})
                self.refuses_before_output()

    def test_linked_symlink_and_writable_producer_receipts(self):
        self.producer.unlink()
        target = self.base / "evidence-target"
        write(target, b'{"fixture":1}')
        self.producer.symlink_to(target)
        self.save_request(self.request | {"producer_receipt": self.pin(self.producer)})
        self.refuses_before_output()
        self.producer.unlink()
        os.link(target, self.producer)
        self.save_request(self.request | {"producer_receipt": self.pin(self.producer)})
        self.refuses_before_output()
        self.producer.unlink()
        target.unlink()
        write(self.producer, b'{"fixture":1}', 0o666)
        self.save_request(self.request | {"producer_receipt": self.pin(self.producer)})
        self.refuses_before_output()

    def test_input_symlink_component_and_fifo_never_follow_or_block(self):
        alias = self.base / "alias"
        alias.symlink_to(self.archive.parent, target_is_directory=True)
        self.save_request(self.request | {"image": self.request["image"] | {"path": str(alias / self.archive.name)}})
        self.refuses_before_output()
        self.producer.unlink()
        os.mkfifo(self.producer, 0o600)
        self.save_request(self.request | {"producer_receipt": self.request["producer_receipt"] | {"size": 1}})
        self.refuses_before_output()

    def test_directory_policy_and_private_output_parent(self):
        own = os.geteuid()
        for uid, mode, allowed in ((own, 0o700, True), (0, 0o755, True), (0, 0o1777, True),
                                   (own + 1, 0o700, False), (own, 0o777, False), (0, 0o777, False),
                                   (0, 0o1775, False)):
            with self.subTest(uid=uid, mode=oct(mode)):
                metadata = mock.Mock(st_mode=stat.S_IFDIR | mode, st_uid=uid)
                if allowed:
                    context.trusted_directory(metadata)
                else:
                    with self.assertRaises(context.Refused):
                        context.trusted_directory(metadata)
        parent = self.base / "writable"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        self.output = parent / "context"
        self.refuses_before_output()

    def test_closed_absolute_bounded_paths(self):
        for value in (None, Path("/valid"), "/", "relative", "/tmp/../cw", "/tmp//cw", "/tmp/./cw",
                      "/tmp/cw\n", "/tmp/\ud800", "/" + "x" * 4096, "/" + "/".join(["a"] * 65)):
            with self.subTest(value=repr(value)):
                with self.assertRaises(context.Refused):
                    context.path_arg(value)
        self.assertEqual(context.path_arg(str(self.output)), self.output)

    def test_existing_output_or_receipt_is_preserved(self):
        receipt = self.output.with_name(self.output.name + ".context.json")
        write(receipt, b"unrelated")
        self.refuses_before_output_existing_receipt(receipt)
        receipt.unlink()
        self.output.mkdir(mode=0o700)
        write(self.output / "unrelated", b"preserve")
        with self.assertRaises(context.Refused):
            self.prepare()
        self.assertEqual((self.output / "unrelated").read_bytes(), b"preserve")
        self.assertFalse(receipt.exists())

    def refuses_before_output_existing_receipt(self, receipt):
        with self.assertRaises(context.Refused):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertEqual(receipt.read_bytes(), b"unrelated")

    def test_retained_and_reopened_context_refuse_modified_files_and_inventory(self):
        with self.prepare() as admitted:
            extra = self.output / "extra"
            write(extra, b"not an admitted context member")
            with self.assertRaises(context.Refused):
                admitted.revalidate()
            extra.unlink()
            write(self.output / "cw", b"changed", 0o500)
            with self.assertRaises(context.Refused):
                admitted.revalidate()
            with self.assertRaises(REFUSALS):
                context.verify(str(admitted.receipt_path), admitted.receipt_sha256)
        self.assertEqual((self.output / "cw").read_bytes(), b"changed")

    def test_retained_original_input_and_receipt_changes_refuse(self):
        with self.prepare() as admitted:
            write(self.producer, b'{"fixture":"changed external evidence"}')
            with self.assertRaises(context.Refused):
                admitted.revalidate()
            with self.assertRaises(REFUSALS):
                context.verify(str(admitted.receipt_path), admitted.receipt_sha256)
        self.assertTrue(self.output.exists())

    def test_receipt_fd_is_retained_and_replacement_refuses(self):
        with self.prepare() as prepared:
            receipt, pin = prepared.receipt_path, prepared.receipt_sha256
        with context.verify(str(receipt), pin) as reopened:
            replacement = self.base / "new-receipt"
            write(replacement, receipt.read_bytes())
            os.replace(replacement, receipt)
            with self.assertRaises(context.Refused):
                reopened.revalidate()
        self.assertTrue(receipt.exists())

    def test_receipt_private_mode_is_required_when_reopened(self):
        with self.prepare() as admitted:
            receipt, pin = admitted.receipt_path, admitted.receipt_sha256
        receipt.chmod(0o600)
        with self.assertRaises(context.Refused):
            context.verify(str(receipt), pin)
        self.assertTrue(self.output.is_dir())

    def test_context_root_replacement_or_mode_change_is_not_deleted(self):
        with self.prepare() as admitted:
            moved = self.base / "original-context"
            self.output.rename(moved)
            self.output.mkdir(mode=0o700)
            with self.assertRaises(context.Refused):
                admitted.revalidate()
            self.assertTrue(moved.is_dir())
            self.assertTrue(self.output.is_dir())
        self.output.rmdir()
        moved.rename(self.output)
        self.output.chmod(0o755)
        with self.assertRaises(REFUSALS):
            context.verify(str(admitted.receipt_path), admitted.receipt_sha256)

    def test_in_place_mutation_during_held_read_is_refused(self):
        original = context.os.read
        changed = False

        def mutate(fd, count):
            nonlocal changed
            block = original(fd, count)
            if not changed and os.fstat(fd).st_ino == self.producer.stat().st_ino:
                changed = True
                write(self.producer, b'{"fixture":"mutated"}')
            return block

        with mock.patch.object(context.os, "read", side_effect=mutate):
            self.refuses_before_output()
        self.assertTrue(changed)

    def test_ancestry_replacement_during_read_has_old_boundary_witness(self):
        original_parent = self.producer.parent
        # Put the only affected input below its own owned directory. Replacing
        # this parent leaves the held leaf inode/metadata completely unchanged.
        source = self.base / "replaceable"
        source.mkdir(mode=0o700)
        leaf = source / "evidence.json"
        write(leaf, self.producer.read_bytes())
        saved = self.base / "preserved-parent"
        old_bytes = leaf.read_bytes()
        expected = self.pin(leaf)
        self.assertEqual(original_parent, self.base)
        swapped = False

        def replace_parent():
            nonlocal swapped
            if not swapped:
                swapped = True
                source.rename(saved)
                source.mkdir(mode=0o700)
                write(source / leaf.name, b'{"foreign":"replacement"}')

        if LEGACY_READ_WITNESS:
            fdopen = context.image.os.fdopen

            class AfterRead:
                def __init__(self, handle):
                    self.handle = handle

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.handle.__exit__(*args)

                def fileno(self):
                    return self.handle.fileno()

                def read(self, count):
                    result = self.handle.read(count)
                    replace_parent()
                    return result

            with mock.patch.object(context.image.os, "fdopen", side_effect=lambda fd, mode: AfterRead(fdopen(fd, mode))):
                with self.assertRaises(REFUSALS):
                    context.image.read_regular(leaf, context.MAX_DOCUMENT, private=True)
        else:
            original = context.os.read

            def replace(fd, count):
                block = original(fd, count)
                replace_parent()
                return block

            with mock.patch.object(context.os, "read", side_effect=replace):
                with self.assertRaises(REFUSALS):
                    context.HeldFile(leaf, context.MAX_DOCUMENT, expected)
        self.assertTrue(swapped)
        self.assertEqual((saved / leaf.name).read_bytes(), old_bytes)
        self.assertEqual(leaf.read_bytes(), b'{"foreign":"replacement"}')

    def test_receipt_contract_bool_equivalence_unknown_or_placement_refuses(self):
        with self.prepare() as admitted:
            original = admitted.receipt_path.read_bytes()
            receipt = admitted.receipt_path
        for change in (lambda value: value["provenance"].update(schema_version=True),
                       lambda value: value["payload"].update(protocol_version=True),
                       lambda value: value.update(extra=1),
                       lambda value: value.update(producer_semantics_verified=True)):
            model = json.loads(original)
            change(model)
            raw = context.release.canonical(model)
            write(receipt, raw)
            with self.assertRaises(REFUSALS):
                context.verify(str(receipt), sha(raw))
        write(receipt, original)
        copied = self.base / "wrong-placement.json"
        write(copied, original)
        with self.assertRaises(REFUSALS):
            context.verify(str(copied), sha(original))

    def test_cancellation_has_no_success_and_preserves_partial_output(self):
        context.STOP = 15
        self.refuses_before_output()
        context.STOP = None
        write_new = context.write_new

        def cancel_after_first(parent, name, raw, mode):
            write_new(parent, name, raw, mode)
            context.STOP = 15

        with mock.patch.object(context, "write_new", side_effect=cancel_after_first):
            with self.assertRaises(context.Refused):
                self.prepare()
        self.assertTrue((self.output / "cw").is_file())
        self.assertFalse(self.output.with_name(self.output.name + ".context.json").exists())
        self.assertEqual((self.output / "cw").read_bytes(), self.cw)

    def test_cli_closed_options_fail_before_any_admission_or_effect(self):
        valid = ["prepare", "--request", str(self.request_path), "--request-sha256", self.request_sha,
                 "--output", str(self.output)]
        for arguments in (valid + ["--output", str(self.output)], valid + ["--origin", "https://invalid.example"],
                          ["prepare", "--req", str(self.request_path)],
                          ["prepare", "--request", "", "--request-sha256", self.request_sha, "--output", str(self.output)]):
            with self.subTest(arguments=arguments):
                with mock.patch.object(context, "prepare") as admission, contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        context.main(arguments)
                    self.assertEqual(error.exception.code, 2)
                    admission.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_cli_status_is_asset_admission_only_and_errors_do_not_render_input(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(context.main(["prepare", "--request", str(self.request_path), "--request-sha256", self.request_sha,
                                           "--output", str(self.output)]), 0)
        value = json.loads(stdout.getvalue())
        self.assertEqual(value["status"], "asset-admitted")
        self.assertIs(value["producer_semantics_verified"], False)
        self.assertEqual(value["cw_sha256"], self.payload["sha256"])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(context.main(["verify", "--receipt", value["receipt"],
                                           "--receipt-sha256", value["receipt_sha256"]]), 0)
        self.assertEqual(json.loads(stdout.getvalue()), value)
        stderr, stdout = io.StringIO(), io.StringIO()
        write(self.request_path, b'{"private_input":"DO_NOT_RENDER_185"}')
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(context.main(["prepare", "--request", str(self.request_path), "--request-sha256", self.request_sha,
                                           "--output", str(self.base / "other")]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("DO_NOT_RENDER_185", stderr.getvalue())
        self.assertNotIn(str(self.base), stderr.getvalue())


if __name__ == "__main__":
    if sys.argv[1:] == ["--old-read-witness"]:
        LEGACY_READ_WITNESS = True
        sys.argv[1:] = ["Intake.test_ancestry_replacement_during_read_has_old_boundary_witness", "-v"]
    unittest.main()
