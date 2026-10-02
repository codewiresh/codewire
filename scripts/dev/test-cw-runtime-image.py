#!/usr/bin/env python3
"""Hostile OCI admission fixtures; no image execution, credentials or network."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("cw_image", Path(__file__).with_name("cw-runtime-image.py"))
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)


class Admission(unittest.TestCase):
    def setUp(self):
        self.cw = bytearray(136)
        self.cw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HH", self.cw, 16, 2, 62)
        struct.pack_into("<Q", self.cw, 32, 64)
        struct.pack_into("<HH", self.cw, 54, 56, 1)
        struct.pack_into("<I", self.cw, 64, 1)
        self.metadata = {"schema_version": 1, "protocol_version": 1, "target": image.TARGET,
                         "source_revision": "a" * 40, "source_tree_sha256": "b" * 64,
                         "rustc": "rustc 1.93.0 (synthetic fixture)", "sha256": image.sha(self.cw),
                         "size": len(self.cw)}

    def layer(self, metadata=None, cw=None, extra=()):
        return image.tar_bytes([(name, 0o555, None) for name in image.DIRECTORIES]
                               + [(image.CW_PATH, 0o555, bytes(self.cw if cw is None else cw)),
                                  (image.META_PATH, 0o444, image.encode(self.metadata if metadata is None else metadata))]
                               + list(extra))

    def package(self, layer=None, config_edit=None, manifest_edit=None, index_edit=None, extra=()):
        layer = self.layer() if layer is None else layer
        config = {"os": "linux", "architecture": "amd64", "config": {},
                  "rootfs": {"type": "layers", "diff_ids": ["sha256:" + image.sha(layer)]}}
        if config_edit:
            config_edit(config)
        config_raw = image.encode(config)
        manifest = {"schemaVersion": 2, "mediaType": image.MANIFEST,
                    "config": image.descriptor(image.CONFIG, config_raw), "layers": [image.descriptor(image.LAYER, layer)]}
        if manifest_edit:
            manifest_edit(manifest)
        manifest_raw = image.encode(manifest)
        selected = image.descriptor(image.MANIFEST, manifest_raw)
        selected["platform"] = {"os": "linux", "architecture": "amd64"}
        index = {"schemaVersion": 2, "manifests": [selected]}
        if index_edit:
            index_edit(index)
        index_raw = image.encode(index)
        archive = image.tar_bytes([("oci-layout", 0o444, image.encode({"imageLayoutVersion": "1.0.0"})),
                                   ("index.json", 0o444, index_raw)]
                                  + [("blobs/sha256/" + image.sha(data), 0o444, data)
                                     for data in (manifest_raw, config_raw, layer)] + list(extra))
        return archive, image.sha(index_raw)

    def refuses(self, *args):
        with self.assertRaises((ValueError, KeyError, TypeError, tarfile.TarError)):
            image.admit(*args)

    def test_actual_producer_roundtrip_and_external_identity(self):
        with tempfile.TemporaryDirectory() as task:
            task = Path(task)
            binary = task / "cw"
            binary.write_bytes(self.cw)
            binary.chmod(0o500)
            descriptor = task / "artifact.json"
            descriptor.write_bytes(image.encode({key: value for key, value in self.metadata.items() if key != "size"}
                                                | {"path": str(binary)}))
            with contextlib.redirect_stdout(io.StringIO()):
                image.build(descriptor, task / "image")
            receipt = json.loads((task / "image/image.json").read_bytes())
            archive = image.read_regular(task / "image/cw.oci.tar", image.MAX_ARCHIVE, private=True)
            cw, provenance = image.admit(archive, receipt["index_sha256"])
            self.assertEqual(cw, self.cw)
            provenance = image.decode(provenance)
            self.assertEqual(provenance["image_manifest"]["sha256"], receipt["manifest_sha256"])
            self.assertEqual(provenance["payload"], self.metadata)
            self.assertNotIn(str(task), json.dumps(provenance))

    def test_external_index_pin_and_corrupt_blob(self):
        archive, pin = self.package()
        self.refuses(archive, "0" * 64)
        # Change bytes without changing the OCI descriptor, including the tail
        # of a payload that still looks like a valid static ELF.
        position = archive.index(bytes(self.cw))
        corrupted = bytearray(archive)
        corrupted[position + len(self.cw) - 1] = 1
        self.refuses(bytes(corrupted), pin)

    def test_platform_selection_shape_and_integer_schema(self):
        edits = [lambda value: value["manifests"][0]["platform"].update(architecture="arm64"),
                 lambda value: value["manifests"].append(copy.deepcopy(value["manifests"][0])),
                 lambda value: value.update(schemaVersion=2.0),
                 lambda value: value["manifests"].__setitem__(0, list(value["manifests"][0].items()))]
        for edit in edits:
            self.refuses(*self.package(index_edit=edit))

    def test_descriptor_urls_data_sizes_and_media_types(self):
        for changes in ({"urls": ["https://invalid.example/payload"]}, {"data": "ignored"},
                        {"size": -1}, {"size": True}, {"size": image.MAX_ARCHIVE + 1},
                        {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}):
            self.refuses(*self.package(manifest_edit=lambda value: value["layers"][0].update(changes)))
        self.refuses(*self.package(manifest_edit=lambda value: value.update(schemaVersion=2.0)))

    def test_diff_id_covers_the_complete_uncompressed_tar(self):
        self.refuses(*self.package(config_edit=lambda value: value["rootfs"].update(diff_ids=["sha256:" + "0" * 64])))
        changed = self.layer() + bytes(512)
        # The changed complete layer is valid only with its updated diff_id.
        self.assertEqual(image.admit(*self.package(layer=changed))[0], self.cw)
        self.refuses(*self.package(layer=changed, config_edit=lambda value: value["rootfs"].update(
            diff_ids=["sha256:" + image.sha(self.layer())])))

    def test_duplicate_extra_blob_and_payload_names(self):
        for extra in (("index.json", 0o444, b"{}"), ("blobs/sha256/" + "d" * 64, 0o444, b"extra")):
            self.refuses(*self.package(extra=[extra]))
        for name in (image.CW_PATH, "usr/local/bin/other", "usr/local/bin/.wh.cw", "../cw", "/" + image.CW_PATH):
            self.refuses(*self.package(layer=self.layer(extra=[(name, 0o555, b"extra")])))

    def test_duplicate_json_keys(self):
        metadata = image.encode(self.metadata).replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
        layer = image.tar_bytes([(name, 0o555, None) for name in image.DIRECTORIES]
                                + [(image.CW_PATH, 0o555, bytes(self.cw)), (image.META_PATH, 0o444, metadata)])
        self.refuses(*self.package(layer=layer))

    def test_links_extensions_and_special_files_fail_before_resolution(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo(image.CW_PATH)
                member.type = kind
                member.mode = 0o555
                member.linkname = "other"
                archive.addfile(member)
            self.refuses(*self.package(layer=output.getvalue()))

    def test_bad_modes_owners_negative_sizes_and_missing_terminator(self):
        layer = self.layer()
        for field, content in ((100, b"0000755\0"), (108, b"0000001\0"), (124, b"\xff" * 12)):
            changed = bytearray(layer)
            changed[field:field + len(content)] = content
            changed[148:156] = b"        "
            changed[148:156] = f"{sum(changed[:512]):06o}\0 ".encode()
            self.refuses(*self.package(layer=bytes(changed)))
        archive, pin = self.package()
        self.refuses(archive.rstrip(b"\0"), pin)

    def test_dynamic_or_other_architecture_payload_with_valid_image_hashes(self):
        for offset, format_, value in ((18, "<H", 183), (64, "<I", 3)):
            changed = bytearray(self.cw)
            struct.pack_into(format_, changed, offset, value)
            metadata = dict(self.metadata, sha256=image.sha(changed))
            self.refuses(*self.package(layer=self.layer(cw=changed, metadata=metadata)))
        changed = bytearray(self.cw)
        struct.pack_into("<I", changed, 64, 2)
        struct.pack_into("<Q", changed, 72, 120)
        struct.pack_into("<Q", changed, 96, 16)
        struct.pack_into("<q", changed, 120, 1)
        self.refuses(*self.package(layer=self.layer(cw=changed, metadata=dict(self.metadata, sha256=image.sha(changed)))))

    def test_provenance_cannot_substitute_hash_size_protocol_or_source(self):
        for changes in ({"sha256": "0" * 64}, {"size": 137}, {"protocol_version": 2},
                        {"source_revision": "A" * 40}, {"target": "x86_64-unknown-linux-gnu"}, {"path": "/host/cw"}):
            self.refuses(*self.package(layer=self.layer(metadata=dict(self.metadata, **changes))))

    def test_regular_file_guard_refuses_links_fifo_and_sparse_oversize(self):
        with tempfile.TemporaryDirectory() as task:
            task = Path(task)
            selected = task / "selected"
            selected.write_bytes(b"input")
            (task / "symlink").symlink_to(selected)
            os.mkfifo(task / "fifo")
            for path in (task / "symlink", task / "fifo"):
                with self.assertRaises((OSError, ValueError)):
                    image.read_regular(path, 1024)
            os.link(selected, task / "alias")
            with self.assertRaises(ValueError):
                image.read_regular(selected, 1024)
            with (task / "large").open("wb") as output:
                output.truncate(1025)
            with self.assertRaises(ValueError):
                image.read_regular(task / "large", 1024)


if __name__ == "__main__":
    unittest.main()
