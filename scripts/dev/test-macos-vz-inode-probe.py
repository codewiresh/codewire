#!/usr/bin/env python3
"""Entitlement-free tests for the macOS VZ exact-inode parent harness."""

import importlib.util
import os
from pathlib import Path
import plistlib
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid


spec = importlib.util.spec_from_file_location(
    "macos_vz_inode_probe", Path(__file__).with_name("macos-vz-inode-probe.py")
)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class InodeProbeHarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cw-vz-inode-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_frame_round_trip_is_bounded(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(probe.framed(b"fixture"))
        self.assertEqual(probe.receive_frame(right), b"fixture")
        with self.assertRaisesRegex(ValueError, "outside"):
            probe.framed(b"")
        with self.assertRaisesRegex(ValueError, "outside"):
            probe.framed(b"x" * (probe.MAX_FRAME_BYTES + 1))

    def test_guest_failure_is_finite_canonical_and_never_readiness(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        failure = "guest-readiness-failed-seed-read"
        payload = probe.json.dumps(
            {"result": failure, "schemaVersion": 1},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        left.sendall(probe.framed(payload))
        with self.assertRaisesRegex(RuntimeError, f"helper reported {failure}"):
            probe.expect_response(right, "guest-ready")

        for rejected in (
            {"result": "guest-ready", "schemaVersion": 2},
            {"result": "guest-readiness-failed-unbounded", "schemaVersion": 1},
            {"result": failure, "schemaVersion": 1, "detail": "/private/path"},
        ):
            left.sendall(probe.framed(probe.json.dumps(rejected, sort_keys=True).encode()))
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                probe.expect_response(right, "guest-ready")

    def test_ext4_identity_is_read_from_exact_bytes(self):
        path = self.root / "data"
        path.write_bytes(b"\0" * 4096)
        expected = uuid.UUID("10000000-0000-4000-8000-000000000001")
        descriptor = os.open(path, os.O_RDWR)
        try:
            os.pwrite(descriptor, b"\x53\xef", probe.EXT4_SUPERBLOCK + probe.EXT4_MAGIC_OFFSET)
            os.pwrite(descriptor, expected.bytes, probe.EXT4_SUPERBLOCK + probe.EXT4_UUID_OFFSET)
        finally:
            os.close(descriptor)
        self.assertEqual(probe.ext4_uuid(path), str(expected))
        descriptor = os.open(path, os.O_RDWR)
        try:
            os.pwrite(descriptor, b"\0\0", probe.EXT4_SUPERBLOCK + probe.EXT4_MAGIC_OFFSET)
        finally:
            os.close(descriptor)
        with self.assertRaisesRegex(ValueError, "ext4"):
            probe.ext4_uuid(path)

    def test_path_replacement_preserves_only_open_original_inode(self):
        path = self.root / "kernel"
        path.write_bytes(b"original")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, descriptor)
        probe.replace_with_decoy(path, len(b"original"))
        self.assertEqual(path.read_bytes(), b"\0" * len(b"original"))
        self.assertEqual(os.pread(descriptor, len(b"original"), 0), b"original")
        self.assertEqual(os.fstat(descriptor).st_nlink, 0)

    def test_exact_input_rejects_relative_symlink_and_empty(self):
        target = self.root / "target"
        target.write_bytes(b"x")
        link = self.root / "link"
        link.symlink_to(target)
        self.assertEqual(probe.exact_input(str(target), "fixture"), target)
        for value in ("relative", str(link)):
            with self.assertRaises(ValueError):
                probe.exact_input(value, "fixture")
        empty = self.root / "empty"
        empty.touch()
        with self.assertRaises(ValueError):
            probe.exact_input(str(empty), "fixture")

    def test_expected_identities_are_canonical(self):
        checksum = "a" * 64
        disk_uuid = "a0000000-0000-4000-8000-000000000001"
        self.assertEqual(probe.exact_sha256(checksum, "fixture"), checksum)
        self.assertEqual(probe.exact_uuid(disk_uuid, "fixture"), disk_uuid)
        for value in ("A" * 64, "a" * 63, "g" * 64):
            with self.assertRaises(ValueError):
                probe.exact_sha256(value, "fixture")
        for value in ("bad", "00000000-0000-0000-0000-000000000000", disk_uuid.upper()):
            with self.assertRaises(ValueError):
                probe.exact_uuid(value, "fixture")

    def test_entitlement_must_parse_as_true(self):
        helper = self.root / "helper"
        helper.write_bytes(b"fixture")
        for value, accepted in ((True, True), (False, False), ("true", False)):
            output = b"Executable=fixture\n" + plistlib.dumps(
                {"com.apple.security.virtualization": value}
            )
            with mock.patch.object(
                probe.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0, stdout=output),
            ):
                if accepted:
                    probe.require_entitled_helper(helper)
                else:
                    with self.assertRaisesRegex(RuntimeError, "entitlement"):
                        probe.require_entitled_helper(helper)


if __name__ == "__main__":
    unittest.main()
