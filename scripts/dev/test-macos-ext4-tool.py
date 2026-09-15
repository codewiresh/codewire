#!/usr/bin/env python3
"""Pure admission/format-contract tests; never execute mke2fs or create a VM."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import uuid


spec = importlib.util.spec_from_file_location(
    "macos_ext4_tool", Path(__file__).with_name("macos-ext4-tool.py")
)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class FormatterContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cw-formatter-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.bundle = self.root / "bundle"
        self.probe = self.root / "probe"
        self.bundle.mkdir(mode=0o700)
        self.probe.mkdir(mode=0o700)
        self.binary = self.bundle / "mke2fs"
        tool.write_new(self.binary, b"synthetic executable; never run", 0o500)
        self.checksum = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        tool.write_new(self.bundle / "mke2fs.conf", tool.CONFIG, 0o400)

    def test_exact_file_admission_and_retained_replacement_refusal(self):
        with tool.admitted_file(self.binary, self.checksum, 4096, 0o500):
            pass
        with self.assertRaisesRegex(ValueError, "identity changed"):
            with tool.admitted_file(self.binary, self.checksum, 4096, 0o500):
                self.binary.rename(self.bundle / "original")
                tool.write_new(self.binary, b"synthetic executable; never run", 0o500)

    def test_checksum_mode_hardlink_and_symlink_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "checksum"):
            with tool.admitted_file(self.binary, "0" * 64, 4096):
                self.fail("bad hash admitted")
        self.binary.chmod(0o700)
        with self.assertRaises(ValueError):
            with tool.admitted_file(self.binary, self.checksum, 4096, 0o500):
                self.fail("wrong mode admitted")
        self.binary.chmod(0o500)
        alias = self.bundle / "alias"
        os.link(self.binary, alias)
        with self.assertRaises(ValueError):
            with tool.admitted_file(self.binary, self.checksum, 4096, 0o500):
                self.fail("hardlinked binary admitted")
        alias.unlink()
        alias.symlink_to(self.binary)
        with self.assertRaises(OSError):
            with tool.admitted_file(alias, self.checksum, 4096, 0o500):
                self.fail("symlink admitted")

    def test_hashing_is_bounded_even_when_the_file_grows(self):
        original_pread = os.pread
        calls = []
        initial_size = self.binary.stat().st_size

        def growing_read(descriptor, count, offset):
            calls.append((count, offset))
            if len(calls) == 1:
                self.binary.chmod(0o700)
                with self.binary.open("ab") as stream:
                    stream.write(b"unexpected growth")
            return original_pread(descriptor, count, offset)

        with mock.patch.object(tool.os, "pread", side_effect=growing_read), \
                self.assertRaisesRegex(ValueError, "grew"):
            with tool.admitted_file(self.binary, self.checksum, 4096, 0o500):
                self.fail("growing file admitted")
        self.assertEqual(calls, [(initial_size, 0), (1, initial_size)])

    def test_truncated_hash_input_is_rejected(self):
        descriptor = os.open(self.binary, os.O_RDONLY)
        try:
            with self.assertRaisesRegex(ValueError, "truncated"):
                tool.hash_fd(descriptor, self.binary.stat().st_size + 1)
        finally:
            os.close(descriptor)

    def test_probe_copy_uses_exact_bytes_and_never_replaces_an_existing_destination(self):
        destination = self.probe / "copied"
        tool.copy_probe_binary(self.binary, self.checksum, destination)
        self.assertEqual(destination.read_bytes(), self.binary.read_bytes())
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o500)
        self.assertNotEqual(destination.stat().st_ino, self.binary.stat().st_ino)
        with self.assertRaises(FileExistsError):
            tool.copy_probe_binary(self.binary, self.checksum, destination)
        with self.assertRaisesRegex(ValueError, "checksum"):
            tool.copy_probe_binary(self.binary, "0" * 64, self.probe / "bad-hash")
        self.assertFalse((self.probe / "bad-hash").exists())

    def test_probe_copy_rejects_source_replacement_or_truncation(self):
        write = tool.write_new
        for change in ("replace", "truncate"):
            source = self.bundle / change
            write(source, self.binary.read_bytes(), 0o500)

            def changed_source(path, content, mode):
                write(path, content, mode)
                if change == "replace":
                    source.rename(self.bundle / "original-copy-source")
                    write(source, content, mode)
                else:
                    source.chmod(0o700)
                    source.write_bytes(b"short")

            with self.subTest(change=change), \
                    mock.patch.object(tool, "write_new", side_effect=changed_source), \
                    self.assertRaisesRegex(ValueError, "identity changed"):
                tool.copy_probe_binary(source, self.checksum, self.probe / change)

    def test_probe_copy_rechecks_destination_hash_before_commands(self):
        write = tool.write_new

        def changed_destination(path, content, mode):
            write(path, b"different bytes".ljust(len(content), b"!"), mode)

        with mock.patch.object(tool, "write_new", side_effect=changed_destination), \
                self.assertRaisesRegex(ValueError, "checksum"):
            tool.copy_probe_binary(self.binary, self.checksum, self.probe / "changed-copy")

    def test_source_modes_and_binary_hash_are_validated_before_output_effects(self):
        output = self.root / "not-created"
        archive = self.root / "source.tar.gz"
        for source, binary, checksum in (
                (None, None, None), (archive, self.binary, self.checksum),
                (archive, None, self.checksum), (None, self.binary, None),
                (None, self.binary, "bad"), (None, self.binary, "A" * 64)):
            with self.subTest(source=source, binary=binary, checksum=checksum), \
                    self.assertRaises(ValueError):
                tool.run(source, output, binary, checksum)
            self.assertFalse(output.exists())

    def test_probe_only_result_does_not_claim_build_or_source_provenance(self):
        def command(argv, _cwd, _env, log, _cancel, _deadline):
            if argv[0] == "/usr/bin/otool":
                content = "mke2fs:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            elif argv[0] == "/usr/bin/lipo":
                content = "arm64\n"
            else:
                content = "synthetic platform report\n"
            log.write_text(content)
            return 0

        with mock.patch.object(tool.platform, "system", return_value="Darwin"), \
                mock.patch.object(tool.platform, "machine", return_value="arm64"), \
                mock.patch.object(tool.developer_loop, "run_command", side_effect=command), \
                mock.patch.object(tool, "format_empty", return_value={"synthetic": True}):
            result = tool.run(None, self.root / "probe-only", self.binary, self.checksum)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["mode"], "probe-only")
        self.assertEqual(result["scope"], "native-empty-formatter-probe")
        self.assertEqual(result["binary_sha256"], self.checksum)
        self.assertEqual(result["configuration_sha256"], tool.CONFIG_SHA256)
        self.assertTrue({"source_url", "source_sha256", "version", "compiler",
                         "config_h_sha256", "make_config_sha256"}.isdisjoint(result))
        self.assertEqual([item["argv"][0] for item in result["commands"]],
                         ["/usr/bin/sw_vers", "/usr/bin/otool", "/usr/bin/lipo", "/usr/bin/codesign"])
        self.assertTrue((self.root / "probe-only/producer-source.py").exists())

    def test_source_mode_preserves_pinned_build_inputs_and_separate_provenance(self):
        archive = self.root / "archive"
        archive.write_bytes(b"synthetic archive")
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        output = self.root / "build-and-probe"

        def extract(_archive, destination, _normalized):
            source = destination / f"e2fsprogs-{tool.VERSION}"
            (source / "lib/uuid").mkdir(parents=True)
            (source / "NOTICE").write_text("synthetic notice")
            (source / "lib/uuid/COPYING").write_text("synthetic uuid license")

        def command(argv, cwd, env, log, _cancel, _deadline):
            content = "synthetic build report\n"
            if argv == ["/usr/bin/xcrun", "--find", "clang"]:
                content = "/synthetic/clang\n"
            elif argv == ["/usr/bin/xcrun", "--show-sdk-path"]:
                content = "/synthetic/sdk\n"
            elif argv[0].endswith("/configure"):
                self.assertEqual(argv[1:], ["--prefix=" + str(output / "bundle"), *tool.CONFIGURE_ARGS])
                self.assertEqual(env["CC"], "/synthetic/clang")
                self.assertEqual(env["SDKROOT"], "/synthetic/sdk")
                self.assertEqual(env["CFLAGS"], "-O2 -g0")
                self.assertEqual(env["ac_cv_header_magic_h"], "no")
                self.assertEqual(env["ac_cv_lib_magic_magic_file"], "no")
                (cwd / "lib").mkdir()
                (cwd / "lib/config.h").write_text("#define CONFIG_DISABLE_LIBARCHIVE 1\n")
                (cwd / "MCONFIG").write_text("LIBUUID = $(LIB)/libuuid.a\nLIBBLKID = $(LIB)/libblkid.a $(LIBUUID)\n")
            elif argv == ["/usr/bin/make", "-j4", "-C", "misc", "mke2fs"]:
                (cwd / "misc").mkdir()
                (cwd / "misc/mke2fs").write_bytes(self.binary.read_bytes())
            elif argv[0] == "/usr/bin/otool":
                content = "mke2fs:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            elif argv[0] == "/usr/bin/lipo":
                content = "arm64\n"
            log.write_text(content)
            return 0

        with mock.patch.object(tool.platform, "system", return_value="Darwin"), \
                mock.patch.object(tool.platform, "machine", return_value="arm64"), \
                mock.patch.object(tool, "SOURCE_SHA256", archive_hash), \
                mock.patch.object(tool, "extract_source", side_effect=extract), \
                mock.patch.object(tool.developer_loop, "run_command", side_effect=command), \
                mock.patch.object(tool, "format_empty", return_value={"synthetic": True}):
            result = tool.run(archive, output)
        self.assertEqual(result["mode"], "build-and-probe")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["source_sha256"], archive_hash)
        self.assertEqual(result["version"], tool.VERSION)
        self.assertNotIn("input_binary", result)
        self.assertEqual(result["commands"][6]["argv"], ["/usr/bin/make", "-j4", "libs"])
        self.assertEqual((output / "bundle/NOTICE").read_text(), "synthetic notice")
        self.assertEqual((output / "bundle/libuuid-COPYING").read_text(), "synthetic uuid license")

    def test_validation_cannot_bless_a_changed_probe_binary(self):
        output = self.root / "changed-during-validation"

        def command(argv, _cwd, _env, log, _cancel, _deadline):
            if argv[0] == "/usr/bin/otool":
                binary = Path(argv[-1])
                binary.chmod(0o700)
                binary.write_bytes(b"x" * binary.stat().st_size)
                binary.chmod(0o500)
                content = "mke2fs:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            elif argv[0] == "/usr/bin/lipo":
                content = "arm64\n"
            else:
                content = "synthetic report\n"
            log.write_text(content)
            return 0

        with mock.patch.object(tool.platform, "system", return_value="Darwin"), \
                mock.patch.object(tool.platform, "machine", return_value="arm64"), \
                mock.patch.object(tool.developer_loop, "run_command", side_effect=command), \
                mock.patch.object(tool, "format_empty") as format_empty, \
                self.assertRaisesRegex(ValueError, "artifact changed"):
            tool.run(None, output, self.binary, self.checksum)
        format_empty.assert_not_called()
        self.assertEqual(list((output / "probe").iterdir()), [])

    def test_missing_or_changed_config_precedes_disk_and_child_effects(self):
        command = mock.Mock()
        config = self.bundle / "mke2fs.conf"
        config.unlink()
        with self.assertRaises(FileNotFoundError):
            tool.format_empty(self.bundle, self.checksum, self.probe, 256, "CWROOT", command)
        tool.write_new(config, b"changed configuration", 0o400)
        with self.assertRaises(ValueError):
            tool.format_empty(self.bundle, self.checksum, self.probe, 256, "CWROOT", command)
        command.assert_not_called()
        self.assertEqual(list(self.probe.iterdir()), [])

    def test_unlisted_size_role_and_existing_target_are_not_formatted(self):
        command = mock.Mock()
        for size, label in ((255, "CWROOT"), (256, "OTHER"), (1000000, "CWROOT")):
            with self.assertRaises(ValueError):
                tool.format_empty(self.bundle, self.checksum, self.probe, size, label, command)
        retained = self.probe / "cwroot-256.raw"
        retained.write_bytes(b"keep existing user bytes")
        with self.assertRaises(FileExistsError):
            tool.format_empty(self.bundle, self.checksum, self.probe, 256, "CWROOT", command)
        self.assertEqual(retained.read_bytes(), b"keep existing user bytes")
        command.assert_not_called()

    def test_generated_configuration_requires_static_private_libraries(self):
        good = "LIBUUID = $(LIB)/libuuid.a \nLIBBLKID = $(LIB)/libblkid.a  $(LIBUUID)\n"
        config = "#define CONFIG_DISABLE_LIBARCHIVE 1\n/* #undef HAVE_MAGIC_H */"
        tool.validate_build_config(config, good)
        for macro in tool.FORBIDDEN_DEFINES:
            with self.subTest(macro=macro), self.assertRaises(ValueError):
                tool.validate_build_config(config + f"\n#define {macro} 1\n", good)
        for changed in (good.replace("libuuid.a", "libuuid.dylib"),
                        good.replace("$(LIB)/libblkid.a", "-lblkid")):
            with self.assertRaises(ValueError):
                tool.validate_build_config(config, changed)
        with self.assertRaisesRegex(ValueError, "explicitly disabled"):
            tool.validate_build_config("", good)

    def test_macho_dependency_admission_is_closed(self):
        good = "mke2fs:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n"
        tool.validate_dependencies(good)
        for changed in (good.replace("libSystem.B", "libarchive"),
                        good + "\t/opt/homebrew/lib/libuuid.dylib (compatibility version 1.0.0)\n",
                        "mke2fs:\n", good + "unexpected output\n"):
            with self.assertRaises(ValueError):
                tool.validate_dependencies(changed)

    @staticmethod
    def synthetic_filesystem(descriptor, size, filesystem_uuid, label, filesystem_size=None):
        block = bytearray(1024)
        for offset, value in ((0x38, 0xEF53), (0x3A, 1), (0x58, 256), (0xFE, 64)):
            struct.pack_into("<H", block, offset, value)
        for offset, value in ((4, (filesystem_size or size) // 4096), (0x18, 2),
                              *zip((0x5C, 0x60, 0x64), tool.FEATURE_WORDS)):
            struct.pack_into("<I", block, offset, value)
        block[0x68:0x78] = filesystem_uuid.bytes
        block[0x78:0x88] = label.encode().ljust(16, b"\0")
        os.pwrite(descriptor, block, 1024)
        group = bytearray(64)
        struct.pack_into("<I", group, 8, 3)
        os.pwrite(descriptor, group, 4096)
        inode = bytearray(256)
        struct.pack_into("<H", inode, 0, 0o40755)
        os.pwrite(descriptor, inode, 3 * 4096 + 256)

    def test_ext4_reader_checks_size_features_uuid_label_and_root_inode(self):
        path = self.root / "synthetic.raw"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, descriptor)
        size = 256 * 1024 * 1024
        identity = uuid.UUID(int=123)
        os.ftruncate(descriptor, size)
        self.synthetic_filesystem(descriptor, size, identity, "CWROOT")
        self.assertEqual(tool.inspect_ext4(descriptor, size, identity, "CWROOT")["root_uid"], 0)
        for offset in (1024 + 0x38, 1024 + 4, 1024 + 0x5C, 1024 + 0x60,
                       1024 + 0x64, 1024 + 0x68, 1024 + 0x78,
                       3 * 4096 + 256, 3 * 4096 + 258, 3 * 4096 + 376):
            with self.subTest(offset=offset):
                original = os.pread(descriptor, 1, offset)
                os.pwrite(descriptor, bytes([original[0] ^ 1]), offset)
                with self.assertRaises(ValueError):
                    tool.inspect_ext4(descriptor, size, identity, "CWROOT")
                os.pwrite(descriptor, original, offset)

    def test_fixed_tail_rounding_is_exact_and_metadata_cannot_use_the_tail(self):
        descriptor = os.open(self.root / "tail.raw", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, descriptor)
        image_size, filesystem_size = 513 * 1024 * 1024, 512 * 1024 * 1024
        identity = uuid.UUID(int=456)
        os.ftruncate(descriptor, image_size)
        self.synthetic_filesystem(descriptor, image_size, identity, "CWSTATE", filesystem_size)
        observed = tool.inspect_ext4(descriptor, image_size, identity, "CWSTATE")
        self.assertEqual(observed["image_bytes"], image_size)
        self.assertEqual(observed["filesystem_bytes"], filesystem_size)
        self.assertEqual(observed["unused_tail_bytes"], 1024 * 1024)
        os.pwrite(descriptor, struct.pack("<I", filesystem_size // 4096 - 1), 1028)
        with self.assertRaisesRegex(ValueError, "size"):
            tool.inspect_ext4(descriptor, image_size, identity, "CWSTATE")
        os.pwrite(descriptor, struct.pack("<I", filesystem_size // 4096), 1028)
        valid_inode = os.pread(descriptor, 256, 3 * 4096 + 256)
        os.pwrite(descriptor, valid_inode, filesystem_size + 256)
        os.pwrite(descriptor, struct.pack("<I", filesystem_size // 4096), 4096 + 8)
        with self.assertRaisesRegex(ValueError, "outside the filesystem"):
            tool.inspect_ext4(descriptor, image_size, identity, "CWSTATE")

    def test_fixed_argv_environment_and_exact_created_file(self):
        seen = []

        def command(argv, cwd, env, timeout):
            seen.append((argv, cwd, env, timeout))
            path = Path(argv[-1])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            descriptor = os.open(path, os.O_RDWR)
            try:
                self.synthetic_filesystem(descriptor, path.stat().st_size,
                                          uuid.UUID(argv[argv.index("-U") + 1]), "CWROOT")
            finally:
                os.close(descriptor)

        result = tool.format_empty(self.bundle, self.checksum, self.probe, 256, "CWROOT", command)
        self.assertEqual(result["image_bytes"], 256 * 1024 * 1024)
        self.assertEqual(len(seen), 1)
        argv, cwd, env, timeout = seen[0]
        self.assertNotIn("-d", argv)
        self.assertNotIn("-j", argv)
        self.assertNotIn("-J", argv)
        self.assertNotIn("-c", argv)
        self.assertEqual(argv[-2], "lazy_itable_init=0,lazy_journal_init=0,nodiscard,root_owner=0:0,root_perms=0755")
        self.assertEqual(set(env), {"LC_ALL", "PATH", "MKE2FS_CONFIG", "BLKID_FILE", "E2FSPROGS_UNDO_DIR"})
        self.assertEqual(env["MKE2FS_CONFIG"], str(self.bundle / "mke2fs.conf"))
        self.assertEqual(cwd, self.probe)
        self.assertEqual(timeout, 30)

    def test_failed_child_retains_only_the_new_owned_image(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
            tool.format_empty(self.bundle, self.checksum, self.probe, 256, "CWROOT",
                              mock.Mock(side_effect=RuntimeError("synthetic failure")))
        self.assertEqual([item.name for item in self.probe.iterdir()], ["cwroot-256.raw"])

    def test_successful_child_returning_after_phase_deadline_is_not_accepted(self):
        log = self.root / "late.log"
        log.write_text("synthetic child exit zero")
        records = []
        with mock.patch.object(tool.developer_loop, "run_command", return_value=0), \
                mock.patch.object(tool.time, "monotonic", side_effect=[10, 41]), \
                self.assertRaises(TimeoutError):
            tool.run_checked(["synthetic"], self.root, {}, log, threading.Event(), 600, records, 30)
        self.assertEqual(records[0]["exit_code"], 0)

    def test_cancellation_during_cleanup_or_after_final_command_prevents_success(self):
        cancel = threading.Event()
        log = self.root / "cancelled.log"
        log.write_text("synthetic child exit zero")

        def completed_child(*_args):
            cancel.set()
            return 0

        with mock.patch.object(tool.developer_loop, "run_command", side_effect=completed_child), \
                self.assertRaisesRegex(RuntimeError, "cancelled"):
            tool.run_checked(["synthetic"], self.root, {}, log, cancel, float("inf"), [], 30)
        result = {"status": "running"}
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            tool.accept_result(result, cancel, float("inf"))
        self.assertEqual(result["status"], "running")
        cancel.clear()
        with mock.patch.object(tool.time, "monotonic", return_value=100), self.assertRaises(TimeoutError):
            tool.accept_result(result, cancel, 99)
        self.assertEqual(result["status"], "running")

    def test_upstream_directories_and_internal_symlink_use_safe_extractor(self):
        archive = self.root / "source.tar"
        with tarfile.open(archive, "x") as output:
            directory = tarfile.TarInfo(f"e2fsprogs-{tool.VERSION}")
            directory.type = tarfile.DIRTYPE
            output.addfile(directory)
            entry = tarfile.TarInfo(directory.name + "/NOTICE")
            entry.size = 7
            output.addfile(entry, io.BytesIO(b"license"))
            link = tarfile.TarInfo(directory.name + "/alias")
            link.type = tarfile.SYMTYPE
            link.linkname = "NOTICE"
            output.addfile(link)
        destination = self.root / "source"
        destination.mkdir()
        tool.extract_source(archive, destination, self.root / "normalized.tar")
        self.assertEqual((destination / directory.name / "alias").read_bytes(), b"license")

    def test_escaping_archive_root_is_rejected_before_extraction(self):
        archive = self.root / "source.tar"
        with tarfile.open(archive, "x") as output:
            entry = tarfile.TarInfo("../escape")
            entry.size = 1
            output.addfile(entry, io.BytesIO(b"x"))
        destination = self.root / "source"
        destination.mkdir()
        with self.assertRaises(ValueError):
            tool.extract_source(archive, destination, self.root / "normalized.tar")
        self.assertEqual(list(destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
