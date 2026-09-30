#!/usr/bin/env python3
"""Exercise immutable archive identity and copied executable admission."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
from contextlib import contextmanager, ExitStack, redirect_stderr
import fcntl
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "profile_artifacts", ROOT / "scripts/ci/verify/kind/profile-artifacts.py")
assert SPEC and SPEC.loader
ARTIFACTS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ARTIFACTS
SPEC.loader.exec_module(ARTIFACTS)
CORE = ARTIFACTS.load_core(ROOT)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kind-profile-artifacts-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def archive(self, *, tag="codewire-services:e2e", link=False):
        path = self.root / "images.tar"
        config = b'{"architecture":"amd64","os":"linux"}'
        with tarfile.open(path, "w") as archive:
            member = tarfile.TarInfo("config.json")
            member.size = len(config)
            if link:
                member.type = tarfile.SYMTYPE
                member.linkname = "outside.json"
                member.size = 0
            archive.addfile(member, None if link else io.BytesIO(config))
            manifest = json.dumps([{"Config": "config.json", "RepoTags": [tag],
                                    "Layers": []}]).encode()
            member = tarfile.TarInfo("manifest.json")
            member.size = len(manifest)
            archive.addfile(member, io.BytesIO(manifest))
        return path, {"codewire-services:e2e": "sha256:" + hashlib.sha256(config).hexdigest()}

    def test_archive_resolves_exact_recorded_id(self):
        path, expected = self.archive()
        ARTIFACTS.verify_archive(path, expected)

    def test_mutable_tag_with_different_content_fails(self):
        path, expected = self.archive()
        expected["codewire-services:e2e"] = "sha256:" + "0" * 64
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.verify_archive(path, expected)

    def test_foreign_archive_tag_fails(self):
        path, expected = self.archive(tag="other:e2e")
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.verify_archive(path, expected)

    def test_archive_link_cannot_supply_image_identity(self):
        path, expected = self.archive(link=True)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.verify_archive(path, expected)

    def test_copy_owns_inode_and_survives_build_overwrite(self):
        source, destination = self.root / "mutable", self.root / "sealed"
        source.write_bytes(b"accepted executable")
        source.chmod(0o700)
        ARTIFACTS.copy_file(source, destination, 0o500)
        source.write_bytes(b"another worktree output")
        self.assertEqual(destination.read_bytes(), b"accepted executable")
        self.assertEqual(destination.stat().st_nlink, 1)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o500)

    def test_source_symlink_is_rejected(self):
        source = self.root / "source"
        source.symlink_to(self.root / "target")
        (self.root / "target").write_bytes(b"outside")
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.copy_file(source, self.root / "sealed", 0o400)

    def test_test_selection_is_exact_and_confined(self):
        executable = self.root / "ci/deps/test"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"test")
        log = self.root / "test.jsonl"
        value = {"reason": "compiler-artifact", "profile": {"test": True},
                 "target": {"name": "wire_contract", "kind": ["test"]},
                 "executable": str(executable)}
        log.write_text(json.dumps(value) + "\n")
        self.assertEqual(ARTIFACTS.select_test(log, "wire_contract", ["test"], self.root / "ci"),
                         executable)
        log.write_text((json.dumps(value) + "\n") * 2)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.select_test(log, "wire_contract", ["test"], self.root / "ci")
        value["executable"] = str(self.root / "foreign")
        (self.root / "foreign").write_bytes(b"test")
        log.write_text(json.dumps(value) + "\n")
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.select_test(log, "wire_contract", ["test"], self.root / "ci")

    def test_copy_refuses_a_source_replaced_by_a_symlink_at_open(self):
        source, outside = self.root / "source", self.root / "outside"
        source.write_bytes(b"owned build")
        outside.write_bytes(b"must never be read")
        original_open = os.open

        def replace(name, flags, *args, **kwargs):
            if name == "source":
                source.unlink()
                source.symlink_to(outside)
            return original_open(name, flags, *args, **kwargs)

        with patch.object(ARTIFACTS.os, "open", side_effect=replace):
            with self.assertRaises(ARTIFACTS.SealError):
                ARTIFACTS.copy_file(source, self.root / "sealed", 0o400)
        self.assertFalse((self.root / "sealed").exists())

    def test_copy_rejects_mutation_of_the_open_inode(self):
        source = self.root / "source"
        source.write_bytes(b"accepted bytes")
        original_chunks = ARTIFACTS.chunks

        def mutate(descriptor, size):
            for chunk in original_chunks(descriptor, size):
                yield chunk
                source.write_bytes(b"different data")

        with patch.object(ARTIFACTS, "chunks", side_effect=mutate):
            with self.assertRaises(ARTIFACTS.SealError):
                ARTIFACTS.copy_file(source, self.root / "sealed", 0o400)

    def test_copy_and_inventory_bounds_fail_before_the_next_write(self):
        source = self.root / "source"
        source.write_bytes(b"12345")
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.copy_file(source, self.root / "oversized", 0o400, bound=4)
        self.assertFalse((self.root / "oversized").exists())
        budget = ARTIFACTS.Budget()
        with patch.object(ARTIFACTS, "TOTAL_BOUND", 9):
            ARTIFACTS.copy_file(source, self.root / "first", 0o400, budget)
            with self.assertRaises(ARTIFACTS.SealError):
                ARTIFACTS.copy_file(source, self.root / "second", 0o400, budget)
        self.assertFalse((self.root / "second").exists())
        with patch.object(ARTIFACTS, "FILE_COUNT_BOUND", 1):
            with self.assertRaises(ARTIFACTS.SealError):
                budget.reserve(0)

    def test_cargo_log_symlinks_fifos_and_oversize_fail_without_blocking(self):
        target = self.root / "target"
        target.write_bytes(b"{}\n")
        log = self.root / "log"
        log.symlink_to(target)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.select_test(log, "test", ["test"], self.root)
        log.unlink()
        os.mkfifo(log)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.select_test(log, "test", ["test"], self.root)
        log.unlink()
        log.write_bytes(b"{}\n")
        with patch.object(ARTIFACTS, "LOG_BOUND", 2):
            with self.assertRaises(ARTIFACTS.SealError):
                ARTIFACTS.select_test(log, "test", ["test"], self.root)

    def test_archive_duplicate_and_unsafe_member_names_fail(self):
        for names in (("config.json", "config.json"), ("../escape",)):
            with self.subTest(names=names):
                path = self.root / "bad.tar"
                with tarfile.open(path, "w") as archive:
                    for name in names:
                        member = tarfile.TarInfo(name)
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b"x"))
                with self.assertRaises(ARTIFACTS.SealError):
                    ARTIFACTS.verify_archive(path, {})

    def test_archive_member_and_extended_header_budgets_fail_before_parsing(self):
        path, expected = self.archive()
        with patch.object(ARTIFACTS, "ARCHIVE_MEMBER_BOUND", 1):
            with self.assertRaises(ARTIFACTS.SealError):
                ARTIFACTS.verify_archive(path, expected)
        member = tarfile.TarInfo("PaxHeaders/entry")
        member.type = tarfile.XHDTYPE
        member.size = ARTIFACTS.ARCHIVE_METADATA_BOUND + 1
        path.write_bytes(member.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.verify_archive(path, expected)

    def test_archive_duplicate_json_and_missing_layers_fail(self):
        for manifest in (b'[{"Config":"config.json","Config":"config.json","RepoTags":[],"Layers":[]}]',
                         b'[{"Config":"config.json","RepoTags":["codewire-services:e2e"],"Layers":["missing"]}]'):
            with self.subTest(manifest=manifest):
                path = self.root / "bad.tar"
                config = b"{}"
                with tarfile.open(path, "w") as archive:
                    for name, data in (("config.json", config), ("manifest.json", manifest)):
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                with self.assertRaises(ARTIFACTS.SealError):
                    ARTIFACTS.verify_archive(path, {"codewire-services:e2e": "sha256:" + hashlib.sha256(config).hexdigest()})

    def test_invalid_archive_checksum_is_a_closed_admission_error(self):
        path = self.root / "bad.tar"
        path.write_bytes(b"x" * 512 + b"\0" * 1024)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.verify_archive(path, {})

    def test_atomic_publication_preserves_an_unexpected_empty_directory(self):
        stage, destination = self.root / ".sealing-owned", self.root / "existing"
        stage.mkdir(mode=0o700)
        (stage / "owned").write_bytes(b"publication")
        destination.mkdir(mode=0o700)
        identity = destination.stat().st_ino
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.publish(stage, destination)
        self.assertEqual(destination.stat().st_ino, identity)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertEqual((stage / "owned").read_bytes(), b"publication")

    def test_publication_fsync_failure_preserves_and_names_the_published_directory(self):
        stage, destination = self.root / ".sealing-owned", self.root / "published"
        stage.mkdir(mode=0o700)
        (stage / "owned").write_bytes(b"publication")
        with patch.object(ARTIFACTS.os, "fsync", side_effect=OSError("synthetic durability failure")):
            with self.assertRaisesRegex(ARTIFACTS.SealError, "retained:.*published"):
                ARTIFACTS.publish(stage, destination)
        self.assertFalse(stage.exists())
        self.assertEqual((destination / "owned").read_bytes(), b"publication")


class FakeDocker:
    """Only synthetic daemon/image metadata; never invoke Docker or reserve ports."""

    def __init__(self):
        self.daemon = "synthetic-daemon"
        self.configs = {name: json.dumps({"architecture": "amd64", "os": "linux", "family": name}).encode()
                        for name in CORE.IMAGE_NAMES}
        self.images = {name: "sha256:" + hashlib.sha256(config).hexdigest()
                       for name, config in self.configs.items()}
        self.image_reads = 0

    def identity(self):
        return self.daemon

    def nodes(self, cluster):
        return []

    def image_ids(self):
        self.image_reads += 1
        return self.images.copy()


class TransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kind-seal-transaction-")
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.root = self.scratch / "source"
        self.root.mkdir(mode=0o700)
        for name in ARTIFACTS.SOURCE_INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + "\n").encode())
        self.environ = patch.dict(os.environ, {}, clear=True)
        self.environ.start()
        self.addCleanup(self.environ.stop)
        os.environ["CODEWIRE_KIND_PROFILE_ROOT"] = str(self.scratch / "profiles")
        self.docker = FakeDocker()
        self.profiles = CORE.Profiles(Path(os.environ["CODEWIRE_KIND_PROFILE_ROOT"]), self.docker)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        @contextmanager
        def fake_ports(ports=None, **kwargs):
            yield ports or {name: 40001 + index for index, name in enumerate(CORE.PORT_NAMES)}

        with patch.object(CORE.Profiles, "free_ports", side_effect=fake_ports):
            self.profiles.ensure("alpha")
        operation = self.stack.enter_context(CORE.owned_file(self.profiles.path("alpha") / "operation.lock", writable=True))
        publication = self.stack.enter_context(CORE.owned_file(self.profiles.root / "publication.lock", writable=True))
        fcntl.flock(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(publication, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.environ.update(CLUSTER="alpha", KIND_PROFILE_LOCK_FD=str(operation),
                          KIND_BUILD_PUBLICATION_LOCK_FD=str(publication), CARGO_TARGET_DIR=str(self.root / "target"))
        self.refresh()
        self.cargo_ci = self.root / "target/ci"
        self.cargo_ci.mkdir(parents=True)
        self.run_dir = Path(os.environ["RUN_DIR"])
        self.inventory = SimpleNamespace(
            PRODUCT_IMAGES=tuple(f"codewire-{name}:e2e" for name in CORE.IMAGE_NAMES),
            SMOKE_FILES={"smoke": "fixture-smoke", "example": "examples/fixture-example"},
            TEST_FILES={"fixture-test": ("fixture-build.jsonl", "fixture_test", ["test"])})
        for relative in (*self.inventory.SMOKE_FILES.values(), "deps/fixture-test"):
            path = self.cargo_ci / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic executable\n")
            path.chmod(0o700)
        record = {"reason": "compiler-artifact", "profile": {"test": True},
                  "target": {"name": "fixture_test", "kind": ["test"]},
                  "executable": str(self.cargo_ci / "deps/fixture-test")}
        (self.run_dir / "fixture-build.jsonl").write_text(json.dumps(record) + "\n")
        self.head, self.tree = "1" * 40, "2" * 40
        self.dirty = False
        self.versions = {"rustc": "synthetic-rustc-1", "cargo": "synthetic-cargo-1", "protoc": "synthetic-protoc-1"}
        self.inspect_count = 0
        self.after_save = None
        self.stack.enter_context(patch.object(ARTIFACTS, "load_core", return_value=CORE))
        self.stack.enter_context(patch.object(ARTIFACTS, "load_inventory", return_value=self.inventory))
        self.stack.enter_context(patch.object(CORE, "Docker", return_value=self.docker))
        self.stack.enter_context(patch.object(ARTIFACTS, "run", side_effect=self.command))

    def refresh(self):
        os.environ.update(self.profiles.env("alpha"))

    def command(self, *argv, **kwargs):
        if argv[0] == "git":
            return f"{self.head}\n{self.tree}" if "rev-parse" in argv else (" M synthetic" if self.dirty else "")
        if argv[0] in self.versions:
            return self.versions[argv[0]]
        if argv[:3] == ("docker", "image", "inspect"):
            self.inspect_count += 1
            name = argv[-1].removeprefix("codewire-").removesuffix(":e2e")
            return json.dumps({"id": self.docker.images[name], "os": "linux", "arch": "amd64",
                               "profile": "ci", "promotable": "false", "source": self.head})
        if argv[:3] == ("docker", "image", "save"):
            self.save_archive(Path(argv[4]))
            if self.after_save is not None:
                self.after_save()
            return ""
        self.fail(f"unexpected metadata command: {argv}")

    def save_archive(self, path):
        entries = []
        with tarfile.open(path, "w") as archive:
            for name, config in self.docker.configs.items():
                member = tarfile.TarInfo(f"{name}.json")
                member.size = len(config)
                archive.addfile(member, io.BytesIO(config))
                entries.append({"Config": member.name, "RepoTags": [f"codewire-{name}:e2e"], "Layers": []})
            data = json.dumps(entries).encode()
            member = tarfile.TarInfo("manifest.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))

    def seal(self):
        return ARTIFACTS.seal(self.root, self.cargo_ci, self.run_dir)

    def reuse(self):
        return ARTIFACTS.reuse(self.root, self.cargo_ci, self.run_dir)

    def assert_unpublished(self):
        self.assertEqual(list(Path(os.environ["KIND_PROFILE_ARTIFACT_ROOT"]).iterdir()), [])
        self.assertIsNone(self.profiles.load("alpha")["artifacts"])

    def test_seal_copies_complete_inventory_and_reuses_without_mutable_tags(self):
        destination = self.seal()
        self.refresh()
        manifest = json.loads((destination / "manifest.json").read_bytes())
        self.assertEqual(set(manifest["files"]), ARTIFACTS.required_inventory(self.inventory))
        (self.cargo_ci / "fixture-smoke").write_bytes(b"another checkout overwrote the target")
        self.docker.images = {name: "sha256:" + "f" * 64 for name in CORE.IMAGE_NAMES}
        reads, inspections = self.docker.image_reads, self.inspect_count
        os.environ.pop("KIND_BUILD_PUBLICATION_LOCK_FD")
        self.assertEqual(self.reuse(), destination)
        self.assertEqual((self.docker.image_reads, self.inspect_count), (reads, inspections))
        self.assertEqual((destination / "smokes/fixture-smoke").read_bytes(), b"synthetic executable\n")

    def test_reuse_exit_three_only_for_a_valid_profile_with_no_admission(self):
        def invoke():
            with patch.object(sys, "argv", ["profile-artifacts.py", "reuse", "--root", str(self.root),
                                            "--cargo-ci-dir", str(self.cargo_ci), "--run-dir", str(self.run_dir)]), \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit:
                ARTIFACTS.main()
            return exit.exception.code

        self.assertEqual(invoke(), 3)
        self.dirty = True
        self.assertEqual(invoke(), 1)
        self.dirty = False
        os.environ["KIND_PROFILE_NONCE"] = "0" * 32
        self.assertEqual(invoke(), 1)
        self.assert_unpublished()

    def test_missing_foreign_nonprivate_and_hardlinked_locks_fail_before_writes(self):
        original = os.environ["KIND_BUILD_PUBLICATION_LOCK_FD"]
        os.environ.pop("KIND_BUILD_PUBLICATION_LOCK_FD")
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        self.assert_unpublished()
        foreign = self.scratch / "foreign.lock"
        foreign.write_bytes(b"")
        foreign.chmod(0o600)
        with foreign.open("r+b") as stream:
            os.environ["KIND_BUILD_PUBLICATION_LOCK_FD"] = str(stream.fileno())
            with self.assertRaises(ARTIFACTS.SealError):
                self.seal()
        os.environ["KIND_BUILD_PUBLICATION_LOCK_FD"] = original
        publication = self.profiles.root / "publication.lock"
        publication.chmod(0o644)
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        publication.chmod(0o600)
        os.link(publication, self.scratch / "second-publication-link")
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        self.assert_unpublished()

    def test_redirected_artifact_root_and_changed_daemon_fail_before_writes(self):
        actual = os.environ["KIND_PROFILE_ARTIFACT_ROOT"]
        redirected = self.scratch / "redirected"
        redirected.mkdir(mode=0o700)
        os.environ["KIND_PROFILE_ARTIFACT_ROOT"] = str(redirected)
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        self.assertEqual(list(redirected.iterdir()), [])
        os.environ["KIND_PROFILE_ARTIFACT_ROOT"] = actual
        self.docker.daemon = "other-daemon"
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        self.docker.daemon = "synthetic-daemon"
        self.assert_unpublished()

    def test_projection_and_producer_directory_conflicts_fail_before_writes(self):
        for key, wrong in (("KIND_PROFILE_NONCE", "0" * 32), ("KUBECONFIG", str(self.scratch / "foreign")),
                           ("KIND_ORCHESTRATION_URL", "http://127.0.0.1:1")):
            previous = os.environ[key]
            with self.subTest(key=key):
                os.environ[key] = wrong
                with self.assertRaises(ARTIFACTS.SealError):
                    self.seal()
                os.environ[key] = previous
                self.assert_unpublished()
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.seal(self.root, self.scratch / "foreign-ci", self.run_dir)
        with self.assertRaises(ARTIFACTS.SealError):
            ARTIFACTS.seal(self.root, self.cargo_ci, self.scratch / "foreign-run")
        self.assert_unpublished()

    def test_changed_source_or_toolchain_before_publication_never_admits(self):
        source = self.root / ARTIFACTS.SOURCE_INPUTS[0]
        self.after_save = lambda: source.write_bytes(b"changed producer input\n")
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        self.assert_unpublished()
        source.write_bytes((ARTIFACTS.SOURCE_INPUTS[0] + "\n").encode())
        self.after_save = lambda: self.versions.update(rustc="synthetic-rustc-2")
        with self.assertRaises(ARTIFACTS.SealError):
            self.seal()
        self.assert_unpublished()

    def test_source_change_after_publication_preserves_the_unadmitted_directory(self):
        original = ARTIFACTS.publish

        def changed_after_rename(source, destination):
            original(source, destination)
            (self.root / ARTIFACTS.SOURCE_INPUTS[0]).write_bytes(b"changed after publication")

        with patch.object(ARTIFACTS, "publish", side_effect=changed_after_rename):
            with self.assertRaisesRegex(ARTIFACTS.SealError, "retained"):
                self.seal()
        self.assertIsNone(self.profiles.load("alpha")["artifacts"])
        destinations = list(Path(os.environ["KIND_PROFILE_ARTIFACT_ROOT"]).iterdir())
        self.assertEqual(len(destinations), 1)
        self.assertTrue((destinations[0] / "manifest.json").is_file())

    def test_unknown_admission_after_durable_save_reconciles_without_deleting_or_retagging(self):
        original = CORE.Profiles.record_artifacts

        def lost_ack(profiles, *args):
            original(profiles, *args)
            raise OSError("synthetic acknowledgement failure")

        with patch.object(CORE.Profiles, "record_artifacts", new=lost_ack):
            with self.assertRaisesRegex(ARTIFACTS.SealError, "retained"):
                self.seal()
        admitted = self.profiles.load("alpha")
        destination = self.profiles.manifest_path(admitted).parent
        self.assertTrue((destination / "images.tar").is_file())
        self.refresh()
        reads, inspections = self.docker.image_reads, self.inspect_count
        self.assertEqual(self.seal(), destination)
        self.assertEqual((reads, inspections), (self.docker.image_reads, self.inspect_count))

    def test_unknown_admission_before_save_is_preserved_and_cannot_be_adopted(self):
        with patch.object(CORE.Profiles, "record_artifacts", side_effect=OSError("synthetic admission failure")):
            with self.assertRaisesRegex(ARTIFACTS.SealError, "retained"):
                self.seal()
        self.assertIsNone(self.profiles.load("alpha")["artifacts"])
        destination = next(Path(os.environ["KIND_PROFILE_ARTIFACT_ROOT"]).iterdir())
        original = (destination / "manifest.json").read_bytes()
        inspections = self.inspect_count
        with self.assertRaisesRegex(ARTIFACTS.SealError, "unadmitted"):
            self.reuse()
        with self.assertRaisesRegex(ARTIFACTS.SealError, "unadmitted"):
            self.seal()
        self.assertEqual(self.inspect_count, inspections)
        self.assertEqual((destination / "manifest.json").read_bytes(), original)

    def test_reuse_rejects_changed_head_mode_toolchain_and_relevant_inputs(self):
        self.seal()
        self.refresh()
        inspections = self.inspect_count
        self.head = "3" * 40
        with self.assertRaises(ARTIFACTS.SealError):
            self.reuse()
        self.head = "1" * 40
        os.environ["CODEWIRE_KIND_PRODUCT_IMAGE_MODE"] = "prebuilt-ci"
        with self.assertRaises(ARTIFACTS.SealError):
            self.reuse()
        os.environ.pop("CODEWIRE_KIND_PRODUCT_IMAGE_MODE")
        self.versions["protoc"] = "synthetic-protoc-2"
        with self.assertRaises(ARTIFACTS.SealError):
            self.reuse()
        self.versions["protoc"] = "synthetic-protoc-1"
        (self.root / ARTIFACTS.SOURCE_INPUTS[0]).write_bytes(b"different input at same claimed Git identity")
        with self.assertRaises(ARTIFACTS.SealError):
            self.reuse()
        self.assertEqual(self.inspect_count, inspections)

    def test_reuse_rejects_corrupt_same_size_smoke_bytes(self):
        destination = self.seal()
        self.refresh()
        smoke = destination / "smokes/fixture-smoke"
        original = smoke.read_bytes()
        smoke.chmod(0o700)
        smoke.write_bytes(b"X" * len(original))
        smoke.chmod(0o500)
        with self.assertRaises(ARTIFACTS.SealError):
            self.reuse()

    def test_compiler_flags_are_bound_as_hashes_without_persisting_values(self):
        value = "synthetic-private-looking-flag"
        os.environ["RUSTFLAGS"] = value
        destination = self.seal()
        self.refresh()
        self.assertNotIn(value.encode(), (destination / ARTIFACTS.PROVENANCE).read_bytes())
        os.environ["RUSTFLAGS"] = "another-flag"
        with self.assertRaises(ARTIFACTS.SealError):
            self.reuse()


if __name__ == "__main__":
    unittest.main()
