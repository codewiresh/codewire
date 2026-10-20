#!/usr/bin/env python3
"""Focused rejection tests for exact Kind build-artifact handoff."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "kind_build_artifacts", ROOT / "scripts/ci/verify/kind-build-artifacts.py"
)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)
REAL_IDENTITY = artifact.identity
WORKSPACE_SPEC = importlib.util.spec_from_file_location(
    "workspace_image_artifact_for_handoff",
    ROOT / "scripts/ci/verify/workspace-image-artifact.py",
)
workspace_artifact = importlib.util.module_from_spec(WORKSPACE_SPEC)
WORKSPACE_SPEC.loader.exec_module(workspace_artifact)


def write_oci_archive(path: Path) -> tuple[str, str]:
    config = json.dumps({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []},
    }, sort_keys=True).encode()

    def descriptor(raw: bytes, media_type: str):
        return {
            "mediaType": media_type,
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }

    config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": config_descriptor,
        "layers": [],
    }, sort_keys=True).encode()
    manifest_descriptor = descriptor(
        manifest, "application/vnd.oci.image.manifest.v1+json",
    )
    entries = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps({
            "schemaVersion": 2, "manifests": [manifest_descriptor],
        }).encode(),
        "blobs/sha256/" + manifest_descriptor["digest"][7:]: manifest,
        "blobs/sha256/" + config_descriptor["digest"][7:]: config,
    }
    with tarfile.open(path, "w") as archive:
        for name, contents in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(contents)
            archive.addfile(member, io.BytesIO(contents))
    path.chmod(0o400)
    return config_descriptor["digest"], manifest_descriptor["digest"]


def receipt_bytes(oci_name: str, contents: bytes, source_digest: str) -> bytes:
    return (json.dumps({"workspace_oci": {
        "file": oci_name,
        "sha256": hashlib.sha256(contents).hexdigest(),
        "size": len(contents),
        "source_digest": source_digest,
    }}, sort_keys=True) + "\n").encode()


class KindBuildArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.directory = self.base / "artifact"
        self.context = {
            "repository": "codewire/codewire",
            "run_id": "42",
            "run_attempt": "1",
            "head": "a" * 40,
            "tree": "b" * 40,
            "platform": "linux/amd64",
            "profile": "ci",
        }
        self.identity = mock.patch.object(artifact, "identity", side_effect=self._identity)
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def _identity(self, group: str):
        return {
            **self.context,
            "profile": "workspace-verify" if group == "workspace" else "ci",
        }

    def write_artifact(self, group: str, members: dict[str, bytes], modes=None, **extra):
        self.directory.mkdir(mode=0o700)
        files = {}
        default_mode = 0o755 if group == "smokes" else 0o600
        for name, content in members.items():
            path = self.directory / name
            path.write_bytes(content)
            files[name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
                "mode": (modes or {}).get(name, default_mode),
            }
        value = {
            "schema": artifact.SCHEMA,
            "group": group,
            "identity": self._identity(group),
            "nonce": "c" * 32,
            "files": files,
            **extra,
        }
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (self.directory / artifact.MANIFEST).write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        os.environ["EXPECTED_MANIFEST_SHA256"] = self.digest
        self.addCleanup(os.environ.pop, "EXPECTED_MANIFEST_SHA256", None)
        return value

    def rewrite_manifest(self, value) -> None:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (self.directory / artifact.MANIFEST).write_bytes(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        os.environ["EXPECTED_MANIFEST_SHA256"] = self.digest

    def smoke_members(self) -> dict[str, bytes]:
        return {
            name: f"executable:{name}\n".encode()
            for name in set(artifact.SMOKE_FILES) | set(artifact.TEST_FILES)
        }

    def configure_smoke_destination(self) -> tuple[Path, Path]:
        target = self.base / "target"
        run_directory = self.base / "run"
        os.environ.update(CARGO_TARGET_DIR=str(target), RUN_DIR=str(run_directory))
        self.addCleanup(os.environ.pop, "CARGO_TARGET_DIR", None)
        self.addCleanup(os.environ.pop, "RUN_DIR", None)
        return target, run_directory

    def test_normalizes_missing_first_attempt_only(self):
        self.assertEqual(artifact.normalized_attempt({}), "1")
        self.assertEqual(artifact.normalized_attempt({"GITHUB_RUN_ATTEMPT": "3"}), "3")
        for value in ("0", "-1", "abc", "01"):
            with self.subTest(value=value), self.assertRaises(artifact.ArtifactError):
                artifact.normalized_attempt({"GITHUB_RUN_ATTEMPT": value})

    def test_identity_rejects_dirty_source_and_binds_build_inputs(self):
        environment = {
            "GITHUB_REPOSITORY": "codewire/codewire", "GITHUB_RUN_ID": "42",
            "GITHUB_SHA": "a" * 40,
        }
        with mock.patch.object(artifact, "run", return_value="?? unexpected"):
            with self.assertRaisesRegex(artifact.ArtifactError, "not clean"):
                REAL_IDENTITY("smokes", environment)
        with mock.patch.object(
            artifact, "run", side_effect=("", "a" * 40 + "\n" + "b" * 40)
        ):
            value = REAL_IDENTITY("smokes", environment)
        self.assertEqual(value["head"], "a" * 40)
        self.assertEqual(value["tree"], "b" * 40)
        self.assertRegex(value["build_entrypoint_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(value["rust_toolchain_sha256"], r"^[0-9a-f]{64}$")

    def test_smoke_consume_validates_then_installs_and_rewrites_jsonl(self):
        members = self.smoke_members()
        self.write_artifact("smokes", members)
        target, run_directory = self.configure_smoke_destination()

        artifact.consume("smokes", self.directory)

        for name, relative in artifact.SMOKE_FILES.items():
            installed = target / "ci" / relative
            self.assertEqual(installed.read_bytes(), members[name])
            self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
        for name, (jsonl_name, cargo_target, target_kind) in artifact.TEST_FILES.items():
            installed = target / "ci/deps" / name
            value = json.loads((run_directory / jsonl_name).read_text())
            self.assertEqual(value, {
                "reason": "compiler-artifact", "profile": {"test": True},
                "target": {"name": cargo_target, "kind": target_kind},
                "executable": str(installed),
            })
            self.assertEqual(installed.read_bytes(), members[name])

    def test_changed_member_rejected_before_any_smoke_install(self):
        members = self.smoke_members()
        self.write_artifact("smokes", members)
        target, _ = self.configure_smoke_destination()
        (self.directory / next(iter(members))).write_bytes(b"changed")
        with self.assertRaises(artifact.ArtifactError):
            artifact.consume("smokes", self.directory)
        self.assertFalse(target.exists())

    def test_closed_set_rejects_missing_extra_and_symlink_members(self):
        for case in ("missing", "extra", "symlink"):
            with self.subTest(case=case):
                if self.directory.exists():
                    for child in self.directory.iterdir():
                        child.unlink()
                    self.directory.rmdir()
                members = self.smoke_members()
                self.write_artifact("smokes", members)
                self.configure_smoke_destination()
                selected = next(iter(members))
                if case == "missing":
                    (self.directory / selected).unlink()
                elif case == "extra":
                    (self.directory / "extra").write_bytes(b"extra")
                else:
                    (self.directory / selected).unlink()
                    (self.directory / selected).symlink_to(self.directory / artifact.MANIFEST)
                with self.assertRaises(artifact.ArtifactError):
                    artifact.consume("smokes", self.directory)

    def test_manifest_digest_identity_nonce_and_mode_are_exact(self):
        mutations = (
            lambda value: value["identity"].update(tree="d" * 40),
            lambda value: value.update(nonce="not-a-nonce"),
            lambda value: next(iter(value["files"].values())).update(mode=0o600),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                if self.directory.exists():
                    for child in self.directory.iterdir():
                        child.unlink()
                    self.directory.rmdir()
                value = self.write_artifact("smokes", self.smoke_members())
                self.configure_smoke_destination()
                mutation(value)
                self.rewrite_manifest(value)
                with self.assertRaises(artifact.ArtifactError):
                    artifact.consume("smokes", self.directory)
        os.environ["EXPECTED_MANIFEST_SHA256"] = "0" * 64
        with self.assertRaises(artifact.ArtifactError):
            artifact.consume("smokes", self.directory)

    def test_product_bytes_are_validated_before_docker_load(self):
        images = {name: {"id": "sha256:" + str(index) * 64}
                  for index, name in enumerate(artifact.GROUP_IMAGES["product"], 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)
        (self.directory / artifact.IMAGE_ARCHIVE).write_bytes(b"corrupt")
        with mock.patch.object(artifact, "run") as command:
            with self.assertRaises(artifact.ArtifactError):
                artifact.consume("product", self.directory)
        command.assert_not_called()

    def test_product_import_rechecks_all_recorded_image_identities(self):
        images = {name: {"id": "sha256:" + str(index) * 64}
                  for index, name in enumerate(artifact.GROUP_IMAGES["product"], 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)

        def inspect(reference):
            return [{
                "Id": images[reference]["id"], "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": {
                    "dev.codewire.build.profile": "runtime",
                    "dev.codewire.promotable": "false",
                    "org.opencontainers.image.revision": "a" * 40,
                }},
            }]

        with mock.patch.object(artifact, "run") as command, \
                mock.patch.object(artifact, "inspect_image", side_effect=lambda ref: inspect(ref)[0]):
            artifact.consume("product", self.directory)
        command.assert_called_once_with(
            artifact.docker(), "load", "--input", str(self.directory / artifact.IMAGE_ARCHIVE),
            capture=False,
        )

    def test_product_import_rejects_changed_revision(self):
        images = {name: {"id": "sha256:" + str(index) * 64}
                  for index, name in enumerate(artifact.GROUP_IMAGES["product"], 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)

        def inspect(reference):
            return {
                "Id": images[reference]["id"], "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": {
                    "dev.codewire.build.profile": "runtime",
                    "dev.codewire.promotable": "false",
                    "org.opencontainers.image.revision": "d" * 40,
                }},
            }

        with mock.patch.object(artifact, "run"), \
                mock.patch.object(artifact, "inspect_image", side_effect=inspect), \
                self.assertRaises(artifact.ArtifactError):
            artifact.consume("product", self.directory)

    def test_product_import_rejects_another_profile_or_a_promotable_image(self):
        # Kind runs the runtime profile Dev and Production run; an image from
        # the retired ci profile, the release profile or a promotable build
        # is not this run's Kind artifact.
        images = {name: {"id": "sha256:" + str(index) * 64}
                  for index, name in enumerate(artifact.GROUP_IMAGES["product"], 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)
        for profile, promotable in (("ci", "false"), ("release", "false"), ("runtime", "true")):
            def inspect(reference):
                return {
                    "Id": images[reference]["id"], "Os": "linux", "Architecture": "amd64",
                    "Config": {"Labels": {
                        "dev.codewire.build.profile": profile,
                        "dev.codewire.promotable": promotable,
                        "org.opencontainers.image.revision": "a" * 40,
                    }},
                }

            with self.subTest(profile=profile, promotable=promotable), \
                    mock.patch.object(artifact, "run"), \
                    mock.patch.object(artifact, "inspect_image", side_effect=inspect), \
                    self.assertRaises(artifact.ArtifactError):
                artifact.consume("product", self.directory)

    def test_daemon_group_carries_only_the_daemon_image(self):
        self.assertEqual(artifact.GROUP_IMAGES["daemon"], ("codewire-daemon:e2e",))
        self.assertNotIn("codewire-daemon:e2e", artifact.GROUP_IMAGES["product"])
        # The local profile seal still archives all four product images.
        self.assertEqual(set(artifact.PRODUCT_IMAGES),
                         set(artifact.GROUP_IMAGES["product"]) | set(artifact.GROUP_IMAGES["daemon"]))
        images = {"codewire-daemon:e2e": {"id": "sha256:" + "4" * 64}}
        self.write_artifact("daemon", {artifact.IMAGE_ARCHIVE: b"daemon archive"}, images=images)

        def inspect(reference):
            return {
                "Id": images[reference]["id"], "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": {
                    "dev.codewire.build.profile": "runtime",
                    "dev.codewire.promotable": "false",
                    "org.opencontainers.image.revision": "a" * 40,
                }},
            }

        with mock.patch.object(artifact, "run") as command, \
                mock.patch.object(artifact, "inspect_image", side_effect=inspect):
            artifact.consume("daemon", self.directory)
        command.assert_called_once_with(
            artifact.docker(), "load", "--input", str(self.directory / artifact.IMAGE_ARCHIVE),
            capture=False,
        )

    def test_daemon_group_rejects_the_service_image_set(self):
        images = {name: {"id": "sha256:" + str(index) * 64}
                  for index, name in enumerate(artifact.GROUP_IMAGES["product"], 1)}
        self.write_artifact("daemon", {artifact.IMAGE_ARCHIVE: b"archive"}, images=images)
        with mock.patch.object(artifact, "run"), \
                mock.patch.object(artifact, "inspect_image"), \
                self.assertRaisesRegex(artifact.ArtifactError, "daemon image set differs"):
            artifact.consume("daemon", self.directory)

    def test_workspace_receipt_validation_follows_archive_hash_and_load(self):
        source_archive = self.base / "source.oci.tar"
        image_id, _source_digest = write_oci_archive(source_archive)
        archive_sha = hashlib.sha256(source_archive.read_bytes()).hexdigest()
        oci_name = f"workspace-image-{archive_sha}.oci.tar"
        self.write_artifact("workspace", {
            artifact.WORKSPACE_RECEIPT: receipt_bytes(
                oci_name, source_archive.read_bytes(), _source_digest,
            ),
            artifact.IMAGE_ARCHIVE: b"archive\n",
            oci_name: source_archive.read_bytes(),
        }, modes={oci_name: 0o400})
        calls = []

        def command(*args, **kwargs):
            calls.append((args, kwargs))
            return ""

        def validate_staged(receipt):
            calls.append(("reuse", receipt))
            staged_archive = receipt.parent / oci_name
            workspace_artifact.archive_identity(staged_archive, image_id, "amd64")
            return "alias"

        with mock.patch.object(artifact, "run", side_effect=command), \
                mock.patch.object(artifact, "workspace_reuse", side_effect=validate_staged), \
                mock.patch.object(artifact, "publish_workspace", side_effect=lambda *args: calls.append(("publish", args))):
            artifact.consume("workspace", self.directory)
        self.assertEqual(calls[0][0][:2], (artifact.docker(), "load"))
        self.assertEqual(calls[1][0], "reuse")
        self.assertEqual(calls[2][0], "publish")

    def test_workspace_tampered_oci_is_rejected_before_docker_load(self):
        original = b"oci archive\n"
        oci_name = "workspace-image-" + hashlib.sha256(original).hexdigest() + ".oci.tar"
        self.write_artifact("workspace", {
            artifact.WORKSPACE_RECEIPT: receipt_bytes(
                oci_name, original, "sha256:" + "1" * 64,
            ),
            artifact.IMAGE_ARCHIVE: b"docker archive\n",
            oci_name: original,
        }, modes={oci_name: 0o400})
        (self.directory / oci_name).write_bytes(b"changed")
        with mock.patch.object(artifact, "run") as command, \
                self.assertRaises(artifact.ArtifactError):
            artifact.consume("workspace", self.directory)
        command.assert_not_called()

    def test_workspace_receipt_mismatch_or_missing_oci_rejects_before_load(self):
        original = b"sealed OCI fixture"
        oci_name = "workspace-image-" + hashlib.sha256(original).hexdigest() + ".oci.tar"
        for case in ("file", "sha256", "size", "missing", "renamed"):
            with self.subTest(case=case):
                self.directory = self.base / f"artifact-{case}"
                receipt = json.loads(receipt_bytes(oci_name, original, "sha256:" + "1" * 64))
                if case == "file":
                    receipt["workspace_oci"]["file"] = "workspace-image-" + "f" * 64 + ".oci.tar"
                elif case == "sha256":
                    receipt["workspace_oci"]["sha256"] = "f" * 64
                elif case == "size":
                    receipt["workspace_oci"]["size"] += 1
                self.write_artifact("workspace", {
                    artifact.WORKSPACE_RECEIPT: json.dumps(receipt).encode(),
                    artifact.IMAGE_ARCHIVE: b"Docker archive fixture",
                    oci_name: original,
                }, modes={oci_name: 0o400})
                if case == "missing":
                    (self.directory / oci_name).unlink()
                elif case == "renamed":
                    (self.directory / oci_name).rename(self.directory / "wrong.oci.tar")
                with mock.patch.object(artifact, "run") as command, \
                        self.assertRaises(artifact.ArtifactError):
                    artifact.consume("workspace", self.directory)
                command.assert_not_called()

    def test_workspace_archive_publication_rolls_back_exactly(self):
        checkout = self.base / "checkout"
        canonical = checkout / ".tmp"
        canonical.mkdir(parents=True)
        staged = self.base / "staged"
        staged.mkdir()
        archive_bytes = b"sealed oci"
        archive = staged / (
            "workspace-image-" + hashlib.sha256(archive_bytes).hexdigest() + ".oci.tar"
        )
        archive.write_bytes(archive_bytes)
        archive.chmod(0o400)
        receipt = staged / artifact.WORKSPACE_RECEIPT
        receipt.write_bytes(b"new receipt")
        contract = {
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "bytes": len(archive.read_bytes()), "mode": 0o400,
        }
        old_receipt = canonical / "codewire-workspace-image-verification.json"
        old_receipt.write_bytes(b"old receipt")

        with mock.patch.object(artifact, "ROOT", checkout), \
                mock.patch.object(artifact, "workspace_reuse", side_effect=artifact.ArtifactError("invalid")), \
                self.assertRaises(artifact.ArtifactError):
            artifact.publish_workspace(receipt, archive, contract)

        self.assertEqual(old_receipt.read_bytes(), b"old receipt")
        self.assertFalse((canonical / archive.name).exists())

    def test_workspace_publication_preserves_matching_existing_archive(self):
        checkout = self.base / "checkout-existing"
        canonical = checkout / ".tmp"
        canonical.mkdir(parents=True)
        staged = self.base / "staged-existing"
        staged.mkdir()
        archive_bytes = b"same sealed oci"
        archive = staged / (
            "workspace-image-" + hashlib.sha256(archive_bytes).hexdigest() + ".oci.tar"
        )
        archive.write_bytes(archive_bytes)
        archive.chmod(0o400)
        existing = canonical / archive.name
        existing.write_bytes(archive.read_bytes())
        existing.chmod(0o400)
        receipt = staged / artifact.WORKSPACE_RECEIPT
        receipt.write_bytes(b"new receipt")
        contract = {
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "bytes": len(archive.read_bytes()), "mode": 0o400,
        }

        with mock.patch.object(artifact, "ROOT", checkout), \
                mock.patch.object(artifact, "workspace_reuse", side_effect=artifact.ArtifactError("invalid")), \
                self.assertRaises(artifact.ArtifactError):
            artifact.publish_workspace(receipt, archive, contract)

        self.assertEqual(existing.read_bytes(), b"same sealed oci")

    def test_workspace_publication_passes_real_canonical_reuse_and_native_validation(self):
        checkout = self.base / "checkout-valid"
        canonical = checkout / ".tmp"
        canonical.mkdir(parents=True)
        staged = self.base / "staged-valid"
        staged.mkdir()
        source_archive = staged / "source.oci.tar"
        image_id, source_digest = write_oci_archive(source_archive)
        archive_sha = hashlib.sha256(source_archive.read_bytes()).hexdigest()
        archive = staged / f"workspace-image-{archive_sha}.oci.tar"
        source_archive.rename(archive)
        identity = {
            "schema_version": 2, "source_sha": "1" * 40, "source_tree": "2" * 40,
            "inputs": {}, "os": "linux", "architecture": "amd64",
        }
        receipt_value = {
            **identity,
            "base_manifest_digest": "sha256:" + "3" * 64,
            "workspace_image_id": image_id,
            "workspace_alias": workspace_artifact.alias_for(image_id),
            "workspace_oci": {
                "file": archive.name, "sha256": archive_sha,
                "size": archive.stat().st_size, "source_digest": source_digest,
            },
            "cache_modes": {"compiler": "local", "layers": "local"},
            "layer_cache_fallback": False,
        }
        receipt = staged / artifact.WORKSPACE_RECEIPT
        receipt.write_text(json.dumps(receipt_value) + "\n")
        contract = {
            "sha256": archive_sha, "bytes": archive.stat().st_size, "mode": 0o400,
        }

        def real_reuse(path):
            return workspace_artifact.reuse(checkout, path)

        def real_native(path):
            return workspace_artifact.reuse(checkout, path, native=True)

        with mock.patch.object(artifact, "ROOT", checkout), \
                mock.patch.object(artifact, "workspace_reuse", side_effect=real_reuse), \
                mock.patch.object(artifact, "workspace_native_input", side_effect=real_native), \
                mock.patch.object(workspace_artifact, "source_identity", return_value=identity), \
                mock.patch.object(workspace_artifact, "command", return_value=identity["source_tree"]), \
                mock.patch.object(workspace_artifact, "validate_image"), \
                mock.patch.object(workspace_artifact, "inspect", return_value={"Id": image_id}):
            artifact.publish_workspace(receipt, archive, contract)

        canonical_receipt = canonical / "codewire-workspace-image-verification.json"
        self.assertEqual(json.loads(canonical_receipt.read_text()), receipt_value)
        self.assertEqual((canonical / archive.name).stat().st_mode & 0o777, 0o400)

    def test_smoke_produce_uses_only_closed_sources_and_unique_output(self):
        target = self.base / "producer-target"
        run_directory = self.base / "producer-run"
        output = self.base / "github-output"
        os.environ.update(
            CARGO_TARGET_DIR=str(target), RUN_DIR=str(run_directory), GITHUB_OUTPUT=str(output),
        )
        for key in ("CARGO_TARGET_DIR", "RUN_DIR", "GITHUB_OUTPUT"):
            self.addCleanup(os.environ.pop, key, None)
        for name, relative in artifact.SMOKE_FILES.items():
            path = target / "ci" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            path.chmod(0o755)
        test_paths = {}
        for name, (jsonl_name, cargo_target, target_kind) in artifact.TEST_FILES.items():
            executable = target / "ci/deps" / f"{name}-hash"
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(name.encode())
            executable.chmod(0o755)
            test_paths[name] = executable
            (run_directory / jsonl_name).parent.mkdir(parents=True, exist_ok=True)
            (run_directory / jsonl_name).write_text(json.dumps({
                "reason": "compiler-artifact", "profile": {"test": True},
                "target": {"name": cargo_target, "kind": target_kind},
                "executable": str(executable),
            }) + "\n")

        # Some developer TMPDIR mounts are intentionally noexec; source mode is
        # covered independently from this closed-inventory fixture.
        with mock.patch.object(artifact.os, "access", return_value=True):
            result = artifact.produce("smokes", self.directory)

        self.assertEqual(
            {entry.name for entry in self.directory.iterdir()},
            set(artifact.SMOKE_FILES) | set(artifact.TEST_FILES) | {artifact.MANIFEST},
        )
        self.assertRegex(result["artifact_name"], r"^codewire-kind-smokes-v1-42-1-a{40}-[0-9a-f]{32}$")
        self.assertEqual(output.read_text().splitlines(), [
            f"artifact_name={result['artifact_name']}",
            f"manifest_sha256={result['manifest_sha256']}",
        ])

    def test_duplicate_or_malformed_test_artifact_is_rejected(self):
        executable = self.base / "test-bin"
        executable.write_bytes(b"test")
        executable.chmod(0o755)
        jsonl = self.base / "artifact.jsonl"
        record = json.dumps({
            "reason": "compiler-artifact", "profile": {"test": True},
            "target": {"name": "wire_contract", "kind": ["test"]},
            "executable": str(executable),
        })
        jsonl.write_text(record + "\n" + record + "\n")
        with self.assertRaises(artifact.ArtifactError):
            artifact.select_test_artifact(jsonl, "wire_contract", ["test"])
        jsonl.write_text("not json\n")
        with self.assertRaises(artifact.ArtifactError):
            artifact.select_test_artifact(jsonl, "wire_contract", ["test"])

    def test_smoke_source_rejects_test_artifact_outside_cargo_target(self):
        target = self.base / "target-boundary"
        run_directory = self.base / "run-boundary"
        os.environ.update(CARGO_TARGET_DIR=str(target), RUN_DIR=str(run_directory))
        self.addCleanup(os.environ.pop, "CARGO_TARGET_DIR", None)
        self.addCleanup(os.environ.pop, "RUN_DIR", None)
        for name, relative in artifact.SMOKE_FILES.items():
            path = target / "ci" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            path.chmod(0o755)
        escaped = self.base / "escaped-test"
        escaped.write_bytes(b"test")
        escaped.chmod(0o755)
        for _name, (jsonl_name, cargo_target, target_kind) in artifact.TEST_FILES.items():
            path = run_directory / jsonl_name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({
                "reason": "compiler-artifact", "profile": {"test": True},
                "target": {"name": cargo_target, "kind": target_kind},
                "executable": str(escaped),
            }) + "\n")
        with mock.patch.object(artifact.os, "access", return_value=True), \
                self.assertRaisesRegex(artifact.ArtifactError, "escaped"):
            artifact.smoke_sources()

    def test_transport_directory_must_be_fresh_and_outside_checkout(self):
        existing = self.base / "existing"
        existing.mkdir()
        with self.assertRaises(FileExistsError):
            artifact.require_directory(existing, create=True)
        with self.assertRaises(artifact.ArtifactError):
            artifact.require_directory(ROOT, create=False)


PIN_DIGEST = "sha256:" + "e" * 64
PIN_IMAGE = "ghcr.io/codewiresh/workspace@" + PIN_DIGEST
PIN_SOURCE = "5" * 40
PIN_INPUTS = "6" * 64
PINNED_ID = "sha256:" + "7" * 64


class FakePinTool:
    """The workspace-image-pin.py surface the Kind artifact helper uses."""

    class PinError(Exception):
        pass

    def __init__(self, definitions=None, pin_inputs=PIN_INPUTS, error=None):
        self.definitions = definitions or {}
        self.pin = {"digest": PIN_DIGEST, "source_sha": PIN_SOURCE,
                    "inputs_sha256": pin_inputs, "agents": {}, "previous_digests": []}
        self.error = error

    def read_pin(self, root, commit):
        if self.error:
            raise self.PinError(self.error)
        return self.pin

    def inputs_sha256(self, root, commit):
        if commit not in self.definitions:
            raise self.PinError(f"{commit} has no workspace image definition")
        return self.definitions[commit]

    def field(self, pin, name):
        return {"public-image": "ghcr.io/codewiresh/workspace@" + pin["digest"]}[name]


def pinned_inspect(reference, *, revision=PIN_SOURCE, digests=(PIN_IMAGE,), image_id=PINNED_ID,
                   architecture="amd64"):
    return {
        "Id": image_id, "Os": "linux", "Architecture": architecture,
        "RepoDigests": list(digests),
        "Config": {"Labels": {"org.opencontainers.image.revision": revision}},
    }


class PinnedWorkspaceTests(unittest.TestCase):
    HEAD = "a" * 40
    BASE = "b" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.checkout = self.base / "checkout"
        self.checkout.mkdir()
        self.directory = self.base / "artifact"
        for patcher in (
            mock.patch.object(artifact, "ROOT", self.checkout),
            mock.patch.object(artifact, "identity", side_effect=self._identity),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _identity(self, group):
        return {"repository": "codewire/codewire", "run_id": "42", "run_attempt": "1",
                "head": self.HEAD, "tree": "c" * 40, "platform": "linux/amd64",
                "profile": "workspace-verify"}

    def use_pin(self, tool):
        patcher = mock.patch.object(artifact, "pin_tool", return_value=tool)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_only_a_pin_built_from_this_definition_is_used(self):
        for base in (self.BASE, None):
            self.use_pin(FakePinTool({self.HEAD: PIN_INPUTS, self.BASE: PIN_INPUTS}))
            self.assertEqual(artifact.workspace_source(self.HEAD, base)[0], "pinned")

    def test_a_pin_that_lags_an_unchanged_definition_rebuilds_from_source(self):
        # The definition is unchanged from the base, but the pin was built from
        # an older one: Kind must not run an image this tree does not deploy.
        self.use_pin(FakePinTool({self.HEAD: "1" * 64, self.BASE: "1" * 64}))
        self.assertEqual(artifact.workspace_source(self.HEAD, self.BASE),
                         ("source", "the pin was built from another workspace image definition"))

    def test_changed_definition_rebuilds_from_source(self):
        self.use_pin(FakePinTool({self.HEAD: "1" * 64, self.BASE: PIN_INPUTS}))
        self.assertEqual(artifact.workspace_source(self.HEAD, self.BASE)[0], "source")
        self.use_pin(FakePinTool({self.HEAD: "1" * 64}))
        self.assertEqual(artifact.workspace_source(self.HEAD, None)[0], "source")

    def test_unreadable_pin_falls_back_to_source(self):
        self.use_pin(FakePinTool({self.HEAD: PIN_INPUTS}, error="invalid pin"))
        self.assertEqual(artifact.workspace_source(self.HEAD, self.BASE)[0], "source")
        with self.assertRaises(artifact.ArtifactError):
            artifact.workspace_source("HEAD", None)

    def test_source_mode_is_closed(self):
        self.assertEqual(artifact.workspace_source_mode({}), "source")
        self.assertEqual(artifact.workspace_source_mode({"CODEWIRE_KIND_WORKSPACE_SOURCE": "pinned"}), "pinned")
        with self.assertRaises(artifact.ArtifactError):
            artifact.workspace_source_mode({"CODEWIRE_KIND_WORKSPACE_SOURCE": "latest"})

    def produce_pinned(self):
        output = self.base / "github-output"
        environment = {"GITHUB_OUTPUT": str(output), "CODEWIRE_KIND_WORKSPACE_SOURCE": "pinned"}
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(artifact, "run") as command, \
                mock.patch.object(artifact, "workspace_reuse") as reuse:
            result = artifact.produce("workspace", self.directory)
        command.assert_not_called()
        reuse.assert_not_called()
        return result

    def test_pinned_producer_exports_only_the_pin_record(self):
        self.use_pin(FakePinTool())
        result = self.produce_pinned()
        self.assertEqual({entry.name for entry in self.directory.iterdir()},
                         {artifact.WORKSPACE_PIN, artifact.MANIFEST})
        record = json.loads((self.directory / artifact.WORKSPACE_PIN).read_text())
        self.assertEqual(record, {
            "schema": artifact.WORKSPACE_PIN_SCHEMA, "image": PIN_IMAGE, "digest": PIN_DIGEST,
            "source_sha": PIN_SOURCE, "inputs_sha256": PIN_INPUTS,
        })
        manifest = json.loads((self.directory / artifact.MANIFEST).read_text())
        self.assertEqual(set(manifest["files"]), {artifact.WORKSPACE_PIN})
        self.assertEqual(manifest["files"][artifact.WORKSPACE_PIN]["mode"], 0o600)
        self.assertEqual(hashlib.sha256((self.directory / artifact.MANIFEST).read_bytes()).hexdigest(),
                         result["manifest_sha256"])

    def consume_pinned(self, inspect=pinned_inspect, pull_failures=0):
        calls = []

        def command(*args, **kwargs):
            calls.append(args)
            if args[1] == "pull" and sum(call[1] == "pull" for call in calls) <= pull_failures:
                raise artifact.subprocess.CalledProcessError(1, args)
            return ""

        os.environ["EXPECTED_MANIFEST_SHA256"] = hashlib.sha256(
            (self.directory / artifact.MANIFEST).read_bytes()).hexdigest()
        self.addCleanup(os.environ.pop, "EXPECTED_MANIFEST_SHA256", None)
        with mock.patch.object(artifact, "run", side_effect=command), \
                mock.patch.object(artifact, "inspect_image", side_effect=inspect), \
                mock.patch.object(artifact.time, "sleep"):
            artifact.consume("workspace", self.directory)
        return calls

    def test_pinned_consumer_pulls_by_digest_and_records_its_alias(self):
        self.use_pin(FakePinTool())
        self.produce_pinned()
        calls = self.consume_pinned(pull_failures=1)
        alias = artifact.PINNED_WORKSPACE_ALIAS + "7" * 64
        self.assertEqual(calls, [
            (artifact.docker(), "pull", "--platform", "linux/amd64", PIN_IMAGE),
            (artifact.docker(), "pull", "--platform", "linux/amd64", PIN_IMAGE),
            (artifact.docker(), "image", "tag", PINNED_ID, alias),
        ])
        selection = json.loads((self.checkout / artifact.WORKSPACE_SELECTION).read_text())
        self.assertEqual(selection, {
            "schema": artifact.WORKSPACE_SELECTION_SCHEMA, "mode": "pinned", "image": alias,
            "image_id": PINNED_ID, "reference": PIN_IMAGE, "source_sha": PIN_SOURCE,
        })
        with mock.patch.object(artifact, "inspect_image", side_effect=pinned_inspect), \
                mock.patch.object(artifact, "workspace_reuse") as reuse:
            self.assertEqual(artifact.workspace_runtime_image(), alias)
        reuse.assert_not_called()

    def test_pinned_consumer_rejects_an_image_that_is_not_the_pin(self):
        cases = {
            "revision": lambda ref: pinned_inspect(ref, revision="9" * 40),
            "digest": lambda ref: pinned_inspect(ref, digests=("ghcr.io/codewiresh/workspace@sha256:" + "8" * 64,)),
            "architecture": lambda ref: pinned_inspect(ref, architecture="arm64"),
        }
        for name, inspect in cases.items():
            with self.subTest(case=name):
                if self.directory.exists():
                    for child in self.directory.iterdir():
                        child.unlink()
                    self.directory.rmdir()
                self.use_pin(FakePinTool())
                self.produce_pinned()
                with self.assertRaisesRegex(artifact.ArtifactError, "not the published pin"):
                    self.consume_pinned(inspect=inspect)
                self.assertFalse((self.checkout / artifact.WORKSPACE_SELECTION).exists())

    def test_pinned_record_must_match_the_checkout_pin_before_any_pull(self):
        self.use_pin(FakePinTool())
        self.produce_pinned()
        other = FakePinTool()
        other.pin = dict(other.pin, digest="sha256:" + "d" * 64)
        self.use_pin(other)
        with self.assertRaisesRegex(artifact.ArtifactError, "differs from the checkout"):
            self.consume_pinned()

    def test_runtime_image_without_pinned_selection_uses_the_source_receipt(self):
        receipt = self.checkout / ".tmp/codewire-workspace-image-verification.json"
        with mock.patch.object(artifact, "workspace_reuse", return_value="source-alias") as reuse:
            self.assertEqual(artifact.workspace_runtime_image(), "source-alias")
            artifact.write_workspace_selection({"mode": "source"})
            self.assertEqual(artifact.workspace_runtime_image(), "source-alias")
        self.assertEqual(reuse.call_args_list, [mock.call(receipt), mock.call(receipt)])

    def test_runtime_image_rejects_a_changed_pinned_alias(self):
        self.use_pin(FakePinTool())
        alias = artifact.PINNED_WORKSPACE_ALIAS + "7" * 64
        artifact.write_workspace_selection({
            "mode": "pinned", "image": alias, "image_id": PINNED_ID,
            "reference": PIN_IMAGE, "source_sha": PIN_SOURCE,
        })
        with mock.patch.object(artifact, "inspect_image",
                               side_effect=lambda ref: pinned_inspect(ref, image_id="sha256:" + "3" * 64)), \
                self.assertRaisesRegex(artifact.ArtifactError, "names another image"):
            artifact.workspace_runtime_image()


if __name__ == "__main__":
    unittest.main()
