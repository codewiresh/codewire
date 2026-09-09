#!/usr/bin/env python3
"""Focused rejection tests for exact Kind build-artifact handoff."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
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

    def write_artifact(self, group: str, members: dict[str, bytes], **extra):
        self.directory.mkdir(mode=0o700)
        files = {}
        mode = 0o755 if group == "smokes" else 0o600
        for name, content in members.items():
            path = self.directory / name
            path.write_bytes(content)
            files[name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
                "mode": mode,
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
                  for index, name in enumerate(artifact.PRODUCT_IMAGES, 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)
        (self.directory / artifact.IMAGE_ARCHIVE).write_bytes(b"corrupt")
        with mock.patch.object(artifact, "run") as command:
            with self.assertRaises(artifact.ArtifactError):
                artifact.consume("product", self.directory)
        command.assert_not_called()

    def test_product_import_rechecks_all_recorded_image_identities(self):
        images = {name: {"id": "sha256:" + str(index) * 64}
                  for index, name in enumerate(artifact.PRODUCT_IMAGES, 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)

        def inspect(reference):
            return [{
                "Id": images[reference]["id"], "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": {
                    "dev.codewire.build.profile": "ci",
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
                  for index, name in enumerate(artifact.PRODUCT_IMAGES, 1)}
        self.write_artifact("product", {artifact.IMAGE_ARCHIVE: b"image archive"}, images=images)

        def inspect(reference):
            return {
                "Id": images[reference]["id"], "Os": "linux", "Architecture": "amd64",
                "Config": {"Labels": {
                    "dev.codewire.build.profile": "ci",
                    "dev.codewire.promotable": "false",
                    "org.opencontainers.image.revision": "d" * 40,
                }},
            }

        with mock.patch.object(artifact, "run"), \
                mock.patch.object(artifact, "inspect_image", side_effect=inspect), \
                self.assertRaises(artifact.ArtifactError):
            artifact.consume("product", self.directory)

    def test_workspace_receipt_validation_follows_archive_hash_and_load(self):
        self.write_artifact("workspace", {
            artifact.WORKSPACE_RECEIPT: b"receipt\n",
            artifact.IMAGE_ARCHIVE: b"archive\n",
        })
        calls = []

        def command(*args, **kwargs):
            calls.append((args, kwargs))
            return ""

        with mock.patch.object(artifact, "run", side_effect=command), \
                mock.patch.object(artifact, "workspace_reuse", side_effect=lambda path: calls.append(("reuse", path)) or "alias"), \
                mock.patch.object(artifact, "atomic_install", side_effect=lambda *args: calls.append(("install", args))):
            artifact.consume("workspace", self.directory)
        self.assertEqual(calls[0][0][:2], (artifact.docker(), "load"))
        self.assertEqual(calls[1], ("reuse", self.directory / artifact.WORKSPACE_RECEIPT))
        self.assertEqual(calls[2][0], "install")

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


if __name__ == "__main__":
    unittest.main()
