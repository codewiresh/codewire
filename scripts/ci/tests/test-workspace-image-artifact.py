#!/usr/bin/env python3
"""Synthetic receipt checks: no Docker, Git subprocesses, network, or host auth."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / "verify/workspace-image-artifact.py"
SPEC = importlib.util.spec_from_file_location("workspace_image_artifact", HELPER)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)

SOURCE = "1" * 40
TREE = "2" * 40
OTHER_SOURCE = "3" * 40
OTHER_TREE = "4" * 40
IMAGE_ID = "sha256:" + "5" * 64
BASE_DIGEST = "sha256:" + "6" * 64
OTHER_IMAGE_ID = "sha256:" + "7" * 64


class SyntheticSource(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="workspace-image-artifact-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receipt = self.root / "receipt.json"
        for name in artifact.INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic input: " + name + "\n", encoding="utf-8")
        self.source = SOURCE
        self.tree = TREE
        self.status = ""
        self.commits = {SOURCE: TREE}
        self.images = {}
        # Tripwire: even a missing command mock must never reach host tools.
        self.start_patch(mock.patch.object(
            artifact.subprocess, "run", side_effect=AssertionError("host subprocess forbidden")
        ))
        self.command = self.start_patch(mock.patch.object(
            artifact, "command", side_effect=self.fake_command
        ))
        self.start_patch(mock.patch.object(artifact.platform, "system", return_value="Linux"))
        self.start_patch(mock.patch.object(artifact.platform, "machine", return_value="x86_64"))
        self.start_patch(mock.patch.dict(os.environ, {"CODEWIRE_DOCKER_BIN": "synthetic-docker"}))

    def start_patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def fake_command(self, *args):
        git = ("git", "-C", str(self.root))
        if args == (*git, "status", "--porcelain", "--untracked-files=normal"):
            return self.status
        if args == (*git, "rev-parse", "HEAD"):
            return self.source
        if args == (*git, "rev-parse", "HEAD^{tree}"):
            return self.tree
        if args[:4] == (*git, "rev-parse") and len(args) == 5 and args[4].endswith("^{tree}"):
            commit = args[4][:-7]
            if commit not in self.commits:
                raise subprocess.CalledProcessError(128, args)
            return self.commits[commit]
        if args == ("synthetic-docker", "image", "tag", IMAGE_ID, artifact.alias_for(IMAGE_ID)):
            self.images[args[4]] = copy.deepcopy(self.images[IMAGE_ID])
            return ""
        raise AssertionError(f"unexpected synthetic command: {args!r}")


class SourceIdentityTests(SyntheticSource):
    def test_clean_identity_hashes_every_checked_in_input(self):
        identity = artifact.source_identity(self.root)
        self.assertEqual(identity, {
            "schema_version": 1,
            "source_sha": SOURCE,
            "source_tree": TREE,
            "inputs": {
                name: hashlib.sha256((self.root / name).read_bytes()).hexdigest()
                for name in artifact.INPUTS
            },
            "os": "linux",
            "architecture": "amd64",
        })

    def test_dirty_tracked_staged_and_untracked_sources_are_rejected(self):
        for status in (" M images/workspace/Dockerfile", "M  .dockerignore", "?? extra"):
            with self.subTest(status=status):
                self.status = status
                with self.assertRaisesRegex(ValueError, "clean committed"):
                    artifact.source_identity(self.root)

    def test_malformed_commit_and_tree_are_rejected(self):
        for field in ("source", "tree"):
            for value in ("", "a" * 39, "A" * 40, "HEAD", "a" * 40 + "\n"):
                with self.subTest(field=field, value=value):
                    with mock.patch.object(self, field, value):
                        with self.assertRaisesRegex(ValueError, "source identity"):
                            artifact.source_identity(self.root)

    def test_linux_arm64_is_supported(self):
        with mock.patch.object(artifact.platform, "machine", return_value="aarch64"):
            self.assertEqual(artifact.source_identity(self.root)["architecture"], "arm64")

    def test_nonlinux_and_unknown_architectures_are_rejected(self):
        for system, machine in (("Darwin", "aarch64"), ("Linux", "riscv64")):
            with self.subTest(system=system, machine=machine):
                with mock.patch.object(artifact.platform, "system", return_value=system):
                    with mock.patch.object(artifact.platform, "machine", return_value=machine):
                        with self.assertRaisesRegex(ValueError, "native Linux"):
                            artifact.source_identity(self.root)

    def test_missing_input_is_not_an_identity(self):
        (self.root / artifact.INPUTS[0]).unlink()
        with self.assertRaises(FileNotFoundError):
            artifact.source_identity(self.root)


class ReceiptTests(SyntheticSource):
    def setUp(self):
        super().setUp()
        self.identity = artifact.source_identity(self.root)
        self.images[IMAGE_ID] = {
            "Id": IMAGE_ID,
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Labels": {
                "org.opencontainers.image.revision": SOURCE,
                "dev.codewire.source-tree": TREE,
                "dev.codewire.workspace-contract": self.identity["inputs"][artifact.INPUTS[3]],
                "dev.codewire.promotable": "false",
                "dev.codewire.build.profile": "workspace-verify",
            }},
        }
        self.inspect = self.start_patch(mock.patch.object(
            artifact, "inspect", side_effect=self.fake_inspect
        ))

    def fake_inspect(self, image):
        if image not in self.images:
            raise subprocess.CalledProcessError(1, ["synthetic-docker", "image", "inspect", image])
        return copy.deepcopy(self.images[image])

    def seal(self):
        return artifact.seal(self.root, self.receipt, IMAGE_ID, BASE_DIGEST)

    def read_receipt(self):
        return json.loads(self.receipt.read_text(encoding="utf-8"))

    def write_receipt(self, value):
        self.receipt.write_text(json.dumps(value), encoding="utf-8")

    def test_successful_seal_and_reuse_bind_exact_identity_and_image(self):
        alias = self.seal()
        self.assertEqual(alias, "localhost/codewire-ci/workspace:source-" + "5" * 64)
        self.assertEqual(self.read_receipt(), {
            **self.identity,
            "base_manifest_digest": BASE_DIGEST,
            "workspace_image_id": IMAGE_ID,
            "workspace_alias": alias,
        })
        self.assertEqual(artifact.reuse(self.root, self.receipt), alias)
        self.assertEqual(list(self.root.glob(".workspace-image-*")), [])
        self.command.assert_any_call("synthetic-docker", "image", "tag", IMAGE_ID, alias)

    def test_same_tree_commit_can_reuse_original_verified_image(self):
        alias = self.seal()
        self.source = OTHER_SOURCE
        self.commits[OTHER_SOURCE] = TREE
        self.assertEqual(artifact.reuse(self.root, self.receipt), alias)
        self.assertEqual(self.read_receipt()["source_sha"], SOURCE)

    def test_head_tree_change_never_reuses_old_receipt(self):
        self.seal()
        self.source = OTHER_SOURCE
        self.tree = OTHER_TREE
        self.commits[OTHER_SOURCE] = OTHER_TREE
        with self.assertRaisesRegex(ValueError, "source/input mismatch"):
            artifact.reuse(self.root, self.receipt)

    def test_original_commit_must_still_resolve_to_exact_current_tree(self):
        self.seal()
        self.commits[SOURCE] = OTHER_TREE
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            artifact.reuse(self.root, self.receipt)

    def test_unknown_original_commit_is_rejected(self):
        self.seal()
        self.commits.clear()
        with self.assertRaises(subprocess.CalledProcessError):
            artifact.reuse(self.root, self.receipt)

    def test_each_input_change_including_agent_contract_invalidates_receipt(self):
        self.seal()
        for name in artifact.INPUTS:
            path = self.root / name
            original = path.read_bytes()
            with self.subTest(input=name):
                try:
                    path.write_bytes(original + b"changed\n")
                    with self.assertRaisesRegex(ValueError, "source/input mismatch"):
                        artifact.reuse(self.root, self.receipt)
                finally:
                    path.write_bytes(original)

    def test_dirty_source_cannot_seal_or_reuse(self):
        self.status = "?? uncommitted-input"
        with self.assertRaisesRegex(ValueError, "clean committed"):
            self.seal()
        self.assertFalse(self.receipt.exists())
        self.status = ""
        self.seal()
        self.status = " M images/base/Dockerfile"
        with self.assertRaisesRegex(ValueError, "clean committed"):
            artifact.reuse(self.root, self.receipt)

    def test_missing_corrupt_oversized_and_nonfile_receipts_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "receipt file"):
            artifact.reuse(self.root, self.receipt)
        for raw in (b"{", b"null", b"{}", b"x" * (64 * 1024 + 1)):
            with self.subTest(raw=raw[:10]):
                self.receipt.write_bytes(raw)
                with self.assertRaises((ValueError, TypeError)):
                    artifact.reuse(self.root, self.receipt)
        with self.assertRaisesRegex(ValueError, "receipt file"):
            artifact.reuse(self.root, self.root)

    def test_unknown_or_missing_receipt_fields_are_rejected(self):
        self.seal()
        original = self.read_receipt()
        unknown = {**original, "skip_contract": True}
        missing = {key: value for key, value in original.items() if key != "base_manifest_digest"}
        for value in (unknown, missing):
            with self.subTest(fields=sorted(value)):
                self.write_receipt(value)
                with self.assertRaisesRegex(ValueError, "receipt fields"):
                    artifact.reuse(self.root, self.receipt)

    def test_receipt_source_must_be_a_full_lowercase_commit(self):
        self.seal()
        original = self.read_receipt()
        for source in (None, "HEAD", "A" * 40, "1" * 39):
            with self.subTest(source=source):
                self.write_receipt({**original, "source_sha": source})
                with self.assertRaisesRegex(ValueError, "receipt source"):
                    artifact.reuse(self.root, self.receipt)

    def test_schema_os_architecture_and_input_inventory_must_match(self):
        self.seal()
        for key, changed in (
            ("schema_version", 2), ("os", "windows"), ("architecture", "arm64"), ("inputs", {}),
        ):
            current = {**self.identity, key: changed}
            with self.subTest(field=key):
                with mock.patch.object(artifact, "source_identity", return_value=current):
                    with self.assertRaisesRegex(ValueError, "source/input mismatch"):
                        artifact.reuse(self.root, self.receipt)

    def test_receipt_digests_and_alias_are_closed(self):
        self.seal()
        original = self.read_receipt()
        for key in ("base_manifest_digest", "workspace_image_id", "workspace_alias"):
            with self.subTest(field=key):
                self.write_receipt({**original, key: "arbitrary:latest"})
                with self.assertRaises(ValueError):
                    artifact.reuse(self.root, self.receipt)

    def test_removed_image_or_retargeted_alias_cannot_reuse_receipt(self):
        alias = self.seal()
        self.images[alias]["Id"] = OTHER_IMAGE_ID
        with self.assertRaisesRegex(ValueError, "alias no longer"):
            artifact.reuse(self.root, self.receipt)
        del self.images[IMAGE_ID]
        with self.assertRaises(subprocess.CalledProcessError):
            artifact.reuse(self.root, self.receipt)

    def test_image_id_os_and_architecture_mismatches_cannot_seal(self):
        for key, value in (("Id", OTHER_IMAGE_ID), ("Os", "windows"), ("Architecture", "arm64")):
            with self.subTest(field=key):
                with mock.patch.dict(self.images[IMAGE_ID], {key: value}):
                    with self.assertRaises(ValueError):
                        self.seal()
                self.assertFalse(self.receipt.exists())
        self.assertFalse(any(call.args[:3] == ("synthetic-docker", "image", "tag")
                             for call in self.command.call_args_list))

    def test_every_image_identity_label_is_required_for_seal_and_reuse(self):
        self.seal()
        self.receipt.unlink()
        labels = self.images[IMAGE_ID]["Config"]["Labels"]
        original = copy.deepcopy(labels)
        for key in original:
            for mutation in ("missing", "wrong"):
                with self.subTest(label=key, mutation=mutation):
                    labels.clear()
                    labels.update(original)
                    if mutation == "missing":
                        del labels[key]
                    else:
                        labels[key] = "unexpected"
                    with self.assertRaisesRegex(ValueError, "source identity mismatch"):
                        self.seal()
                    self.assertFalse(self.receipt.exists())
        labels.clear()
        labels.update(original)
        self.seal()
        for key in original:
            with self.subTest(reuse_label=key):
                with mock.patch.dict(labels, {key: "unexpected"}):
                    with self.assertRaisesRegex(ValueError, "source identity mismatch"):
                        artifact.reuse(self.root, self.receipt)

    def test_image_inspection_failure_emits_no_receipt(self):
        self.inspect.side_effect = subprocess.CalledProcessError(1, ["synthetic-docker"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.seal()
        self.assertFalse(self.receipt.exists())
        self.assertEqual(list(self.root.glob(".workspace-image-*")), [])

    def test_malformed_image_configuration_and_labels_are_closed_failures(self):
        for config in (None, [], "invalid", {"Labels": ["invalid"]}, {"Labels": "invalid"}):
            with self.subTest(config=config):
                with mock.patch.dict(self.images[IMAGE_ID], {"Config": config}):
                    with self.assertRaisesRegex(ValueError, "invalid image (configuration|labels)"):
                        self.seal()
                self.assertFalse(self.receipt.exists())

    def test_alias_validation_failure_emits_no_receipt(self):
        def wrong_alias(image):
            value = self.fake_inspect(image)
            if image != IMAGE_ID:
                value["Id"] = OTHER_IMAGE_ID
            return value

        self.inspect.side_effect = wrong_alias
        with self.assertRaisesRegex(ValueError, "image alias mismatch"):
            self.seal()
        self.assertFalse(self.receipt.exists())

    def test_invalid_base_digest_emits_no_receipt(self):
        with self.assertRaisesRegex(ValueError, "image digest"):
            artifact.seal(self.root, self.receipt, IMAGE_ID, "latest")
        self.assertFalse(self.receipt.exists())

    def test_atomic_write_failure_leaves_no_partial_receipt(self):
        with mock.patch.object(artifact.os, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                self.seal()
        self.assertFalse(self.receipt.exists())
        self.assertEqual(list(self.root.glob(".workspace-image-*")), [])

    def test_receipt_and_direct_parent_symlinks_are_rejected(self):
        self.seal()
        link = self.root / "receipt-link.json"
        link.symlink_to(self.receipt)
        with self.assertRaisesRegex(ValueError, "receipt file"):
            artifact.reuse(self.root, link)
        with self.assertRaisesRegex(ValueError, "receipt destination"):
            artifact.seal(self.root, link, IMAGE_ID, BASE_DIGEST)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "receipt destination"):
            artifact.seal(self.root, parent_link / "other.json", IMAGE_ID, BASE_DIGEST)


class InspectionTests(SyntheticSource):
    def test_inspection_accepts_one_object_using_scoped_docker(self):
        self.command.return_value = json.dumps([{"Id": IMAGE_ID}])
        self.command.side_effect = None
        self.assertEqual(artifact.inspect(IMAGE_ID), {"Id": IMAGE_ID})
        self.command.assert_called_once_with("synthetic-docker", "image", "inspect", IMAGE_ID)

    def test_inspection_rejects_malformed_oversized_or_nonobject_results(self):
        self.command.side_effect = None
        for raw in ("{", "{}", "[]", "[{}, {}]", "[null]", "[[]]", "[1]", "x" * (512 * 1024 + 1)):
            with self.subTest(raw=raw[:10]):
                self.command.return_value = raw
                with self.assertRaises(ValueError):
                    artifact.inspect(IMAGE_ID)


if __name__ == "__main__":
    unittest.main()
