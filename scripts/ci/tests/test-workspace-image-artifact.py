#!/usr/bin/env python3
"""Synthetic receipts and real admission/custody over never-executed CW bytes.

The copy cases use private synthetic Git and a fake Docker API. No compiler,
Docker daemon, incoming CW, provider network or host login is used.
"""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
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
CONFIG_BYTES = json.dumps({"os": "linux", "architecture": "amd64",
                          "rootfs": {"type": "layers", "diff_ids": []}}, sort_keys=True).encode()
IMAGE_ID = "sha256:" + hashlib.sha256(CONFIG_BYTES).hexdigest()
BASE_DIGEST = "sha256:" + "6" * 64
OTHER_IMAGE_ID = "sha256:" + "7" * 64


def write_archive(path, *, config=CONFIG_BYTES, change=None):
    def descriptor(raw, media_type):
        return {"mediaType": media_type, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "size": len(raw)}

    config_descriptor = descriptor(config, "application/vnd.oci.image.config.v1+json")
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": config_descriptor, "layers": []}, sort_keys=True).encode()
    manifest_descriptor = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    entries = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": json.dumps({"schemaVersion": 2, "manifests": [manifest_descriptor]}).encode(),
        "blobs/sha256/" + manifest_descriptor["digest"][7:]: manifest,
        "blobs/sha256/" + config_descriptor["digest"][7:]: config,
    }
    if change:
        change(entries)
    with tarfile.open(path, "w") as archive:
        for name, contents in entries.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(contents)
            archive.addfile(entry, io.BytesIO(contents))
    path.chmod(0o400)
    return manifest_descriptor["digest"]


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
        self.start_patch(mock.patch.dict(os.environ, {"CODEWIRE_DOCKER_BIN": "synthetic-docker", "CODEWIRE_SCCACHE_MODE": "local",
             "CODEWIRE_BUILDKIT_CACHE_MODE": "local", "CODEWIRE_BUILDKIT_CACHE_FALLBACK": "false"}))

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
            "schema_version": 2,
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
        self.archive = self.root / "export.oci.tar"
        self.source_digest = write_archive(self.archive)

    def fake_inspect(self, image):
        if image not in self.images:
            raise subprocess.CalledProcessError(1, ["synthetic-docker", "image", "inspect", image])
        return copy.deepcopy(self.images[image])

    def seal(self):
        if not self.archive.exists():
            write_archive(self.archive)
        return artifact.seal(self.root, self.receipt, IMAGE_ID, BASE_DIGEST, self.archive)

    def read_receipt(self):
        return json.loads(self.receipt.read_text(encoding="utf-8"))

    def write_receipt(self, value):
        self.receipt.write_text(json.dumps(value), encoding="utf-8")

    def test_successful_seal_and_reuse_bind_exact_identity_and_image(self):
        alias = self.seal()
        self.assertEqual(alias, "localhost/codewire-ci/workspace:source-" + IMAGE_ID[7:])
        oci = self.read_receipt()["workspace_oci"]
        self.assertEqual(self.read_receipt(), {
            **self.identity,
            "base_manifest_digest": BASE_DIGEST,
            "workspace_image_id": IMAGE_ID,
            "workspace_alias": alias,
            "workspace_oci": oci,
            "cache_modes": {"compiler": "local", "layers": "local"},
            "layer_cache_fallback": False,
        })
        self.assertEqual(oci, artifact.archive_identity(self.root / oci["file"], IMAGE_ID, "amd64"))
        self.assertEqual(oci["source_digest"], self.source_digest)
        self.assertEqual(artifact.reuse(self.root, self.receipt, native=True),
                         {**oci, "path": str(self.root / oci["file"])})
        self.assertEqual(artifact.reuse(self.root, self.receipt), alias)
        self.assertEqual(list(self.root.glob(".workspace-image-*")), [])
        self.command.assert_any_call("synthetic-docker", "image", "tag", IMAGE_ID, alias)

    def test_mode_change_requires_build_but_kind_can_consume_verified_bytes(self):
        alias = self.seal()
        for compiler in ("disabled", "local", "r2"):
            for layers in ("disabled", "local", "r2"):
                with self.subTest(compiler=compiler, layers=layers):
                    with mock.patch.dict(os.environ, {"CODEWIRE_SCCACHE_MODE": compiler,
                                                     "CODEWIRE_BUILDKIT_CACHE_MODE": layers}):
                        self.assertEqual(artifact.reuse(self.root, self.receipt), alias)
                        if compiler == layers == "local":
                            self.assertEqual(artifact.reuse(self.root, self.receipt, for_build=True), alias)
                        else:
                            with self.assertRaisesRegex(ValueError, "cache mode mismatch"):
                                artifact.reuse(self.root, self.receipt, for_build=True)

    def test_r2_fallback_is_recorded_without_credential_or_endpoint(self):
        with mock.patch.dict(os.environ, {"CODEWIRE_BUILDKIT_CACHE_MODE": "r2",
                                         "CODEWIRE_BUILDKIT_CACHE_FALLBACK": "true",
                                         "CODEWIRE_SCCACHE_CREDENTIALS_FILE": "/private/synthetic.aws"}):
            self.seal()
        value = self.read_receipt()
        self.assertTrue(value["layer_cache_fallback"])
        self.assertEqual(value["cache_modes"]["layers"], "r2")
        self.assertNotIn("synthetic.aws", self.receipt.read_text())

    def test_invalid_cache_evidence_cannot_seal_or_reuse(self):
        for env in ({"CODEWIRE_SCCACHE_MODE": "auto"}, {"CODEWIRE_BUILDKIT_CACHE_MODE": "invalid"},
                    {"CODEWIRE_BUILDKIT_CACHE_FALLBACK": "1"}):
            with mock.patch.dict(os.environ, env):
                with self.assertRaises(ValueError):
                    self.seal()
        self.seal()
        valid = self.read_receipt()
        for modes in ({"compiler": "local"}, {"compiler": "local", "layers": "auto"}, [],
                      {"compiler": "local", "layers": "local", "key": "synthetic"}):
            invalid = copy.deepcopy(valid)
            invalid["cache_modes"] = modes
            self.write_receipt(invalid)
            with self.assertRaisesRegex(ValueError, "cache modes"):
                artifact.reuse(self.root, self.receipt)
        invalid = copy.deepcopy(valid)
        invalid["layer_cache_fallback"] = "false"
        self.write_receipt(invalid)
        with self.assertRaisesRegex(ValueError, "cache modes"):
            artifact.reuse(self.root, self.receipt)

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
            ("schema_version", 1), ("os", "windows"), ("architecture", "arm64"), ("inputs", {}),
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
            artifact.seal(self.root, self.receipt, IMAGE_ID, "latest", self.archive)
        self.assertFalse(self.receipt.exists())

    def test_atomic_write_failure_leaves_no_partial_receipt(self):
        with mock.patch.object(artifact.os, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                self.seal()
        self.assertFalse(self.receipt.exists())
        self.assertEqual(list(self.root.glob(".workspace-image-*")), [])
        self.assertEqual(list(self.root.glob("workspace-image-*.oci.tar")), [])

    def test_failed_receipt_replacement_preserves_previously_verified_archive(self):
        self.seal()
        before = self.read_receipt()
        previous_archive = self.root / before["workspace_oci"]["file"]
        self.write_distinct_archive()
        with mock.patch.object(artifact.os, "replace", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(OSError):
                self.seal()
        self.assertEqual(self.read_receipt(), before)
        self.assertTrue(previous_archive.exists())
        self.assertEqual(list(self.root.glob("workspace-image-*.oci.tar")), [previous_archive])

    def write_distinct_archive(self):
        # Different wrapper bytes, same verified runtime image/configuration.
        self.archive.unlink(missing_ok=True)
        write_archive(self.archive, change=lambda entries: entries.update({
            "oci-layout": b'{ "imageLayoutVersion": "1.0.0" }\n',
        }))

    def test_successful_replacement_removes_only_the_verified_prior_archive(self):
        self.seal()
        previous = self.root / self.read_receipt()["workspace_oci"]["file"]
        unrelated = self.root / ("workspace-image-" + "9" * 64 + ".oci.tar")
        unrelated.write_bytes(b"not owned by the previous receipt")
        unrelated.chmod(0o400)
        self.write_distinct_archive()
        self.seal()
        current = self.root / self.read_receipt()["workspace_oci"]["file"]
        self.assertNotEqual(previous, current)
        self.assertFalse(previous.exists())
        self.assertTrue(current.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(artifact.reuse(self.root, self.receipt), artifact.alias_for(IMAGE_ID))

    def test_moved_stale_receipt_still_selects_only_its_verified_prior_archive(self):
        self.seal()
        previous = self.root / self.read_receipt()["workspace_oci"]["file"]
        private_staging = self.root / "private-staging"
        private_staging.mkdir(mode=0o700)
        stale_receipt = private_staging / "previous-receipt.json"
        self.receipt.rename(stale_receipt)
        self.write_distinct_archive()

        artifact.seal(
            self.root, self.receipt, IMAGE_ID, BASE_DIGEST, self.archive, stale_receipt
        )

        current = self.root / self.read_receipt()["workspace_oci"]["file"]
        self.assertNotEqual(previous, current)
        self.assertFalse(previous.exists())
        self.assertTrue(current.exists())
        self.assertTrue(stale_receipt.exists())

    def test_replacement_never_prunes_untrusted_prior_artifacts(self):
        for change in ("writable", "hardlink", "symlink", "wrong-hash", "traversal"):
            with self.subTest(change=change):
                self.seal()
                value = self.read_receipt()
                previous = self.root / value["workspace_oci"]["file"]
                extra = self.root / ("preserved-" + change)
                if change == "writable":
                    previous.chmod(0o600)
                elif change == "hardlink":
                    os.link(previous, extra)
                elif change == "symlink":
                    previous.rename(extra)
                    previous.symlink_to(extra)
                elif change == "wrong-hash":
                    value["workspace_oci"]["sha256"] = "0" * 64
                else:
                    value["workspace_oci"]["file"] = "../outside.oci.tar"
                self.write_receipt(value)
                self.write_distinct_archive()
                self.seal()
                self.assertTrue(previous.exists())
                # Restore this synthetic fixture before the next subcase.
                if previous.is_symlink():
                    previous.unlink()
                    extra.rename(previous)
                if change == "hardlink":
                    extra.unlink()
                previous.chmod(0o400)

    def test_receipt_and_direct_parent_symlinks_are_rejected(self):
        self.seal()
        link = self.root / "receipt-link.json"
        link.symlink_to(self.receipt)
        with self.assertRaisesRegex(ValueError, "receipt file"):
            artifact.reuse(self.root, link)
        with self.assertRaisesRegex(ValueError, "receipt destination"):
            artifact.seal(self.root, link, IMAGE_ID, BASE_DIGEST, self.archive)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "receipt destination"):
            artifact.seal(self.root, parent_link / "other.json", IMAGE_ID, BASE_DIGEST, self.archive)

    def test_native_archive_missing_or_modified_never_reuses_receipt(self):
        self.seal()
        value = self.read_receipt()
        path = self.root / value["workspace_oci"]["file"]
        path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "archive file"):
            artifact.reuse(self.root, self.receipt, native=True)
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            artifact.reuse(self.root, self.receipt, native=True)

    def test_native_archive_receipt_fields_cannot_redirect_input(self):
        self.seal()
        original = self.read_receipt()
        for field, changed in (("file", "../outside.oci.tar"), ("sha256", "../outside"),
                               ("size", 1), ("source_digest", BASE_DIGEST)):
            value = copy.deepcopy(original)
            value["workspace_oci"][field] = changed
            self.write_receipt(value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                artifact.reuse(self.root, self.receipt, native=True)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="workspace-oci-tests-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "image.tar"
        self.source_digest = write_archive(self.archive)

    def test_archive_binds_wrapper_bytes_native_manifest_and_verified_config(self):
        result = artifact.archive_identity(self.archive, IMAGE_ID, "amd64")
        self.assertEqual(result["source_digest"], self.source_digest)
        self.assertEqual(result["sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual(result["size"], self.archive.stat().st_size)

    def test_containerd_manifest_image_id_binds_the_same_verified_archive(self):
        self.assertEqual(artifact.archive_identity(self.archive, self.source_digest, "amd64"),
                         artifact.archive_identity(self.archive, IMAGE_ID, "amd64"))

    def test_wrong_docker_image_or_architecture_is_rejected(self):
        for image_id, arch in ((OTHER_IMAGE_ID, "amd64"), (IMAGE_ID, "arm64")):
            with self.subTest(image=image_id, architecture=arch), self.assertRaises(ValueError):
                artifact.archive_identity(self.archive, image_id, arch)

    def test_nonprivate_linked_or_oversized_archives_are_rejected(self):
        self.archive.chmod(0o600)
        with self.assertRaises(ValueError):
            artifact.archive_identity(self.archive, IMAGE_ID, "amd64")
        self.archive.chmod(0o400)
        with mock.patch.object(artifact, "MAXIMUM_ARCHIVE_BYTES", 1), self.assertRaises(ValueError):
            artifact.archive_identity(self.archive, IMAGE_ID, "amd64")
        link = self.root / "linked"
        link.symlink_to(self.archive)
        with self.assertRaises(ValueError):
            artifact.archive_identity(link, IMAGE_ID, "amd64")
        link.unlink()
        os.link(self.archive, link)
        with self.assertRaises(ValueError):
            artifact.archive_identity(self.archive, IMAGE_ID, "amd64")

    def test_bad_layout_missing_corrupt_and_traversing_documents_fail_closed(self):
        for mutation in ("layout", "missing", "corrupt", "traversal", "extra-root"):
            def change(entries):
                if mutation == "layout":
                    entries["oci-layout"] = b'{"imageLayoutVersion":"2.0.0"}'
                elif mutation == "missing":
                    del entries["blobs/sha256/" + IMAGE_ID[7:]]
                elif mutation == "corrupt":
                    entries["blobs/sha256/" + IMAGE_ID[7:]] = b"{}"
                elif mutation == "traversal":
                    entries["../outside"] = b"never extracted"
                else:
                    entries["unexpected"] = b"never extracted"
            self.archive.unlink()
            write_archive(self.archive, change=change)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                artifact.archive_identity(self.archive, IMAGE_ID, "amd64")
        self.assertFalse((self.root.parent / "outside").exists())


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


class CwCopyTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("cw_image_fixtures.py")
        spec = importlib.util.spec_from_file_location("workspace_cw_real_fixture", path)
        self.fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.fixture)
        temporary = tempfile.TemporaryDirectory(prefix="workspace-cw-copy-test-", dir=HELPER.parents[3] / ".tmp")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "source"
        self.source = self.fixture.create_source(self.root)
        self.work = self.base / "cw-image-work"
        self.work.mkdir(mode=0o700)
        self.original = self.fixture.make_producer(self.root, self.work / "build")
        self.reference = self.work / "cw-producer-result.json"
        self.fixture.write(self.reference, self.fixture.release.canonical(self.original), 0o400)
        self.settings = self.base / "settings.json"
        self.log = self.base / "docker.jsonl"
        self.fake = self.base / "docker"
        self.image = {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64", "Config": {"Labels": {
            "org.opencontainers.image.revision": self.source["source_sha"],
            "dev.codewire.source-tree": self.source["source_tree"],
            "dev.codewire.workspace-contract": hashlib.sha256(
                (self.root / "scripts/ci/verify/workspace-agent-contract.sh").read_bytes()).hexdigest(),
            "dev.codewire.promotable": "false", "dev.codewire.build.profile": "workspace-verify",
        }}}
        self.options = {"mode": "ok", "active": False, "image": self.image}
        self.configure()
        self.fake.write_text("#!/usr/bin/python3\n" + FAKE_CW_DOCKER.replace(
            "SETTINGS_PATH", repr(str(self.settings))).replace("LOG_PATH", repr(str(self.log))).replace(
            "PAYLOAD_PATH", repr(str(self.work / "build/assets/cw"))).replace(
            "REFERENCE_PATH", repr(str(self.reference))), encoding="utf-8")
        self.fake.chmod(0o700)
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.base), "LC_ALL": "C", "TZ": "UTC",
                       "CODEWIRE_DOCKER_BIN": str(self.fake), "PYTHONDONTWRITEBYTECODE": "1"}
        patch = mock.patch.dict(os.environ, environment, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def configure(self, **changes):
        self.options.update(changes)
        self.settings.write_text(json.dumps(self.options), encoding="utf-8")
        self.settings.chmod(0o600)

    def verify(self):
        return artifact.verify_cw(self.root, IMAGE_ID, self.reference)

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def assert_no_effects(self):
        self.assertFalse(self.log.exists())
        self.assertEqual(list(self.work.glob(".workspace-cw-copy-*")), [])

    def assert_closed(self):
        try:
            os.waitpid(-1, os.WNOHANG | 0x40000000)
        except ChildProcessError:
            return
        self.fail("copy did not prove all-child ECHILD")

    def test_real_reopen_and_installed_bytes_preserve_original_and_current_source(self):
        before = self.reference.read_bytes()
        result = self.verify()
        self.assertEqual(result["status"], "workspace-cw-verified")
        self.assertEqual(result["payload"], self.original["payload"])
        self.assertEqual(result["source"], self.original["source"])
        self.assertEqual(result["current_source"]["revision"], self.source["source_sha"])
        self.assertEqual(result["producer_receipt_sha256"], self.original["receipt"]["sha256"])
        self.assertEqual(self.reference.read_bytes(), before)
        self.assertTrue(result["family_cleanup_known"] and result["container_cleanup_known"])
        commands = self.commands()
        self.assertEqual([c["arguments"][0] for c in commands], ["image", "run", "container"])
        run = commands[1]
        self.assertIn("--pull=never", run["arguments"])
        self.assertIn("--network=none", run["arguments"])
        self.assertIn("--read-only", run["arguments"])
        self.assertEqual(run["arguments"][-2:], [IMAGE_ID, "/usr/local/bin/cw"])
        self.assertEqual(run["arguments"][run["arguments"].index("--entrypoint") + 1], "/usr/bin/cat")
        self.assertEqual(run["arguments"][run["arguments"].index("--user") + 1], "1000:1000")
        self.assert_closed()

    def test_normal_python_default_cannot_write_bytecode_into_admitted_source(self):
        self.assertEqual(list(self.root.rglob("__pycache__")), [])
        self.assertEqual(list((self.work / "build").rglob("__pycache__")), [])
        with mock.patch.object(sys, "dont_write_bytecode", False):
            self.assertEqual(self.verify()["status"], "workspace-cw-verified")
            self.assertFalse(sys.dont_write_bytecode)
        self.assertEqual(list(self.root.rglob("__pycache__")), [])
        self.assertEqual(list((self.work / "build").rglob("__pycache__")), [])
        self.assert_closed()

    def test_copied_wrong_truncated_extended_and_oversize_bytes_fail(self):
        for mode in ("wrong", "short", "long", "oversize"):
            with self.subTest(mode=mode):
                self.configure(mode=mode)
                with self.assertRaises(ValueError):
                    self.verify()
                self.assert_closed()
                outcome = json.loads(sorted(self.work.glob(".workspace-cw-copy-*"),
                                            key=lambda p: p.stat().st_mtime_ns)[-1].joinpath("outcome.json").read_bytes())
                self.assertFalse(outcome["accepted"])
                self.assertTrue(outcome["container_cleanup_known"])

    def test_bad_original_receipt_pin_refuses_before_copy(self):
        value = copy.deepcopy(self.original)
        value["receipt"]["sha256"] = "0" * 64
        self.reference.chmod(0o600)
        self.reference.write_bytes(self.fixture.release.canonical(value))
        self.reference.chmod(0o400)
        with self.assertRaises(ValueError):
            self.verify()
        self.assert_no_effects()

    def test_reference_closed_fields_and_profile_version_are_not_authority(self):
        for key, value in (("profile", "ci"), ("version", "1.0.0"),
                           ("cache_qualified", True), ("unexpected", True)):
            changed = self.original | {key: value}
            self.reference.chmod(0o600)
            self.reference.write_bytes(self.fixture.release.canonical(changed))
            self.reference.chmod(0o400)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()
            self.assert_no_effects()

    def test_effective_version_and_current_source_are_reopened(self):
        with mock.patch.dict(os.environ, {"CODEWIRE_VERSION": "2.0.0"}), self.assertRaises(ValueError):
            self.verify()
        self.assert_no_effects()
        changed = self.root / "crates/demo/src/lib.rs"
        changed.write_bytes(b"pub fn changed() {}\n")
        with self.assertRaises(ValueError):
            self.verify()
        self.assert_no_effects()

    def test_docs_only_head_preserves_original_compilation_identity(self):
        self.fixture.write(self.root / "README.fixture", b"not a compiler input\n", 0o644)
        self.fixture.source.git(self.root, ["add", "README.fixture"])
        self.fixture.source.git(self.root, ["-c", "user.name=Synthetic", "-c",
            "user.email=synthetic@example.invalid", "commit", "-q", "-m", "docs-only fixture"])
        head = self.fixture.source.git(self.root, ["rev-parse", "HEAD"]).strip().decode()
        tree = self.fixture.source.git(self.root, ["rev-parse", "HEAD^{tree}"]).strip().decode()
        self.image["Config"]["Labels"].update({"org.opencontainers.image.revision": head,
                                              "dev.codewire.source-tree": tree})
        self.configure(image=self.image)
        result = self.verify()
        self.assertNotEqual(head, self.original["source"]["revision"])
        self.assertEqual(result["source"], self.original["source"])
        self.assertEqual(result["payload"]["source_revision"], self.original["source"]["revision"])
        self.assertEqual(result["current_source"]["revision"], head)
        self.assert_closed()

    def test_changed_original_export_cannot_become_a_fresh_admission(self):
        cw = self.work / "build/assets/cw"
        cw.chmod(0o600)
        cw.write_bytes(cw.read_bytes() + b"x")
        cw.chmod(0o500)
        with self.assertRaises(ValueError):
            self.verify()
        self.assert_no_effects()

    def test_wrong_image_source_label_is_refused_before_copy(self):
        self.image["Config"]["Labels"]["org.opencontainers.image.revision"] = "0" * 40
        self.configure(image=self.image)
        with self.assertRaisesRegex(ValueError, "source identity mismatch"):
            self.verify()
        self.assertEqual([c["arguments"][0] for c in self.commands()], ["image"])
        self.assert_closed()

    def test_reference_nofollow_single_link_and_private_mode(self):
        self.reference.chmod(0o600)
        with self.assertRaises(ValueError):
            self.verify()
        self.reference.chmod(0o400)
        alias = self.base / "alias"
        os.link(self.reference, alias)
        with self.assertRaises(ValueError):
            self.verify()
        alias.unlink()
        self.reference.rename(alias)
        self.reference.symlink_to(alias)
        with self.assertRaises((ValueError, OSError)):
            self.verify()
        self.assert_no_effects()

    def test_reference_replacement_during_copy_is_refused(self):
        self.configure(mode="replace-reference")
        with self.assertRaises(ValueError):
            self.verify()
        self.assert_closed()

    def test_missing_malformed_and_symlink_cid_cannot_qualify_copy(self):
        for mode in ("missing-cid", "bad-cid", "symlink-cid"):
            self.configure(mode=mode)
            with self.subTest(mode=mode), self.assertRaises((ValueError, OSError)):
                self.verify()
            self.assert_closed()

    def test_arm_static_claim_refuses_before_docker(self):
        with mock.patch.object(artifact.platform, "machine", return_value="aarch64"), self.assertRaises(ValueError):
            self.verify()
        self.assert_no_effects()

    def test_failed_and_excess_stderr_commands_fail_without_rendering_content(self):
        for mode in ("fail", "stderr-oversize"):
            self.configure(mode=mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError) as error:
                self.verify()
            self.assertNotIn("CW_SYNTHETIC_SECRET_MUST_NOT_RENDER", str(error.exception))
            self.assert_closed()

    def test_deadline_kills_only_owned_command_and_proves_cleanup(self):
        self.configure(mode="stall")
        started = time.monotonic()
        with mock.patch.object(artifact, "CW_COPY_SECONDS", 0.5), self.assertRaises(ValueError):
            self.verify()
        self.assertLess(time.monotonic() - started, 5)
        self.assert_closed()

    def test_cancelled_copy_cannot_publish_positive_outcome(self):
        self.configure(mode="cancel")
        with self.assertRaises(ValueError):
            self.verify()
        self.assert_closed()
        for path in self.work.glob(".workspace-cw-copy-*/outcome.json"):
            self.assertFalse(json.loads(path.read_bytes())["accepted"])

    def test_detached_term_resistant_descendant_is_failure_even_after_reaping(self):
        self.configure(mode="detach")
        with self.assertRaisesRegex(ValueError, "unexpected family"):
            self.verify()
        self.assert_closed()

    def test_private_docker_config_cannot_be_replaced_or_populated(self):
        self.configure(mode="tamper-config")
        with self.assertRaisesRegex(ValueError, "configuration is not empty"):
            self.verify()
        self.assert_closed()

    def test_exact_owned_leftover_is_removed_before_success(self):
        self.configure(mode="leftover")
        self.verify()
        commands = self.commands()
        self.assertEqual([c["arguments"][0] for c in commands],
                         ["image", "run", "container", "container", "rm", "container"])
        self.assertEqual(commands[4]["arguments"], ["rm", "--force", "a" * 64])
        self.assert_closed()

    def test_foreign_container_and_unknown_cleanup_refuse_without_deleting(self):
        for mode in ("foreign", "cleanup-fail"):
            self.configure(mode=mode, active=False)
            before = len(self.commands())
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.verify()
            self.assertFalse(any(c["arguments"][0] == "rm" for c in self.commands()[before:]))
            self.assert_closed()
            outcome = json.loads(sorted(self.work.glob(".workspace-cw-copy-*"),
                                        key=lambda p: p.stat().st_mtime_ns)[-1].joinpath("outcome.json").read_bytes())
            self.assertFalse(outcome["accepted"] or outcome["container_cleanup_known"])

    def test_docker_environment_has_only_private_config_and_selected_transport(self):
        with mock.patch.dict(os.environ, {"CODEWIRE_SCCACHE_CREDENTIALS_FILE": "CW_SYNTHETIC_SECRET_MUST_NOT_RENDER",
                                         "ANTHROPIC_API_KEY": "CW_SYNTHETIC_SECRET_MUST_NOT_RENDER",
                                         "HTTP_PROXY": "http://synthetic.invalid", "DOCKER_HOST": "unix:///run/docker.sock"}):
            self.verify()
        for command in self.commands():
            env = command["environment"]
            self.assertEqual(set(env), {"PATH", "HOME", "DOCKER_CONFIG", "TMPDIR", "LC_ALL", "TZ", "DOCKER_HOST"})
            self.assertEqual(env["DOCKER_HOST"], "unix:///run/docker.sock")
            self.assertEqual(list(Path(env["DOCKER_CONFIG"]).iterdir()), [])
            self.assertTrue(str(Path(env["HOME"]).parent).startswith(str(self.work)))


FAKE_CW_DOCKER = r'''
import hashlib,json,os,re,signal,sys,time
from pathlib import Path
settings_path=Path(SETTINGS_PATH)
settings=json.loads(settings_path.read_bytes())
arguments=sys.argv[1:]
with Path(LOG_PATH).open('a') as log:
    log.write(json.dumps({'arguments':arguments,'environment':dict(os.environ)},sort_keys=True)+'\n')
mode=settings['mode']
cid='a'*64
if arguments[:2]==['image','inspect']:
    assert arguments==['image','inspect',settings['image']['Id']]
    print(json.dumps([settings['image']]))
elif arguments[:1]==['run']:
    assert len(arguments)==17
    assert arguments[:7]==['run','--rm','--pull=never','--network=none','--read-only','--user','1000:1000']
    assert arguments[7]=='--name' and re.fullmatch('codewire-workspace-cw-[0-9a-f]{32}',arguments[8])
    assert arguments[9]=='--cidfile' and arguments[11]=='--label'
    assert arguments[12]=='dev.codewire.workspace-cw-verification='+arguments[8].split('-')[-1]
    assert arguments[13:]==['--entrypoint','/usr/bin/cat',settings['image']['Id'],'/usr/local/bin/cw']
    path=Path(arguments[10])
    if mode=='symlink-cid': path.symlink_to(PAYLOAD_PATH)
    elif mode!='missing-cid':
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.write(fd,b'malformed' if mode=='bad-cid' else cid.encode());os.close(fd)
    settings.update(name=arguments[8],token=arguments[8].split('-')[-1],active=mode in ('leftover','foreign'))
    settings_path.write_text(json.dumps(settings))
    data=Path(PAYLOAD_PATH).read_bytes()
    if mode=='wrong': data=data[:-1]+bytes([data[-1]^1])
    if mode=='short': data=data[:-1]
    if mode=='long': data+=b'x'
    if mode=='oversize': data+=b'xx'
    if mode=='fail':
        print('CW_SYNTHETIC_SECRET_MUST_NOT_RENDER',file=sys.stderr);sys.exit(47)
    if mode=='stderr-oversize':
        sys.stderr.buffer.write(b'e'*(64*1024+1));sys.stderr.buffer.flush()
    if mode=='stall': time.sleep(60)
    if mode=='detach':
        child=os.fork()
        if child==0:
            os.setsid()
            grandchild=os.fork()
            if grandchild: os._exit(0)
            signal.signal(signal.SIGTERM,signal.SIG_IGN)
            for fd in (0,1,2): os.close(fd)
            time.sleep(60);os._exit(0)
        os.waitpid(child,0)
    if mode=='tamper-config':
        Path(os.environ['DOCKER_CONFIG']).joinpath('config.json').write_text('{"auths":{}}')
    if mode=='replace-reference':
        reference=Path(REFERENCE_PATH);other=reference.with_name('replaced.json')
        other.write_bytes(reference.read_bytes());other.chmod(0o400);other.replace(reference)
    if mode=='cancel': os.kill(os.getppid(),signal.SIGTERM)
    sys.stdout.buffer.write(data)
elif arguments[:2]==['container','ls']:
    assert arguments[2:5]==['--all','--no-trunc','--filter']
    assert arguments[5]=='name=^/'+settings['name']+'$' and arguments[6:]==['--format','{{.ID}}']
    if mode=='cleanup-fail': sys.exit(48)
    if settings['active']: print(cid)
elif arguments[:2]==['container','inspect']:
    assert arguments==['container','inspect',cid]
    print(json.dumps([{'Id':cid,'Image':settings['image']['Id'],'Name':'/'+settings['name'],
        'Config':{'Image':settings['image']['Id'],'Labels':{'dev.codewire.workspace-cw-verification':
            'foreign' if mode=='foreign' else settings['token']}}}]))
elif arguments[:1]==['rm']:
    assert arguments==['rm','--force',cid] and mode=='leftover'
    settings['active']=False;settings_path.write_text(json.dumps(settings));print(cid)
else:
    raise AssertionError('unsupported fake Docker operation')
'''


if __name__ == "__main__":
    unittest.main()
