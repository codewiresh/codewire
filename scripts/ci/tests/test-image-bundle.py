#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "image_bundle", ROOT / "scripts" / "ci" / "images" / "image-bundle.py"
)
assert SPEC is not None and SPEC.loader is not None
image_bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image_bundle)

SOURCE_SHA = "a" * 40
DIGESTS = {
    family: f"sha256:{str(index) * 64}"
    for index, family in enumerate(image_bundle.FAMILIES, start=1)
}


def candidates(source_sha: str = SOURCE_SHA) -> list[list[str]]:
    return [
        [
            family,
            source_sha,
            f"nexus-system-cluster.example.invalid/oci-promoted/codewire/{family}@{DIGESTS[family]}",
        ]
        for family in image_bundle.FAMILIES
    ]


class ImageBundleTests(unittest.TestCase):
    def assert_rejected(self, value: object) -> None:
        with self.assertRaises(image_bundle.BundleError):
            image_bundle.validate_bundle(value)

    def test_complete_candidate_set_creates_exact_ordered_bundle(self) -> None:
        value = image_bundle._create_bundle(SOURCE_SHA, candidates())
        self.assertNotIn("environment", value)
        self.assertEqual(value["source"]["sha"], SOURCE_SHA)
        self.assertEqual(
            [image["family"] for image in value["images"]],
            list(image_bundle.FAMILIES),
        )
        self.assertEqual(len(value["images"]), 5)

    def test_production_bundle_requires_explicit_environment(self) -> None:
        value = image_bundle._create_bundle(SOURCE_SHA, candidates(), "prod")
        self.assertEqual(value["environment"], "prod")

        omitted = copy.deepcopy(value)
        del omitted["environment"]
        self.assertEqual(
            image_bundle.validate_bundle(omitted).get("environment", "dev"),
            "dev",
        )

    def test_unknown_environment_is_rejected(self) -> None:
        value = image_bundle._create_bundle(SOURCE_SHA, candidates())
        value["environment"] = "production"
        self.assert_rejected(value)

    def test_missing_candidate_is_rejected(self) -> None:
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, candidates()[:-1])

    def test_duplicate_candidate_is_rejected(self) -> None:
        values = candidates()
        values[-1] = copy.deepcopy(values[0])
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_unknown_candidate_is_rejected(self) -> None:
        values = candidates()
        values[-1][0] = "worker"
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_reordered_candidate_set_is_rejected(self) -> None:
        values = candidates()
        values[0], values[1] = values[1], values[0]
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_split_source_candidate_is_rejected(self) -> None:
        values = candidates()
        values[2][1] = "b" * 40
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_mutable_candidate_reference_is_rejected(self) -> None:
        values = candidates()
        values[0][2] = "nexus-system-cluster.example.invalid/oci-promoted/codewire/dashboard:latest"
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_wrong_family_repository_is_rejected(self) -> None:
        values = candidates()
        values[0][2] = values[1][2]
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_create_is_deterministic_and_round_trips_validation(self) -> None:
        value = image_bundle._create_bundle(SOURCE_SHA, candidates())
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            image_bundle._write_bundle(first, value)
            image_bundle._write_bundle(second, value)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(image_bundle.load_bundle(first), value)

    def test_boundary_requires_a_new_exact_source(self) -> None:
        old = image_bundle._create_bundle(SOURCE_SHA, candidates())
        changed_digest = copy.deepcopy(old)
        changed_digest["images"][0]["ref"] = (
            "nexus-system-cluster.example.invalid/oci-promoted/codewire/dashboard@sha256:" + "f" * 64
        )
        with self.assertRaises(image_bundle.BundleError):
            image_bundle.validate_boundary(old, changed_digest)

        new_source = "b" * 40
        new = image_bundle._create_bundle(new_source, candidates(new_source))
        image_bundle.validate_boundary(old, new)

        prod = image_bundle._create_bundle(
            new_source, candidates(new_source), "prod"
        )
        with self.assertRaises(image_bundle.BundleError):
            image_bundle.validate_boundary(old, prod)

    def test_buildx_metadata_emits_exact_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            metadata.write_text(
                json.dumps({"containerimage.digest": DIGESTS["gateway"]}),
                encoding="utf-8",
            )
            self.assertEqual(
                image_bundle._candidate_from_metadata(
                    "gateway", SOURCE_SHA,
                    "nexus-system-cluster.example.invalid/oci-promoted/codewire",
                    metadata,
                ),
                (
                    "gateway",
                    SOURCE_SHA,
                    f"nexus-system-cluster.example.invalid/oci-promoted/codewire/gateway@{DIGESTS['gateway']}",
                ),
            )

    def test_buildx_metadata_emits_support_image_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            digest = "sha256:" + "f" * 64
            metadata.write_text(
                json.dumps({"containerimage.digest": digest}),
                encoding="utf-8",
            )
            self.assertEqual(
                image_bundle._candidate_from_metadata(
                    "workspace", SOURCE_SHA,
                    "nexus-system-cluster.example.invalid/oci-promoted/codewire",
                    metadata,
                ),
                (
                    "workspace",
                    SOURCE_SHA,
                    f"nexus-system-cluster.example.invalid/oci-promoted/codewire/workspace@{digest}",
                ),
            )

    def test_buildx_metadata_emits_confidential_probe_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            digest = "sha256:" + "f" * 64
            metadata.write_text(
                json.dumps({"containerimage.digest": digest}),
                encoding="utf-8",
            )
            self.assertEqual(
                image_bundle._candidate_from_metadata(
                    "confidential-probe",
                    SOURCE_SHA,
                    "nexus-system-cluster.example.invalid/oci-promoted/codewire",
                    metadata,
                ),
                (
                    "confidential-probe",
                    SOURCE_SHA,
                    "nexus-system-cluster.example.invalid/oci-promoted/codewire/confidential-probe@"
                    + digest,
                ),
            )

    def test_support_images_do_not_expand_runtime_bundle(self) -> None:
        values = candidates()
        values[-1] = [
            "workspace",
            SOURCE_SHA,
            "nexus-system-cluster.example.invalid/oci-promoted/codewire/workspace@sha256:" + "f" * 64,
        ]
        with self.assertRaises(image_bundle.BundleError):
            image_bundle._create_bundle(SOURCE_SHA, values)

    def test_buildx_metadata_without_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            metadata.write_text("{}", encoding="utf-8")
            with self.assertRaises(image_bundle.BundleError):
                image_bundle._candidate_from_metadata(
                    "gateway", SOURCE_SHA, "unapproved.example/oci", metadata
                )

    def test_candidate_for_other_registry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "metadata.json"
            metadata.write_text(
                json.dumps({"containerimage.digest": DIGESTS["gateway"]}),
                encoding="utf-8",
            )
            with self.assertRaises(image_bundle.BundleError):
                image_bundle._candidate_from_metadata(
                    "gateway", SOURCE_SHA, "registry.invalid", metadata
                )


if __name__ == "__main__":
    unittest.main()
