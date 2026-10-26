from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ADAPTER = Path(__file__).parents[1] / "apply-support-plan.py"
HEAD = "a" * 40
TREE = "b" * 40
BASE = "c" * 40
BASE_DIGEST = "sha256:" + "1" * 64
WORKSPACE_DIGEST = "sha256:" + "2" * 64


def plan_document(
    base_state: str = "unaffected",
    workspace_state: str = "unaffected",
    confidential_probe_state: str = "unaffected",
    *,
    baseline_valid: bool = True,
) -> dict:
    return {
        "schema": "codewire.ci-plan/v1",
        "trusted_policy": {
            "commit": HEAD,
            "policy_sha256": "d" * 64,
            "graph_sha256": "e" * 64,
        },
        "baseline": {
            "schema": "codewire.ci-baseline/v1",
            "mode": "published_support_pair",
            "target_base_commit": HEAD,
            "baseline_commit": BASE if baseline_valid else HEAD,
            "head_commit": HEAD,
            "head_tree": TREE,
            "provenance": {
                "provider": "ghcr",
                "images": {
                    "base": {"digest": BASE_DIGEST, "revision": BASE if baseline_valid else None},
                    "workspace": {"digest": WORKSPACE_DIGEST, "revision": BASE if baseline_valid else None},
                },
            },
            "validation": {
                "valid": baseline_valid,
                "reasons": [] if baseline_valid else ["candidate unavailable"],
            },
        },
        "artifacts": {
            "base_image": {"state": base_state},
            "workspace_image": {"state": workspace_state},
            "confidential_probe_image": {"state": confidential_probe_state},
        },
        "degraded_reasons": [],
    }


class SupportPlanAdapterTests(unittest.TestCase):
    def apply(self, document: object, *, head: str = HEAD, tree: str = TREE) -> tuple[dict[str, str], str]:
        with tempfile.TemporaryDirectory(prefix="codewire-support-adapter-test-") as temporary:
            plan = Path(temporary) / "plan.json"
            plan.write_text(json.dumps(document, sort_keys=True) + "\n")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ADAPTER),
                    "--plan",
                    str(plan),
                    "--head",
                    head,
                    "--head-tree",
                    tree,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return (
            dict(line.split("=", 1) for line in completed.stdout.splitlines()),
            completed.stderr,
        )

    def test_unaffected_artifacts_skip_publication(self) -> None:
        outputs, _ = self.apply(plan_document())
        self.assertEqual(outputs["build_support_images"], "false")
        self.assertEqual(outputs["reason"], "artifacts_unaffected")
        self.assertEqual(outputs["baseline_sha"], BASE)

    def test_unaffected_pair_is_aliased_from_the_validated_published_pair(self) -> None:
        outputs, _ = self.apply(plan_document())
        self.assertEqual(outputs["alias_support_pair"], "true")
        self.assertEqual(outputs["alias_source_sha"], BASE)
        self.assertEqual(outputs["alias_base_digest"], BASE_DIGEST)
        self.assertEqual(outputs["alias_workspace_digest"], WORKSPACE_DIGEST)

        # A probe-only change still leaves the pair to the alias.
        outputs, _ = self.apply(plan_document(confidential_probe_state="affected"))
        self.assertEqual(outputs["build_support_images"], "false")
        self.assertEqual(outputs["alias_support_pair"], "true")

    def test_alias_refuses_when_inputs_differ_so_the_pair_builds(self) -> None:
        for states in (
            {"base_state": "affected"},
            {"workspace_state": "affected"},
            {"workspace_state": "unclassified"},
        ):
            outputs, _ = self.apply(plan_document(**states))
            self.assertEqual(outputs["build_support_images"], "true", states)
            self.assertEqual(outputs["alias_support_pair"], "false", states)
            self.assertEqual(outputs["alias_source_sha"], "", states)
            self.assertEqual(outputs["alias_base_digest"], "", states)
            self.assertEqual(outputs["alias_workspace_digest"], "", states)

    def test_alias_refuses_without_a_published_pair_so_the_pair_builds(self) -> None:
        outputs, _ = self.apply(
            plan_document("unclassified", "unclassified", "unclassified", baseline_valid=False)
        )
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["alias_support_pair"], "false")

    def test_a_head_that_is_its_own_published_pair_needs_no_alias(self) -> None:
        document = plan_document()
        document["baseline"]["baseline_commit"] = HEAD
        for image in document["baseline"]["provenance"]["images"].values():
            image["revision"] = HEAD
        outputs, _ = self.apply(document)
        self.assertEqual(outputs["build_support_images"], "false")
        self.assertEqual(outputs["alias_support_pair"], "false")

    def test_alias_without_exact_validated_digests_fails_closed_to_a_build(self) -> None:
        for mutate in (
            lambda images: images.pop("workspace"),
            lambda images: images["base"].update(digest="sha256:short"),
            lambda images: images["workspace"].update(revision="f" * 40),
        ):
            document = plan_document()
            mutate(document["baseline"]["provenance"]["images"])
            outputs, error = self.apply(document)
            self.assertEqual(outputs["build_support_images"], "true")
            self.assertEqual(outputs["alias_support_pair"], "false")
            self.assertEqual(outputs["reason"], "plan_invalid")
            self.assertIn("selecting the atomic pair", error)

    def test_either_affected_artifact_selects_atomic_pair(self) -> None:
        outputs, _ = self.apply(plan_document(base_state="affected"))
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["reason"], "artifact_affected")
        self.assertEqual(outputs["workspace_image_state"], "unaffected")

    def test_confidential_probe_is_selected_independently(self) -> None:
        outputs, _ = self.apply(plan_document(confidential_probe_state="affected"))
        self.assertEqual(outputs["build_support_images"], "false")
        self.assertEqual(outputs["build_confidential_probe_image"], "true")
        self.assertEqual(outputs["confidential_probe_image_state"], "affected")
        self.assertEqual(outputs["reason"], "artifact_affected")

    def test_unclassified_artifact_selects_atomic_pair(self) -> None:
        outputs, _ = self.apply(plan_document(workspace_state="unclassified"))
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["reason"], "artifact_unclassified")

    def test_content_verification_does_not_replace_exact_source_publication(self) -> None:
        document = plan_document(workspace_state="affected")
        document["artifacts"]["workspace_image_verification"] = {"state": "unaffected"}
        outputs, _ = self.apply(document)
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["workspace_image_state"], "affected")

        document = plan_document()
        document["artifacts"]["workspace_image_verification"] = {"state": "affected"}
        outputs, _ = self.apply(document)
        self.assertEqual(outputs["build_support_images"], "false")

    def test_invalid_baseline_requires_all_artifacts_unclassified(self) -> None:
        outputs, _ = self.apply(
            plan_document(
                "unclassified",
                "unclassified",
                "unclassified",
                baseline_valid=False,
            )
        )
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["reason"], "baseline_invalid")
        self.assertEqual(outputs["baseline_valid"], "false")

    def test_malformed_or_wrong_head_plan_fails_closed(self) -> None:
        malformed, malformed_error = self.apply({"schema": "wrong"})
        self.assertEqual(malformed["build_support_images"], "true")
        self.assertEqual(malformed["reason"], "plan_invalid")
        self.assertIn("selecting the atomic pair", malformed_error)

        wrong_head = plan_document()
        wrong_head["baseline"]["head_commit"] = "f" * 40
        outputs, _ = self.apply(wrong_head)
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["head_sha"], HEAD)
        self.assertEqual(outputs["head_tree"], TREE)

        wrong_target = plan_document()
        wrong_target["baseline"]["target_base_commit"] = "f" * 40
        outputs, _ = self.apply(wrong_target)
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["reason"], "plan_invalid")


if __name__ == "__main__":
    unittest.main()
