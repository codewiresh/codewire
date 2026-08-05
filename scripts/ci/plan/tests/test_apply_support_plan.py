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


def plan_document(
    base_state: str = "unaffected",
    workspace_state: str = "unaffected",
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
            "provenance": {},
            "validation": {
                "valid": baseline_valid,
                "reasons": [] if baseline_valid else ["candidate unavailable"],
            },
        },
        "verification": {},
        "artifacts": {
            "base_image": {"state": base_state},
            "workspace_image": {"state": workspace_state},
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

    def test_two_unaffected_artifacts_skip_atomic_publication(self) -> None:
        outputs, _ = self.apply(plan_document())
        self.assertEqual(outputs["build_support_images"], "false")
        self.assertEqual(outputs["reason"], "artifacts_unaffected")
        self.assertEqual(outputs["baseline_sha"], BASE)

    def test_either_affected_artifact_selects_atomic_pair(self) -> None:
        outputs, _ = self.apply(plan_document(base_state="affected"))
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["reason"], "artifact_affected")
        self.assertEqual(outputs["workspace_image_state"], "unaffected")

    def test_unclassified_artifact_selects_atomic_pair(self) -> None:
        outputs, _ = self.apply(plan_document(workspace_state="unclassified"))
        self.assertEqual(outputs["build_support_images"], "true")
        self.assertEqual(outputs["reason"], "artifact_unclassified")

    def test_invalid_baseline_requires_both_artifacts_unclassified(self) -> None:
        outputs, _ = self.apply(
            plan_document("unclassified", "unclassified", baseline_valid=False)
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
