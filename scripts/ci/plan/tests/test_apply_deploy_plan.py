from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ADAPTER = Path(__file__).parents[1] / "apply-deploy-plan.py"
HEAD = "a" * 40
TREE = "b" * 40
BASE = "c" * 40
RUNTIME_ARTIFACTS = (
    "dashboard_image",
    "gateway_image",
    "derp_image",
    "services_image",
    "mesh_image",
)
ARTIFACTS = ("dev_release_tree", "dev_acceptance_harness", *RUNTIME_ARTIFACTS)


def plan_document(
    states: dict[str, str] | None = None,
    *,
    baseline_valid: bool = True,
) -> dict:
    effective_states = {name: "unaffected" for name in ARTIFACTS}
    effective_states.update(states or {})
    return {
        "schema": "codewire.ci-plan/v1",
        "trusted_policy": {
            "commit": HEAD,
            "policy_sha256": "d" * 64,
            "graph_sha256": "e" * 64,
        },
        "baseline": {
            "schema": "codewire.ci-baseline/v1",
            "mode": "deployed_source",
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
            name: {"state": effective_states[name]} for name in ARTIFACTS
        },
        "degraded_reasons": [],
    }


class DeployPlanAdapterTests(unittest.TestCase):
    def apply(
        self, document: object, *, head: str = HEAD, tree: str = TREE
    ) -> tuple[dict[str, str], str]:
        return self.apply_raw(
            json.dumps(document, sort_keys=True) + "\n", head=head, tree=tree
        )

    def apply_raw(
        self, raw: str, *, head: str = HEAD, tree: str = TREE
    ) -> tuple[dict[str, str], str]:
        with tempfile.TemporaryDirectory(prefix="codewire-deploy-adapter-test-") as temporary:
            plan = Path(temporary) / "plan.json"
            plan.write_text(raw)
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

    def test_unaffected_release_and_runtime_artifacts_skip_deployment(self) -> None:
        outputs, _ = self.apply(plan_document())
        self.assertEqual(outputs["deploy_dev"], "false")
        self.assertEqual(outputs["reason"], "artifacts_unaffected")
        self.assertEqual(outputs["baseline_sha"], BASE)
        self.assertEqual(outputs["baseline_valid"], "true")

    def test_dev_release_tree_change_selects_atomic_deployment(self) -> None:
        outputs, _ = self.apply(plan_document({"dev_release_tree": "affected"}))
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "dev_release_affected")
        self.assertEqual(outputs["dev_release_tree_state"], "affected")
        self.assertIn("dev_release_tree:affected", outputs["matched_categories"])

    def test_acceptance_harness_change_selects_exact_source_promotion(self) -> None:
        outputs, _ = self.apply(plan_document({"dev_acceptance_harness": "affected"}))
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "dev_acceptance_affected")
        self.assertEqual(outputs["dev_acceptance_harness_state"], "affected")
        self.assertEqual(outputs["dev_release_tree_state"], "unaffected")
        for artifact in RUNTIME_ARTIFACTS:
            self.assertEqual(outputs[f"{artifact}_state"], "unaffected")
        self.assertEqual(
            outputs["matched_categories"],
            "dev_release_tree:unaffected,dev_acceptance_harness:affected,"
            + ",".join(f"{name}:unaffected" for name in RUNTIME_ARTIFACTS),
        )

    def test_acceptance_harness_reason_never_hides_release_or_runtime_changes(self) -> None:
        for states, reason in (
            ({"dev_release_tree": "affected"}, "dev_release_affected"),
            ({"services_image": "affected"}, "artifact_affected"),
            ({"mesh_image": "unclassified"}, "artifact_unclassified"),
        ):
            with self.subTest(states=states):
                outputs, _ = self.apply(
                    plan_document({"dev_acceptance_harness": "affected", **states})
                )
                self.assertEqual(outputs["deploy_dev"], "true")
                self.assertEqual(outputs["reason"], reason)

    def test_unclassified_acceptance_harness_selects_deployment(self) -> None:
        outputs, _ = self.apply(plan_document({"dev_acceptance_harness": "unclassified"}))
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "artifact_unclassified")

    def test_plan_without_acceptance_harness_fact_fails_closed(self) -> None:
        document = plan_document()
        del document["artifacts"]["dev_acceptance_harness"]
        outputs, error = self.apply(document)
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "plan_invalid")
        self.assertIn("plan omits artifact dev_acceptance_harness", error)

    def test_each_affected_artifact_selects_atomic_runtime_set(self) -> None:
        for artifact in RUNTIME_ARTIFACTS:
            with self.subTest(artifact=artifact):
                outputs, _ = self.apply(plan_document({artifact: "affected"}))
                self.assertEqual(outputs["deploy_dev"], "true")
                self.assertEqual(outputs["reason"], "artifact_affected")
                self.assertEqual(outputs[f"{artifact}_state"], "affected")

    def test_unclassified_artifact_selects_atomic_runtime_set(self) -> None:
        outputs, _ = self.apply(plan_document({"mesh_image": "unclassified"}))
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "artifact_unclassified")

    def test_invalid_baseline_requires_every_artifact_unclassified(self) -> None:
        states = {name: "unclassified" for name in ARTIFACTS}
        outputs, _ = self.apply(plan_document(states, baseline_valid=False))
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "baseline_invalid")
        self.assertEqual(outputs["baseline_valid"], "false")

        contradictory, error = self.apply(
            plan_document({"dashboard_image": "unclassified"}, baseline_valid=False)
        )
        self.assertEqual(contradictory["deploy_dev"], "true")
        self.assertEqual(contradictory["reason"], "plan_invalid")
        self.assertIn("selecting the atomic runtime set", error)

    def test_malformed_wrong_head_or_wrong_mode_plan_fails_closed(self) -> None:
        malformed, malformed_error = self.apply({"schema": "wrong"})
        self.assertEqual(malformed["deploy_dev"], "true")
        self.assertEqual(malformed["reason"], "plan_invalid")
        self.assertIn("selecting the atomic runtime set", malformed_error)

        wrong_head = plan_document()
        wrong_head["baseline"]["head_commit"] = "f" * 40
        outputs, _ = self.apply(wrong_head)
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["head_sha"], HEAD)
        self.assertEqual(outputs["head_tree"], TREE)

        wrong_mode = plan_document()
        wrong_mode["baseline"]["mode"] = "published_support_pair"
        outputs, _ = self.apply(wrong_mode)
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "plan_invalid")

    def test_duplicate_plan_keys_fail_closed(self) -> None:
        outputs, error = self.apply_raw(
            '{"schema":"codewire.ci-plan/v1","schema":"wrong"}\n'
        )
        self.assertEqual(outputs["deploy_dev"], "true")
        self.assertEqual(outputs["reason"], "plan_invalid")
        self.assertIn("duplicate JSON key", error)


if __name__ == "__main__":
    unittest.main()
