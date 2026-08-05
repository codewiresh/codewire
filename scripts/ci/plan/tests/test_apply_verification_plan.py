from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ADAPTER_PATH = Path(__file__).parents[1] / "apply-verification-plan.py"
SPEC = importlib.util.spec_from_file_location("codewire_ci_plan_adapter", ADAPTER_PATH)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
TREE_C = "c" * 40
HASH_D = "d" * 64
HASH_E = "e" * 64


def fixture_plan(
    cw_state: str = "unaffected",
    desktop_state: str = "unaffected",
    workspace_state: str = "unaffected",
) -> dict[str, object]:
    return {
        "schema": "codewire.ci-plan/v1",
        "trusted_policy": {
            "commit": COMMIT_A,
            "policy_sha256": HASH_D,
            "graph_sha256": HASH_E,
        },
        "baseline": {
            "target_base_commit": COMMIT_A,
            "baseline_commit": COMMIT_A,
            "head_commit": COMMIT_B,
            "head_tree": TREE_C,
            "validation": {"valid": True, "reasons": []},
        },
        "artifacts": {
            "cw_cli_release_assets": {"state": cw_state},
            "desktop_package": {"state": desktop_state},
            "workspace_image": {"state": workspace_state},
        },
        "degraded_reasons": [],
    }


class PlanAdapterTests(unittest.TestCase):
    def invoke(self, plan: dict[str, object]) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "plan.json"
            plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n")
            args = argparse.Namespace(
                plan=str(plan_path),
                unclassified=False,
                head=None,
                head_tree=None,
            )
            return adapter.build_outputs(args)

    def test_unaffected_artifacts_are_not_selected(self) -> None:
        outputs = self.invoke(fixture_plan())
        self.assertEqual(outputs["cw_package_selected"], "false")
        self.assertEqual(outputs["desktop_package_selected"], "false")
        self.assertEqual(outputs["workspace_image_selected"], "false")
        self.assertNotIn("selection", outputs)
        self.assertNotIn("selector_version", outputs)

    def test_affected_cw_and_unclassified_desktop_are_selected(self) -> None:
        outputs = self.invoke(fixture_plan("affected", "unclassified"))
        self.assertEqual(outputs["cw_package_selected"], "true")
        self.assertEqual(outputs["desktop_package_selected"], "true")

    def test_affected_workspace_image_is_selected(self) -> None:
        outputs = self.invoke(fixture_plan(workspace_state="affected"))
        self.assertEqual(outputs["workspace_image_state"], "affected")
        self.assertEqual(outputs["workspace_image_selected"], "true")

    def test_invalid_artifact_state_fails_closed(self) -> None:
        with self.assertRaisesRegex(adapter.AdapterError, "invalid state"):
            self.invoke(fixture_plan(desktop_state="maybe"))

    def test_policy_and_baseline_identity_must_match(self) -> None:
        plan = fixture_plan()
        plan["baseline"]["baseline_commit"] = COMMIT_B  # type: ignore[index]
        with self.assertRaisesRegex(adapter.AdapterError, "do not match"):
            self.invoke(plan)

    def test_non_pr_mode_is_explicitly_unclassified(self) -> None:
        args = argparse.Namespace(
            plan=None,
            unclassified=True,
            head=COMMIT_B,
            head_tree=TREE_C,
        )
        outputs = adapter.build_outputs(args)
        self.assertEqual(outputs["cw_package_state"], "unclassified")
        self.assertEqual(outputs["workspace_image_state"], "unclassified")
        self.assertEqual(outputs["workspace_image_selected"], "true")
        self.assertNotIn("selection", outputs)


if __name__ == "__main__":
    unittest.main()
