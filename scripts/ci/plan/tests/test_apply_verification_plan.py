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
        "verification": {
            "legacy_selectors_authoritative": True,
            "rust": True,
            "cw_cli_package": cw_state != "unaffected",
            "desktop_package": desktop_state != "unaffected",
            "workspace_image": workspace_state != "unaffected",
        },
        "artifacts": {
            "cw_cli_release_assets": {"state": cw_state},
            "desktop_package": {"state": desktop_state},
            "workspace_image": {"state": workspace_state},
        },
        "degraded_reasons": [],
    }


class PlanAdapterTests(unittest.TestCase):
    def invoke(self, plan: dict[str, object], selection: str) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = root / "legacy"
            plan_path = root / "plan.json"
            legacy.write_text(f"selector_version=v2\nselection={selection}\n")
            plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n")
            args = argparse.Namespace(
                legacy_output=str(legacy),
                plan=str(plan_path),
                unclassified=False,
                trusted_policy=None,
                target_base=None,
                baseline=None,
                head=None,
                head_tree=None,
            )
            return adapter.build_outputs(args)

    def test_unaffected_artifacts_remove_legacy_desktop_false_positive(self) -> None:
        outputs = self.invoke(
            fixture_plan(),
            "|valid:v2|policy|rust|rust_pkg_codewire_desktop|service_billing|complete|",
        )
        self.assertEqual(outputs["cw_package_selected"], "false")
        self.assertEqual(outputs["desktop_package_selected"], "false")
        self.assertEqual(outputs["workspace_image_selected"], "false")
        self.assertEqual(outputs["selection"], "|valid:v2|policy|rust|service_billing|complete|")

    def test_affected_cw_and_unclassified_desktop_are_selected(self) -> None:
        outputs = self.invoke(
            fixture_plan("affected", "unclassified"),
            "|valid:v2|service_billing|complete|",
        )
        self.assertEqual(outputs["cw_package_selected"], "true")
        self.assertEqual(outputs["desktop_package_selected"], "true")
        self.assertEqual(
            outputs["selection"],
            "|valid:v2|policy|rust|rust_pkg_codewire_desktop|service_billing|complete|",
        )

    def test_affected_workspace_image_is_selected(self) -> None:
        outputs = self.invoke(
            fixture_plan(workspace_state="affected"),
            "|valid:v2|policy|complete|",
        )
        self.assertEqual(outputs["workspace_image_state"], "affected")
        self.assertEqual(outputs["workspace_image_selected"], "true")

    def test_plan_verification_boolean_cannot_override_artifact_state(self) -> None:
        plan = fixture_plan()
        plan["verification"]["cw_cli_package"] = True  # type: ignore[index]
        with self.assertRaisesRegex(adapter.AdapterError, "disagrees"):
            self.invoke(plan, "|valid:v2|policy|complete|")

    def test_workspace_verification_boolean_cannot_override_artifact_state(self) -> None:
        plan = fixture_plan()
        plan["verification"]["workspace_image"] = True  # type: ignore[index]
        with self.assertRaisesRegex(adapter.AdapterError, "workspace verification fact disagrees"):
            self.invoke(plan, "|valid:v2|policy|complete|")

    def test_invalid_legacy_selection_fails_closed(self) -> None:
        with self.assertRaisesRegex(adapter.AdapterError, "invalid or incomplete"):
            self.invoke(fixture_plan(), "|valid:v2|policy|")

    def test_non_pr_mode_is_explicitly_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            legacy = Path(temporary) / "legacy"
            legacy.write_text("selector_version=v2\nselection=|valid:v2|policy|complete|\n")
            args = argparse.Namespace(
                legacy_output=str(legacy),
                plan=None,
                unclassified=True,
                trusted_policy=COMMIT_A,
                target_base=COMMIT_A,
                baseline=COMMIT_A,
                head=COMMIT_B,
                head_tree=TREE_C,
            )
            outputs = adapter.build_outputs(args)
        self.assertEqual(outputs["ci_plan_status"], "unclassified")
        self.assertEqual(outputs["cw_package_state"], "unclassified")
        self.assertEqual(outputs["workspace_image_state"], "unclassified")
        self.assertEqual(outputs["workspace_image_selected"], "true")
        self.assertIn("|rust_pkg_codewire_desktop|", outputs["selection"])


if __name__ == "__main__":
    unittest.main()
