from __future__ import annotations

import base64
import importlib.util
import json
import sys
import unittest
from pathlib import Path


EMITTER_PATH = Path(__file__).parents[1] / "emit-verification-receipt.py"
SPEC = importlib.util.spec_from_file_location("codewire_ci_receipt_emitter", EMITTER_PATH)
assert SPEC and SPEC.loader
emitter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = emitter
SPEC.loader.exec_module(emitter)


BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40
HASH = "d" * 64


def environment() -> dict[str, str]:
    return {
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY": "codewire/codewire",
        "GITHUB_RUN_ID": "501",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": HEAD,
        "CODEWIRE_PR_NUMBER": "42",
        "CODEWIRE_BASE_COMMIT": BASE,
        "CODEWIRE_HEAD_COMMIT": HEAD,
        "CODEWIRE_HEAD_TREE": TREE,
        "CODEWIRE_POLICY_COMMIT": BASE,
        "CODEWIRE_POLICY_SHA256": HASH,
        "CODEWIRE_GRAPH_SHA256": HASH,
        "CODEWIRE_TARGET_BASE_COMMIT": BASE,
        "CODEWIRE_BASELINE_COMMIT": BASE,
        "CODEWIRE_PLAN_SCHEMA": "codewire.ci-plan/v1",
        "CODEWIRE_PLAN_SHA256": HASH,
        "CODEWIRE_PLAN_STATUS": "trusted",
        "CODEWIRE_CW_PACKAGE_STATE": "unaffected",
        "CODEWIRE_DESKTOP_PACKAGE_STATE": "affected",
        "CODEWIRE_WORKSPACE_IMAGE_STATE": "unaffected",
        "CODEWIRE_SELECTION": "|valid:v3|policy|rust|rust_pkg_codewire_desktop|complete|",
        "CODEWIRE_SELECTION_RESULT": "success",
        "CODEWIRE_STANDARD_RESULT": "success",
        "CODEWIRE_RUST_TRANSPORT_RESULT": "success",
        "CODEWIRE_DATABASE_SERVICES_RESULT": "success",
        "CODEWIRE_EDGE_KIND_RESULT": "success",
        "CODEWIRE_CW_RELEASE_ASSETS_RESULT": "success",
        "CODEWIRE_WORKSPACE_IMAGE_RESULT": "success",
    }


class ReceiptEmitterTests(unittest.TestCase):
    def test_receipt_is_canonical_and_binds_plan_tree_and_results(self) -> None:
        receipt = emitter.build_receipt(environment())
        decoded = json.loads(base64.b64decode(emitter.encode_receipt(receipt)))
        self.assertEqual(decoded, receipt)
        self.assertEqual(receipt["source"]["head_tree"], TREE)
        self.assertEqual(receipt["plan"]["sha256"], HASH)
        self.assertEqual(receipt["results"]["cw_release_assets"], "success")
        self.assertEqual(receipt["results"]["workspace_image"], "success")
        self.assertEqual(receipt["plan"]["artifacts"]["workspace_image"], "unaffected")

    def test_missing_gitea_first_attempt_defaults_to_one(self) -> None:
        env = environment()
        del env["GITHUB_RUN_ATTEMPT"]
        self.assertEqual(emitter.build_receipt(env)["run"]["attempt"], 1)

    def test_explicit_rerun_attempt_is_preserved(self) -> None:
        env = environment()
        env["GITHUB_RUN_ATTEMPT"] = "3"
        self.assertEqual(emitter.build_receipt(env)["run"]["attempt"], 3)

    def test_invalid_run_attempt_remains_fatal(self) -> None:
        env = environment()
        env["GITHUB_RUN_ATTEMPT"] = "0"
        with self.assertRaisesRegex(emitter.ReceiptError, "GITHUB_RUN_ATTEMPT"):
            emitter.build_receipt(env)

    def test_policy_must_be_the_exact_pr_base(self) -> None:
        env = environment()
        env["CODEWIRE_POLICY_COMMIT"] = "e" * 40
        with self.assertRaisesRegex(emitter.ReceiptError, "exact PR base"):
            emitter.build_receipt(env)

    def test_artifact_state_is_orthogonal_to_capability_selection(self) -> None:
        env = environment()
        env["CODEWIRE_SELECTION"] = "|valid:v3|policy|rust|complete|"
        receipt = emitter.build_receipt(env)
        self.assertEqual(receipt["plan"]["artifacts"]["desktop_package"], "affected")
        self.assertNotIn("|rust_pkg_codewire_desktop|", receipt["selection"])

    def test_every_dependency_must_have_succeeded(self) -> None:
        env = environment()
        env["CODEWIRE_CW_RELEASE_ASSETS_RESULT"] = "skipped"
        with self.assertRaisesRegex(emitter.ReceiptError, "concluded skipped"):
            emitter.build_receipt(env)

    def test_workspace_dependency_must_have_succeeded(self) -> None:
        env = environment()
        env["CODEWIRE_WORKSPACE_IMAGE_RESULT"] = "failure"
        with self.assertRaisesRegex(emitter.ReceiptError, "concluded failure"):
            emitter.build_receipt(env)


if __name__ == "__main__":
    unittest.main()
