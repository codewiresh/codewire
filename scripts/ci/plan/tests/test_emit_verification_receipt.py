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
    }


class ReceiptEmitterTests(unittest.TestCase):
    def test_receipt_is_canonical_and_binds_run_and_source_tree(self) -> None:
        receipt = emitter.build_receipt(environment())
        decoded = json.loads(base64.b64decode(emitter.encode_receipt(receipt)))
        self.assertEqual(decoded, receipt)
        self.assertEqual(receipt["source"]["head_tree"], TREE)
        self.assertEqual(receipt["source"]["base_commit"], BASE)
        self.assertEqual(receipt["run"]["id"], 501)

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

    def test_workflow_head_must_match_receipt_head(self) -> None:
        env = environment()
        env["GITHUB_SHA"] = "e" * 40
        with self.assertRaisesRegex(emitter.ReceiptError, "workflow head"):
            emitter.build_receipt(env)


if __name__ == "__main__":
    unittest.main()
