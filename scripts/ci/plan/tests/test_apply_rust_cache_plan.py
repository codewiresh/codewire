from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ADAPTER_PATH = Path(__file__).parents[1] / "apply-rust-cache-plan.py"
SPEC = importlib.util.spec_from_file_location("codewire_rust_cache_adapter", ADAPTER_PATH)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)

COMMIT = "a" * 40
TREE = "b" * 40
HASH = "c" * 64
BASE = "d" * 40
OTHER_HASH = "e" * 64


def fixture_plan(*, consumer: bool = False) -> dict[str, object]:
    artifacts = {
        artifact: {
            "state": "unclassified" if consumer else "unaffected",
            "baseline_cache_fingerprint": HASH,
            "head_cache_fingerprint": HASH,
        }
        for artifact in adapter.FLAVORS.values()
    }
    target_base = BASE if consumer else COMMIT
    return {
        "schema": adapter.PLAN_SCHEMA,
        "trusted_policy": {"commit": target_base},
        "baseline": {
            "schema": adapter.BASELINE_SCHEMA,
            "mode": "pull_request_merge_base",
            "target_base_commit": target_base,
            "baseline_commit": target_base,
            "head_commit": COMMIT,
            "head_tree": TREE,
            "validation": {"valid": True, "reasons": []},
        },
        "artifacts": artifacts,
        "degraded_reasons": [],
    }


class RustCacheAdapterTests(unittest.TestCase):
    def invoke(
        self, plan: dict[str, object], *, consumer: bool = False
    ) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "plan.json"
            plan_path.write_text(json.dumps(plan))
            if consumer:
                return adapter.build_outputs(plan_path, COMMIT, TREE)
            return adapter.build_outputs(plan_path)

    def test_emits_exact_compatibility_for_every_flavor(self) -> None:
        outputs = self.invoke(fixture_plan())
        self.assertEqual(outputs["rust_cache_head_commit"], COMMIT)
        self.assertEqual(outputs["rust_cache_head_tree"], TREE)
        for flavor in adapter.FLAVORS:
            self.assertEqual(outputs[f"rust_cache_{flavor}_state"], "unaffected")
            self.assertEqual(outputs[f"rust_cache_{flavor}_selected"], "false")
            self.assertEqual(outputs[f"rust_cache_{flavor}_compatibility"], HASH)

    def test_policy_must_be_the_exact_head(self) -> None:
        plan = fixture_plan()
        plan["trusted_policy"]["commit"] = "d" * 40  # type: ignore[index]
        with self.assertRaisesRegex(adapter.AdapterError, "exact canonical head"):
            self.invoke(plan)

    def test_missing_or_invalid_fingerprint_fails_closed(self) -> None:
        plan = fixture_plan()
        cache = plan["artifacts"]["rust_cache_host_ci"]  # type: ignore[index]
        cache["head_cache_fingerprint"] = "bad"  # type: ignore[index]
        with self.assertRaisesRegex(adapter.AdapterError, "invalid compatibility"):
            self.invoke(plan)

    def test_consumer_emits_compatibility_for_equal_trusted_fingerprints(self) -> None:
        outputs = self.invoke(fixture_plan(consumer=True), consumer=True)
        self.assertEqual(outputs["rust_cache_head_commit"], COMMIT)
        self.assertEqual(outputs["rust_cache_head_tree"], TREE)
        for flavor in adapter.FLAVORS:
            self.assertEqual(outputs[f"rust_cache_{flavor}_state"], "unclassified")
            self.assertEqual(outputs[f"rust_cache_{flavor}_selected"], "true")
            self.assertEqual(outputs[f"rust_cache_{flavor}_compatibility"], HASH)

    def test_consumer_cools_only_a_mismatched_or_malformed_flavor(self) -> None:
        plan = fixture_plan(consumer=True)
        host_ci = plan["artifacts"]["rust_cache_host_ci"]  # type: ignore[index]
        host_ci["head_cache_fingerprint"] = OTHER_HASH  # type: ignore[index]
        desktop = plan["artifacts"]["rust_cache_desktop_release"]  # type: ignore[index]
        desktop["state"] = "invalid"  # type: ignore[index]
        del plan["artifacts"]["rust_cache_kind_ci"]  # type: ignore[index]

        outputs = self.invoke(plan, consumer=True)

        self.assertEqual(outputs["rust_cache_host_ci_compatibility"], "")
        self.assertEqual(outputs["rust_cache_desktop_release_compatibility"], "")
        self.assertEqual(outputs["rust_cache_desktop_release_state"], "unclassified")
        self.assertEqual(outputs["rust_cache_kind_ci_compatibility"], "")
        self.assertEqual(outputs["rust_cache_host_debug_compatibility"], HASH)

    def test_consumer_requires_exact_base_head_tree_and_clean_plan(self) -> None:
        cases: list[tuple[str, object]] = [
            ("baseline_commit", "f" * 40),
            ("head_tree", "f" * 40),
            ("validation", {"valid": False, "reasons": ["fixture"]}),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                plan = fixture_plan(consumer=True)
                plan["baseline"][field] = value  # type: ignore[index]
                with self.assertRaises(adapter.AdapterError):
                    self.invoke(plan, consumer=True)

        degraded = fixture_plan(consumer=True)
        degraded["degraded_reasons"] = ["fixture"]
        with self.assertRaisesRegex(adapter.AdapterError, "degraded"):
            self.invoke(degraded, consumer=True)

        candidate_policy = fixture_plan(consumer=True)
        candidate_policy["trusted_policy"]["commit"] = COMMIT  # type: ignore[index]
        with self.assertRaisesRegex(adapter.AdapterError, "exact target base"):
            self.invoke(candidate_policy, consumer=True)

    def test_consumer_cli_turns_global_invalidity_into_cold_outputs(self) -> None:
        plan = fixture_plan(consumer=True)
        plan["baseline"]["head_tree"] = "f" * 40  # type: ignore[index]
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "plan.json"
            plan_path.write_text(json.dumps(plan))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = adapter.main(
                    [
                        "--plan",
                        str(plan_path),
                        "--expected-head",
                        COMMIT,
                        "--expected-head-tree",
                        TREE,
                    ]
                )

        self.assertEqual(result, 0)
        self.assertIn("cold fallback", stderr.getvalue())
        outputs = dict(line.split("=", 1) for line in stdout.getvalue().splitlines())
        for flavor in adapter.FLAVORS:
            self.assertEqual(outputs[f"rust_cache_{flavor}_state"], "unclassified")
            self.assertEqual(outputs[f"rust_cache_{flavor}_selected"], "true")
            self.assertEqual(outputs[f"rust_cache_{flavor}_compatibility"], "")


if __name__ == "__main__":
    unittest.main()
