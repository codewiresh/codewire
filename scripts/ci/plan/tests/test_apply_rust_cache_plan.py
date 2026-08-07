from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
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


def fixture_plan() -> dict[str, object]:
    artifacts = {
        artifact: {"state": "unaffected", "head_cache_fingerprint": HASH}
        for artifact in adapter.FLAVORS.values()
    }
    return {
        "schema": adapter.PLAN_SCHEMA,
        "trusted_policy": {"commit": COMMIT},
        "baseline": {
            "head_commit": COMMIT,
            "head_tree": TREE,
            "validation": {"valid": True, "reasons": []},
        },
        "artifacts": artifacts,
    }


class RustCacheAdapterTests(unittest.TestCase):
    def invoke(self, plan: dict[str, object]) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "plan.json"
            plan_path.write_text(json.dumps(plan))
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


if __name__ == "__main__":
    unittest.main()
