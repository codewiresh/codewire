#!/usr/bin/env python3
"""Validate the frozen v1 selector-decision regression corpus."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
CORPUS_PATH = ROOT / "scripts/ci/plan/decision-corpus.json"
SELECTOR = ROOT / "scripts/ci/select/select-verification.sh"
EXPECTED_TOP_LEVEL_KEYS = {"schema", "cases"}
EXPECTED_CASE_KEYS = {"id", "event", "ref", "kind_e2e_opt_in", "paths", "expected"}
EXPECTED_RESULT_KEYS = {"classification", "selection_tokens", "required_local_mode"}
VALID_CLASSIFICATIONS = {"changed", "unchanged", "unclassified", "requested", "release"}
VALID_LOCAL_MODES = {"default", "integration", "kind", "full"}
# The corpus records path decisions. Its crate cases classify against a Cargo
# workspace without crate edges, so a new dependency in the repository changes
# no case; scripts/ci/tests/test-select-verification.sh proves the crate graph.
EDGELESS_CARGO = """#!/usr/bin/env bash
[ "${1:-}" = metadata ] || { echo "edgeless cargo stub: unexpected cargo $*" >&2; exit 2; }
printf '{"packages":[]}\\n'
"""


def load_corpus() -> dict[str, object]:
    with CORPUS_PATH.open(encoding="utf-8") as corpus_file:
        corpus = json.load(corpus_file)
    if not isinstance(corpus, dict) or set(corpus) != EXPECTED_TOP_LEVEL_KEYS:
        raise AssertionError("corpus must contain only schema and cases")
    if corpus["schema"] != "codewire.ci-decision-corpus/v1":
        raise AssertionError("corpus schema must be codewire.ci-decision-corpus/v1")
    if not isinstance(corpus["cases"], list) or not corpus["cases"]:
        raise AssertionError("corpus cases must be a non-empty list")
    return corpus


def validate_case(case: object, case_ids: set[str]) -> dict[str, object]:
    if not isinstance(case, dict) or set(case) != EXPECTED_CASE_KEYS:
        raise AssertionError("each corpus case must have the documented fields")
    case_id = case["id"]
    if not isinstance(case_id, str) or not case_id or case_id in case_ids:
        raise AssertionError("each corpus case requires a unique non-empty id")
    case_ids.add(case_id)
    if case["event"] not in {"pull_request", "push"}:
        raise AssertionError(f"{case_id}: unsupported event")
    if not isinstance(case["ref"], str) or not case["ref"]:
        raise AssertionError(f"{case_id}: ref must be non-empty")
    if not isinstance(case["kind_e2e_opt_in"], bool):
        raise AssertionError(f"{case_id}: kind_e2e_opt_in must be a boolean")

    paths = case["paths"]
    if not isinstance(paths, list) or not paths or any(
        not isinstance(item, str)
        or not item
        or item.startswith("/")
        or item.startswith("../")
        or "/../" in item
        for item in paths
    ):
        raise AssertionError(f"{case_id}: paths must be safe repository-relative paths")

    expected = case["expected"]
    if not isinstance(expected, dict) or set(expected) != EXPECTED_RESULT_KEYS:
        raise AssertionError(f"{case_id}: expected result fields are invalid")
    if expected["classification"] not in VALID_CLASSIFICATIONS:
        raise AssertionError(f"{case_id}: classification is invalid")
    if expected["required_local_mode"] not in VALID_LOCAL_MODES:
        raise AssertionError(f"{case_id}: required_local_mode is invalid")
    selection_tokens = expected["selection_tokens"]
    if (
        not isinstance(selection_tokens, list)
        or not selection_tokens
        or any(not isinstance(token, str) or not token for token in selection_tokens)
        or selection_tokens != sorted(set(selection_tokens))
    ):
        raise AssertionError(f"{case_id}: selection_tokens must be sorted and unique")
    return case


def selector_result(case: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="codewire-decision-corpus-") as temporary_directory:
        changed_paths = Path(temporary_directory) / "changed-paths"
        changed_paths.write_text("\n".join(case["paths"]) + "\n", encoding="utf-8")
        cargo = Path(temporary_directory) / "bin" / "cargo"
        cargo.parent.mkdir()
        cargo.write_text(EDGELESS_CARGO, encoding="utf-8")
        cargo.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{cargo.parent}{os.pathsep}{environment.get('PATH', '')}"
        environment.pop("GITHUB_OUTPUT", None)
        environment.pop("GITHUB_EVENT_PATH", None)
        environment["GITHUB_EVENT_NAME"] = str(case["event"])
        environment["GITHUB_REF"] = str(case["ref"])
        environment["KIND_E2E_OPT_IN"] = str(case["kind_e2e_opt_in"]).lower()
        completed = subprocess.run(
            ["/usr/bin/bash", str(SELECTOR), str(changed_paths)],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode:
        raise AssertionError(
            f"{case['id']}: selector failed ({completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    lines = completed.stdout.splitlines()
    if len(lines) != 4:
        raise AssertionError(f"{case['id']}: selector output must have four lines")
    result = dict(line.split("=", 1) for line in lines if "=" in line)
    if set(result) != {"selector_version", "classification", "selection", "required_local_mode"}:
        raise AssertionError(f"{case['id']}: selector result fields are invalid")
    if result["selector_version"] != "v3":
        raise AssertionError(f"{case['id']}: selector version changed")
    selection = result["selection"]
    if not selection.startswith("|valid:v3|") or not selection.endswith("|complete|"):
        raise AssertionError(f"{case['id']}: selector envelope is invalid")
    tokens = [token for token in selection.split("|") if token][1:-1]
    if not tokens or len(tokens) != len(set(tokens)):
        raise AssertionError(f"{case['id']}: selector tokens are invalid")
    return {
        "classification": result["classification"],
        "selection_tokens": sorted(tokens),
        "required_local_mode": result["required_local_mode"],
    }


class DecisionCorpusTests(unittest.TestCase):
    def test_current_selector_matches_corpus(self) -> None:
        corpus = load_corpus()
        case_ids: set[str] = set()
        for raw_case in corpus["cases"]:
            case = validate_case(raw_case, case_ids)
            with self.subTest(case=case["id"]):
                self.assertEqual(selector_result(case), case["expected"])


if __name__ == "__main__":
    unittest.main()
