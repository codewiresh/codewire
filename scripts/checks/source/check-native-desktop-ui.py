#!/usr/bin/env python3
"""Guard the retained desktop UI and forbid restored legacy client code."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
POLICY_REL = "scripts/checks/contracts/native-desktop-ui-policy.json"
POLICY_KEYS = {
    "$comment",
    "schema_version",
    "reference_commit",
    "reference_tree",
    "source_roots",
    "required_paths",
    "required_fragments",
    "forbidden_source_fragments",
}


def read_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def source_files() -> list[str]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        cwd=ROOT,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git ls-files failed"
        raise RuntimeError(detail)
    return [
        rel
        for rel in result.stdout.split("\0")
        if rel and (ROOT / rel).is_file()
    ]


def load_policy() -> dict[str, Any]:
    policy = json.loads(read_text(POLICY_REL))
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise RuntimeError(
            "native desktop UI policy keys must be exactly "
            f"{stable_json(sorted(POLICY_KEYS))}"
        )
    if policy.get("schema_version") != 1:
        raise RuntimeError("native desktop UI policy schema_version must equal 1")
    for key in ("$comment", "reference_commit", "reference_tree"):
        if not isinstance(policy.get(key), str) or not policy[key].strip():
            raise RuntimeError(f"native desktop UI policy {key} must be non-empty")
    for key in ("source_roots", "required_paths", "forbidden_source_fragments"):
        values = policy.get(key)
        if not isinstance(values, list) or not values or not all(
            isinstance(value, str) and value for value in values
        ):
            raise RuntimeError(
                f"native desktop UI policy {key} must be a non-empty string list"
            )
    required_fragments = policy.get("required_fragments")
    if not isinstance(required_fragments, dict) or not required_fragments:
        raise RuntimeError(
            "native desktop UI policy required_fragments must be a non-empty object"
        )
    for path, fragments in required_fragments.items():
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(fragments, list)
            or not fragments
            or not all(isinstance(fragment, str) and fragment for fragment in fragments)
        ):
            raise RuntimeError(
                "native desktop UI policy required_fragments must map paths "
                "to non-empty string lists"
            )
    return policy


def desktop_sources(policy: dict[str, Any]) -> dict[str, str]:
    roots = tuple(policy["source_roots"])
    return {
        rel: read_text(rel)
        for rel in source_files()
        if rel.endswith(".rs") and rel.startswith(roots)
    }


def failures_for(
    sources: dict[str, str],
    policy: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    for path in policy["required_paths"]:
        if path not in sources:
            failures.append(f"retained native UI path is missing: {path}")

    for path, fragments in policy["required_fragments"].items():
        source = sources.get(path)
        if source is None:
            failures.append(f"native UI policy source is missing: {path}")
            continue
        for fragment in fragments:
            if fragment not in source:
                failures.append(
                    f"{path} lost required retained/shared-core shape {fragment!r}"
                )

    for path, source in sorted(sources.items()):
        for fragment in policy["forbidden_source_fragments"]:
            if fragment in source:
                failures.append(
                    f"{path} restores forbidden native legacy fragment {fragment!r}"
                )
    return failures


def self_test(sources: dict[str, str], policy: dict[str, Any]) -> None:
    if failures_for(sources, policy):
        raise RuntimeError("self-test requires the accepted native desktop UI baseline")

    required_path = policy["required_paths"][0]
    without_path = dict(sources)
    without_path.pop(required_path, None)
    if not any(
        "retained native UI path is missing" in item
        for item in failures_for(without_path, policy)
    ):
        raise RuntimeError("self-test did not detect a missing retained UI path")

    required_source, required_fragments = next(iter(policy["required_fragments"].items()))
    without_fragment = dict(sources)
    without_fragment[required_source] = without_fragment[required_source].replace(
        required_fragments[0], "", 1
    )
    if not any(
        "lost required retained/shared-core shape" in item
        for item in failures_for(without_fragment, policy)
    ):
        raise RuntimeError("self-test did not detect a missing shared-core UI fragment")

    with_replacement_dashboard = dict(sources)
    with_replacement_dashboard[
        "crates/codewire-desktop/src/replacement_dashboard_fixture.rs"
    ] = 'struct DashboardRequested;\nconst TITLE: &str = "Your development workspace";\n'
    if not any(
        "replacement_dashboard_fixture.rs restores forbidden native legacy fragment"
        in item
        for item in failures_for(with_replacement_dashboard, policy)
    ):
        raise RuntimeError("self-test did not reject the replacement dashboard shell")

    with_retired_provider = dict(sources)
    with_retired_provider[
        "crates/codewire-desktop/src/retired_provider_fixture.rs"
    ] = "struct CoderWorkspace;\n"
    if not any(
        "retired_provider_fixture.rs restores forbidden native legacy fragment" in item
        for item in failures_for(with_retired_provider, policy)
    ):
        raise RuntimeError("self-test did not reject a new retired provider source file")

    with_new_legacy_file = dict(sources)
    with_new_legacy_file[
        "crates/codewire-desktop/src/legacy_client_fixture.rs"
    ] = 'const LEGACY_URL: &str = "/api/v1/environments";\n'
    if not any(
        "legacy_client_fixture.rs restores forbidden native legacy fragment" in item
        for item in failures_for(with_new_legacy_file, policy)
    ):
        raise RuntimeError("self-test did not discover a new legacy client source file")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    try:
        policy = load_policy()
        sources = desktop_sources(policy)
        failures = failures_for(sources, policy)
        if not failures and args.self_test:
            self_test(sources, policy)
    except Exception as error:  # noqa: BLE001 - repository policy check
        failures = [str(error)]

    if failures:
        for failure in failures:
            print(f"native desktop UI: {failure}", file=sys.stderr)
        return 1
    print(
        "native desktop UI: OK "
        "(retained GPUI surface, shared Connect core, no restored legacy client)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
