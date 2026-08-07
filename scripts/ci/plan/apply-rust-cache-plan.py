#!/usr/bin/env python3
"""Emit validated Rust dependency-cache producer or consumer facts."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


PLAN_SCHEMA = "codewire.ci-plan/v1"
BASELINE_SCHEMA = "codewire.ci-baseline/v1"
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_VALUES = {"affected", "unaffected", "unclassified"}
FLAVORS = {
    "host_debug": "rust_cache_host_debug",
    "host_ci": "rust_cache_host_ci",
    "kind_ci": "rust_cache_kind_ci",
    "cw_cross_ci": "rust_cache_cw_cross_ci",
    "desktop_release": "rust_cache_desktop_release",
}


class AdapterError(RuntimeError):
    pass


def require_string(mapping: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AdapterError(f"plan field {key} is invalid")
    return value


def cold_consumer_outputs(expected_head: str, expected_head_tree: str) -> dict[str, str]:
    outputs = {
        "rust_cache_head_commit": expected_head,
        "rust_cache_head_tree": expected_head_tree,
    }
    for flavor in FLAVORS:
        outputs[f"rust_cache_{flavor}_state"] = "unclassified"
        outputs[f"rust_cache_{flavor}_selected"] = "true"
        outputs[f"rust_cache_{flavor}_compatibility"] = ""
    return outputs


def build_outputs(
    plan_path: Path,
    expected_head: str | None = None,
    expected_head_tree: str | None = None,
) -> dict[str, str]:
    if (expected_head is None) != (expected_head_tree is None):
        raise AdapterError("consumer mode requires both expected head and tree")
    try:
        plan = json.loads(plan_path.read_text())
    except json.JSONDecodeError as exc:
        raise AdapterError(f"plan is not valid JSON: {exc}") from exc
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise AdapterError("plan schema is unsupported")
    trusted = plan.get("trusted_policy")
    baseline = plan.get("baseline")
    artifacts = plan.get("artifacts")
    if not all(isinstance(value, dict) for value in (trusted, baseline, artifacts)):
        raise AdapterError("plan omits trusted policy, baseline, or artifacts")
    validation = baseline.get("validation")
    if not isinstance(validation, dict) or validation != {"valid": True, "reasons": []}:
        raise AdapterError("plan baseline validation is not trusted")
    head_commit = require_string(baseline, "head_commit", HEX40_RE)
    head_tree = require_string(baseline, "head_tree", HEX40_RE)
    trusted_commit = require_string(trusted, "commit", HEX40_RE)

    consumer_mode = expected_head is not None and expected_head_tree is not None
    if consumer_mode:
        assert expected_head is not None and expected_head_tree is not None
        if not HEX40_RE.fullmatch(expected_head) or not HEX40_RE.fullmatch(expected_head_tree):
            raise AdapterError("consumer expected head or tree is invalid")
        if baseline.get("schema") != BASELINE_SCHEMA:
            raise AdapterError("consumer baseline schema is unsupported")
        if baseline.get("mode") != "pull_request_merge_base":
            raise AdapterError("consumer baseline mode is not a pull request")
        target_base = require_string(baseline, "target_base_commit", HEX40_RE)
        baseline_commit = require_string(baseline, "baseline_commit", HEX40_RE)
        if trusted_commit != target_base or baseline_commit != target_base:
            raise AdapterError("consumer policy is not the exact target base")
        if head_commit != expected_head or head_tree != expected_head_tree:
            raise AdapterError("consumer plan does not match the expected head and tree")
        if plan.get("degraded_reasons") != []:
            raise AdapterError("consumer plan is degraded")
    elif trusted_commit != head_commit:
        raise AdapterError("cache planning policy is not the exact canonical head")

    outputs = {
        "rust_cache_head_commit": head_commit,
        "rust_cache_head_tree": head_tree,
    }
    for flavor, artifact_name in FLAVORS.items():
        artifact = artifacts.get(artifact_name)
        if consumer_mode:
            state = "unclassified"
            compatibility = ""
            if isinstance(artifact, dict):
                candidate_state = artifact.get("state")
                if candidate_state in STATE_VALUES:
                    state = candidate_state
                    baseline_compatibility = artifact.get("baseline_cache_fingerprint")
                    head_compatibility = artifact.get("head_cache_fingerprint")
                    if (
                        isinstance(baseline_compatibility, str)
                        and HEX64_RE.fullmatch(baseline_compatibility)
                        and isinstance(head_compatibility, str)
                        and HEX64_RE.fullmatch(head_compatibility)
                        and baseline_compatibility == head_compatibility
                    ):
                        compatibility = head_compatibility
            outputs[f"rust_cache_{flavor}_state"] = state
            outputs[f"rust_cache_{flavor}_selected"] = str(
                state != "unaffected"
            ).lower()
            outputs[f"rust_cache_{flavor}_compatibility"] = compatibility
            continue
        if not isinstance(artifact, dict):
            raise AdapterError(f"plan omits cache artifact {artifact_name}")
        state = artifact.get("state")
        if state not in STATE_VALUES:
            raise AdapterError(f"cache artifact {artifact_name} has invalid state")
        compatibility = artifact.get("head_cache_fingerprint")
        if not isinstance(compatibility, str) or not HEX64_RE.fullmatch(compatibility):
            raise AdapterError(
                f"cache artifact {artifact_name} has invalid compatibility fingerprint"
            )
        outputs[f"rust_cache_{flavor}_state"] = state
        outputs[f"rust_cache_{flavor}_selected"] = str(state != "unaffected").lower()
        outputs[f"rust_cache_{flavor}_compatibility"] = compatibility
    return outputs


def emit(outputs: dict[str, str]) -> None:
    rendered = "".join(f"{key}={value}\n" for key, value in outputs.items())
    if output_path := os.environ.get("GITHUB_OUTPUT"):
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(rendered)
    sys.stdout.write(rendered)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--expected-head")
    parser.add_argument("--expected-head-tree")
    args = parser.parse_args(argv)
    consumer_mode = args.expected_head is not None or args.expected_head_tree is not None
    if consumer_mode and (
        not isinstance(args.expected_head, str)
        or not HEX40_RE.fullmatch(args.expected_head)
        or not isinstance(args.expected_head_tree, str)
        or not HEX40_RE.fullmatch(args.expected_head_tree)
    ):
        print(
            "Rust cache plan adapter: consumer mode requires exact head and tree",
            file=sys.stderr,
        )
        return 2
    try:
        outputs = build_outputs(
            Path(args.plan), args.expected_head, args.expected_head_tree
        )
    except (OSError, UnicodeError, AdapterError) as exc:
        if consumer_mode:
            print(f"Rust cache plan adapter: cold fallback ({exc})", file=sys.stderr)
            emit(cold_consumer_outputs(args.expected_head, args.expected_head_tree))
            return 0
        print(f"Rust cache plan adapter: {exc}", file=sys.stderr)
        return 2
    emit(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
