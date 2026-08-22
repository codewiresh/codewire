#!/usr/bin/env python3
"""Apply trusted artifact facts to atomic support-image publication policy."""

from __future__ import annotations

import argparse
import hashlib
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
MAX_PLAN_BYTES = 4 * 1024 * 1024
ZERO_HASH = "0" * 64


class AdapterError(RuntimeError):
    pass


def require_string(mapping: dict[str, Any], key: str, pattern: re.Pattern[str]) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AdapterError(f"plan field {key} is invalid")
    return value


def artifact_state(plan: dict[str, Any], name: str) -> str:
    artifacts = plan.get("artifacts")
    if not isinstance(artifacts, dict) or not isinstance(artifacts.get(name), dict):
        raise AdapterError(f"plan omits artifact {name}")
    state = artifacts[name].get("state")
    if state not in STATE_VALUES:
        raise AdapterError(f"plan artifact {name} has invalid state")
    return state


def trusted_outputs(path: Path, expected_head: str, expected_head_tree: str) -> dict[str, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_PLAN_BYTES:
        raise AdapterError("plan exceeds the size limit")
    try:
        plan = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"plan is malformed: {exc}") from exc
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise AdapterError("plan schema is unsupported")

    trusted = plan.get("trusted_policy")
    baseline = plan.get("baseline")
    if not isinstance(trusted, dict) or not isinstance(baseline, dict):
        raise AdapterError("plan omits trusted policy or baseline facts")
    if baseline.get("schema") != BASELINE_SCHEMA or baseline.get("mode") != "published_support_pair":
        raise AdapterError("plan does not contain a published support-pair baseline")
    target = require_string(baseline, "target_base_commit", HEX40_RE)
    if target != expected_head:
        raise AdapterError("support plan target is not the exact canonical head")
    head = require_string(baseline, "head_commit", HEX40_RE)
    if head != expected_head:
        raise AdapterError("plan head does not match the exact workflow head")
    head_tree = require_string(baseline, "head_tree", HEX40_RE)
    if head_tree != expected_head_tree:
        raise AdapterError("plan tree does not match the exact workflow tree")
    if require_string(trusted, "commit", HEX40_RE) != expected_head:
        raise AdapterError("support plan policy is not the exact canonical head")

    base_state = artifact_state(plan, "base_image")
    workspace_state = artifact_state(plan, "workspace_image")
    confidential_probe_state = artifact_state(plan, "confidential_probe_image")
    validation = baseline.get("validation")
    if not isinstance(validation, dict):
        raise AdapterError("plan baseline validation is malformed")
    valid = validation.get("valid") is True and validation.get("reasons") == []
    if not valid and any(
        state != "unclassified"
        for state in (base_state, workspace_state, confidential_probe_state)
    ):
        raise AdapterError("invalid baseline did not fail every support artifact closed")

    selected = base_state != "unaffected" or workspace_state != "unaffected"
    confidential_probe_selected = confidential_probe_state != "unaffected"
    if not valid:
        reason = "baseline_invalid"
    elif "unclassified" in (base_state, workspace_state, confidential_probe_state):
        reason = "artifact_unclassified"
    elif selected or confidential_probe_selected:
        reason = "artifact_affected"
    else:
        reason = "artifacts_unaffected"

    return {
        "build_support_images": str(selected).lower(),
        "build_confidential_probe_image": str(confidential_probe_selected).lower(),
        "reason": reason,
        "matched_categories": (
            f"base_image:{base_state},workspace_image:{workspace_state},"
            f"confidential_probe_image:{confidential_probe_state}"
        ),
        "base_image_state": base_state,
        "workspace_image_state": workspace_state,
        "confidential_probe_image_state": confidential_probe_state,
        "baseline_sha": require_string(baseline, "baseline_commit", HEX40_RE),
        "head_sha": head,
        "head_tree": head_tree,
        "ci_plan_sha256": hashlib.sha256(raw).hexdigest(),
        "ci_policy_sha256": require_string(trusted, "policy_sha256", HEX64_RE),
        "baseline_valid": str(valid).lower(),
    }


def fail_closed_outputs(head: str, head_tree: str) -> dict[str, str]:
    if not HEX40_RE.fullmatch(head) or not HEX40_RE.fullmatch(head_tree):
        raise AdapterError("fail-closed head or tree is invalid")
    return {
        "build_support_images": "true",
        "build_confidential_probe_image": "true",
        "reason": "plan_invalid",
        "matched_categories": (
            "base_image:unclassified,workspace_image:unclassified,"
            "confidential_probe_image:unclassified"
        ),
        "base_image_state": "unclassified",
        "workspace_image_state": "unclassified",
        "confidential_probe_image_state": "unclassified",
        "baseline_sha": head,
        "head_sha": head,
        "head_tree": head_tree,
        "ci_plan_sha256": ZERO_HASH,
        "ci_policy_sha256": ZERO_HASH,
        "baseline_valid": "false",
    }


def emit(outputs: dict[str, str]) -> None:
    rendered = "".join(f"{key}={value}\n" for key, value in outputs.items())
    if output_path := os.environ.get("GITHUB_OUTPUT"):
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(rendered)
    sys.stdout.write(rendered)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--head-tree", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        outputs = trusted_outputs(Path(args.plan), args.head, args.head_tree)
    except (OSError, AdapterError) as exc:
        print(f"support plan adapter: {exc}; selecting the atomic pair", file=sys.stderr)
        try:
            outputs = fail_closed_outputs(args.head, args.head_tree)
        except AdapterError as fallback_exc:
            print(f"support plan adapter: {fallback_exc}", file=sys.stderr)
            return 2
    emit(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
