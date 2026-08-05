#!/usr/bin/env python3
"""Emit validated artifact facts without changing verification capabilities."""

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
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_VALUES = {"affected", "unaffected", "unclassified"}
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


def trusted_plan_outputs(plan_path: Path) -> dict[str, str]:
    raw = plan_path.read_bytes()
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdapterError(f"plan is not valid JSON: {exc}") from exc
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise AdapterError("plan schema is unsupported")

    trusted = plan.get("trusted_policy")
    baseline = plan.get("baseline")
    if not isinstance(trusted, dict) or not isinstance(baseline, dict):
        raise AdapterError("plan omits trusted policy or baseline facts")
    validation = baseline.get("validation")
    if (
        not isinstance(validation, dict)
        or validation.get("valid") is not True
        or validation.get("reasons") != []
    ):
        raise AdapterError("plan baseline validation is not trusted")

    cw_state = artifact_state(plan, "cw_cli_release_assets")
    desktop_state = artifact_state(plan, "desktop_package")
    workspace_state = artifact_state(plan, "workspace_image")
    return {
        "ci_plan_status": "trusted",
        "ci_plan_schema": PLAN_SCHEMA,
        "ci_plan_sha256": hashlib.sha256(raw).hexdigest(),
        "ci_policy_commit": require_string(trusted, "commit", HEX40_RE),
        "ci_policy_sha256": require_string(trusted, "policy_sha256", HEX64_RE),
        "ci_graph_sha256": require_string(trusted, "graph_sha256", HEX64_RE),
        "ci_target_base_commit": require_string(baseline, "target_base_commit", HEX40_RE),
        "ci_baseline_commit": require_string(baseline, "baseline_commit", HEX40_RE),
        "ci_head_commit": require_string(baseline, "head_commit", HEX40_RE),
        "ci_head_tree": require_string(baseline, "head_tree", HEX40_RE),
        "cw_package_state": cw_state,
        "cw_package_selected": str(cw_state != "unaffected").lower(),
        "desktop_package_state": desktop_state,
        "desktop_package_selected": str(desktop_state != "unaffected").lower(),
        "workspace_image_state": workspace_state,
        "workspace_image_selected": str(workspace_state != "unaffected").lower(),
    }


def unclassified_outputs(args: argparse.Namespace) -> dict[str, str]:
    commits = {
        "ci_policy_commit": args.trusted_policy,
        "ci_target_base_commit": args.target_base,
        "ci_baseline_commit": args.baseline,
        "ci_head_commit": args.head,
        "ci_head_tree": args.head_tree,
    }
    for key, value in commits.items():
        if not isinstance(value, str) or not HEX40_RE.fullmatch(value):
            raise AdapterError(f"fail-closed field {key} is invalid")
    return {
        "ci_plan_status": "unclassified",
        "ci_plan_schema": PLAN_SCHEMA,
        "ci_plan_sha256": ZERO_HASH,
        "ci_policy_sha256": ZERO_HASH,
        "ci_graph_sha256": ZERO_HASH,
        "cw_package_state": "unclassified",
        "cw_package_selected": "true",
        "desktop_package_state": "unclassified",
        "desktop_package_selected": "true",
        "workspace_image_state": "unclassified",
        "workspace_image_selected": "true",
        **commits,
    }


def emit(outputs: dict[str, str]) -> None:
    rendered = "".join(f"{key}={value}\n" for key, value in outputs.items())
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(rendered)
    sys.stdout.write(rendered)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan")
    mode.add_argument("--unclassified", action="store_true")
    parser.add_argument("--trusted-policy")
    parser.add_argument("--target-base")
    parser.add_argument("--baseline")
    parser.add_argument("--head")
    parser.add_argument("--head-tree")
    return parser.parse_args(argv)


def build_outputs(args: argparse.Namespace) -> dict[str, str]:
    return (
        trusted_plan_outputs(Path(args.plan))
        if args.plan
        else unclassified_outputs(args)
    )


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv or sys.argv[1:])
        emit(build_outputs(args))
    except (OSError, AdapterError) as exc:
        print(f"artifact plan adapter: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
