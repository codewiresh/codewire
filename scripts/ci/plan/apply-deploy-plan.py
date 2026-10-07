#!/usr/bin/env python3
"""Apply trusted runtime artifact facts to atomic Dev deployment policy."""

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
RUNTIME_ARTIFACTS = (
    "dashboard_image",
    "daemon_image",
    "derp_image",
    "services_image",
    "mesh_image",
)
DEV_RELEASE_ARTIFACT = "dev_release_tree"
# Dev acceptance runs only from the exact promoted source, so a harness change
# can be accepted only by promoting that exact source.
DEV_ACCEPTANCE_ARTIFACT = "dev_acceptance_harness"
DEPLOY_ARTIFACTS = (DEV_RELEASE_ARTIFACT, DEV_ACCEPTANCE_ARTIFACT, *RUNTIME_ARTIFACTS)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_VALUES = {"affected", "unaffected", "unclassified"}
MAX_PLAN_BYTES = 4 * 1024 * 1024
ZERO_HASH = "0" * 64


class AdapterError(RuntimeError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


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
        plan = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise AdapterError(f"plan is malformed: {exc}") from exc
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise AdapterError("plan schema is unsupported")

    trusted = plan.get("trusted_policy")
    baseline = plan.get("baseline")
    if not isinstance(trusted, dict) or not isinstance(baseline, dict):
        raise AdapterError("plan omits trusted policy or baseline facts")
    if baseline.get("schema") != BASELINE_SCHEMA or baseline.get("mode") != "deployed_source":
        raise AdapterError("plan does not contain a deployed-source baseline")
    target = require_string(baseline, "target_base_commit", HEX40_RE)
    if target != expected_head:
        raise AdapterError("deploy plan target is not the exact canonical head")
    head = require_string(baseline, "head_commit", HEX40_RE)
    if head != expected_head:
        raise AdapterError("plan head does not match the exact workflow head")
    head_tree = require_string(baseline, "head_tree", HEX40_RE)
    if head_tree != expected_head_tree:
        raise AdapterError("plan tree does not match the exact workflow tree")
    if require_string(trusted, "commit", HEX40_RE) != expected_head:
        raise AdapterError("deploy plan policy is not the exact canonical head")

    states = {name: artifact_state(plan, name) for name in DEPLOY_ARTIFACTS}
    validation = baseline.get("validation")
    if not isinstance(validation, dict):
        raise AdapterError("plan baseline validation is malformed")
    valid = validation.get("valid") is True and validation.get("reasons") == []
    if not valid and any(state != "unclassified" for state in states.values()):
        raise AdapterError("invalid baseline did not fail every deploy artifact closed")

    runtime_selected = any(
        states[name] != "unaffected" for name in RUNTIME_ARTIFACTS
    )
    release_state = states[DEV_RELEASE_ARTIFACT]
    acceptance_state = states[DEV_ACCEPTANCE_ARTIFACT]
    selected = (
        runtime_selected
        or release_state != "unaffected"
        or acceptance_state != "unaffected"
    )
    if not valid:
        reason = "baseline_invalid"
    elif "unclassified" in states.values():
        reason = "artifact_unclassified"
    elif runtime_selected:
        reason = "artifact_affected"
    elif release_state == "affected":
        reason = "dev_release_affected"
    elif acceptance_state == "affected":
        reason = "dev_acceptance_affected"
    else:
        reason = "artifacts_unaffected"

    outputs = {
        "deploy_dev": str(selected).lower(),
        "reason": reason,
        "matched_categories": ",".join(f"{name}:{states[name]}" for name in DEPLOY_ARTIFACTS),
        "baseline_sha": require_string(baseline, "baseline_commit", HEX40_RE),
        "head_sha": head,
        "head_tree": head_tree,
        "ci_plan_sha256": hashlib.sha256(raw).hexdigest(),
        "ci_policy_sha256": require_string(trusted, "policy_sha256", HEX64_RE),
        "baseline_valid": str(valid).lower(),
    }
    outputs.update({f"{name}_state": state for name, state in states.items()})
    return outputs


def fail_closed_outputs(head: str, head_tree: str) -> dict[str, str]:
    if not HEX40_RE.fullmatch(head) or not HEX40_RE.fullmatch(head_tree):
        raise AdapterError("fail-closed head or tree is invalid")
    states = {name: "unclassified" for name in DEPLOY_ARTIFACTS}
    outputs = {
        "deploy_dev": "true",
        "reason": "plan_invalid",
        "matched_categories": ",".join(f"{name}:unclassified" for name in DEPLOY_ARTIFACTS),
        "baseline_sha": head,
        "head_sha": head,
        "head_tree": head_tree,
        "ci_plan_sha256": ZERO_HASH,
        "ci_policy_sha256": ZERO_HASH,
        "baseline_valid": "false",
    }
    outputs.update({f"{name}_state": state for name, state in states.items()})
    return outputs


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
        print(f"deploy plan adapter: {exc}; selecting the atomic runtime set", file=sys.stderr)
        try:
            outputs = fail_closed_outputs(args.head, args.head_tree)
        except AdapterError as fallback_exc:
            print(f"deploy plan adapter: {fallback_exc}", file=sys.stderr)
            return 2
    emit(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
