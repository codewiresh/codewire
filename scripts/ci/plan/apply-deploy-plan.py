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
# cw-egress is built and signed by Dev delivery's workflow but never delivered
# by it, so it never selects a delivery: only its fingerprint, which keys the
# image (private-docs designs/hosted-egress.md, "The image and its deployment").
EGRESS_ARTIFACT = "egress_image"
# The standard pod-runtime image (#5602) is built, signed and keyed the same way.
POD_RUNTIME_ARTIFACT = "pod_runtime_image"
# And the /dev/kvm device plugin's own image (#6202).
KVM_DEVICE_PLUGIN_ARTIFACT = "kvm_device_plugin_image"
# And the standard workspace disk (#5602), built on the KVM runner.
WORKSPACE_DISK_ARTIFACT = "workspace_disk_image"
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


def egress_fingerprint(plan: dict[str, Any], name: str = EGRESS_ARTIFACT) -> str:
    """An image's head fingerprint (the egress image's by default), or empty
    when the planner gave none (an unclassified run): then no such image is
    built for this commit, and the next commit with a fingerprint builds it."""
    artifacts = plan.get("artifacts")
    entry = artifacts.get(name) if isinstance(artifacts, dict) else None
    if not isinstance(entry, dict):
        raise AdapterError(f"plan omits artifact {name}")
    fingerprint = entry.get("head_fingerprint")
    if fingerprint is None:
        return ""
    if not isinstance(fingerprint, str) or not HEX64_RE.fullmatch(fingerprint):
        raise AdapterError(f"plan artifact {name} has an invalid fingerprint")
    return fingerprint


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
        "egress_image_fingerprint": egress_fingerprint(plan),
        "pod_runtime_image_fingerprint": egress_fingerprint(plan, POD_RUNTIME_ARTIFACT),
        "kvm_device_plugin_image_fingerprint": egress_fingerprint(plan, KVM_DEVICE_PLUGIN_ARTIFACT),
        "workspace_disk_image_fingerprint": egress_fingerprint(plan, WORKSPACE_DISK_ARTIFACT),
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
        "egress_image_fingerprint": "",
        "pod_runtime_image_fingerprint": "",
        "kvm_device_plugin_image_fingerprint": "",
        "workspace_disk_image_fingerprint": "",
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
