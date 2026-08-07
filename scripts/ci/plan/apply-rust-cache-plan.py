#!/usr/bin/env python3
"""Emit validated canonical-main Rust dependency-cache refresh facts."""

from __future__ import annotations

import argparse
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


def build_outputs(plan_path: Path) -> dict[str, str]:
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
    if require_string(trusted, "commit", HEX40_RE) != head_commit:
        raise AdapterError("cache planning policy is not the exact canonical head")

    outputs = {
        "rust_cache_head_commit": head_commit,
        "rust_cache_head_tree": head_tree,
    }
    for flavor, artifact_name in FLAVORS.items():
        artifact = artifacts.get(artifact_name)
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
    args = parser.parse_args(argv)
    try:
        emit(build_outputs(Path(args.plan)))
    except (OSError, UnicodeError, AdapterError) as exc:
        print(f"Rust cache plan adapter: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
