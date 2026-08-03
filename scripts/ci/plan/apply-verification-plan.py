#!/usr/bin/env python3
"""Apply trusted artifact facts to the legacy product-verification selection."""

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


def read_legacy_output(path: Path) -> tuple[str, set[str]]:
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        if not raw_line or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        if key in values:
            raise AdapterError(f"legacy selector output repeats {key}")
        values[key] = value

    version = values.get("selector_version", "")
    selection = values.get("selection", "")
    expected_prefix = f"|valid:{version}|"
    if version != "v2" or not selection.startswith(expected_prefix) or not selection.endswith("|complete|"):
        raise AdapterError("legacy selector output is invalid or incomplete")
    parts = selection.split("|")
    if len(parts) < 5 or parts[0] or parts[-1] or parts[1] != f"valid:{version}" or parts[-2] != "complete":
        raise AdapterError("legacy selector token framing is invalid")
    tokens = parts[2:-2]
    if any(not re.fullmatch(r"[a-z0-9_:-]+", token) for token in tokens):
        raise AdapterError("legacy selector contains an invalid token")
    if len(tokens) != len(set(tokens)):
        raise AdapterError("legacy selector contains duplicate tokens")
    return version, set(tokens)


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
    verification = plan.get("verification")
    if not isinstance(trusted, dict) or not isinstance(baseline, dict) or not isinstance(verification, dict):
        raise AdapterError("plan omits trusted policy, baseline, or verification facts")
    validation = baseline.get("validation")
    if (
        not isinstance(validation, dict)
        or validation.get("valid") is not True
        or validation.get("reasons") != []
    ):
        raise AdapterError("plan baseline validation is not trusted")

    cw_state = artifact_state(plan, "cw_cli_release_assets")
    desktop_state = artifact_state(plan, "desktop_package")
    cw_selected = cw_state != "unaffected"
    desktop_selected = desktop_state != "unaffected"
    if verification.get("cw_cli_package") is not cw_selected:
        raise AdapterError("plan CW verification fact disagrees with artifact state")
    if verification.get("desktop_package") is not desktop_selected:
        raise AdapterError("plan desktop verification fact disagrees with artifact state")
    if verification.get("legacy_selectors_authoritative") is not True:
        raise AdapterError("plan does not preserve unmigrated legacy selectors")

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
        "cw_package_selected": str(cw_selected).lower(),
        "desktop_package_state": desktop_state,
        "desktop_package_selected": str(desktop_selected).lower(),
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
        **commits,
    }


def apply_tokens(version: str, tokens: set[str], outputs: dict[str, str]) -> str:
    tokens.discard("rust_pkg_codewire_desktop")
    if outputs["desktop_package_selected"] == "true":
        tokens.update({"policy", "rust", "rust_pkg_codewire_desktop"})
    ordered = "|".join(sorted(tokens))
    middle = f"{ordered}|" if ordered else ""
    return f"|valid:{version}|{middle}complete|"


def build_outputs(args: argparse.Namespace) -> dict[str, str]:
    version, tokens = read_legacy_output(Path(args.legacy_output))
    plan_outputs = trusted_plan_outputs(Path(args.plan)) if args.plan else unclassified_outputs(args)
    return {
        "selector_version": version,
        "selection": apply_tokens(version, tokens, plan_outputs),
        **plan_outputs,
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
    parser.add_argument("--legacy-output", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan")
    mode.add_argument("--unclassified", action="store_true")
    parser.add_argument("--trusted-policy")
    parser.add_argument("--target-base")
    parser.add_argument("--baseline")
    parser.add_argument("--head")
    parser.add_argument("--head-tree")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        emit(build_outputs(parse_args(argv or sys.argv[1:])))
    except (OSError, AdapterError) as exc:
        print(f"verification plan adapter: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
