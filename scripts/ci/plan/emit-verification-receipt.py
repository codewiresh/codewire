#!/usr/bin/env python3
"""Emit one canonical, log-transported receipt for successful PR verification."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from typing import Mapping


RECEIPT_SCHEMA = "codewire.ci-verification-receipt/v1"
PLAN_SCHEMA = "codewire.ci-plan/v1"
PREFIX = "CODEWIRE_CI_VERIFICATION_RECEIPT="
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
STATES = {"affected", "unaffected", "unclassified"}


class ReceiptError(RuntimeError):
    pass


def require(env: Mapping[str, str], key: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(key, "")
    if not value or (pattern and not pattern.fullmatch(value)):
        raise ReceiptError(f"receipt input {key} is invalid")
    return value


def require_success(env: Mapping[str, str], key: str) -> str:
    value = require(env, key)
    if value != "success":
        raise ReceiptError(f"receipt dependency {key} concluded {value}")
    return value


def run_attempt(env: Mapping[str, str]) -> int:
    value = env.get("GITHUB_RUN_ATTEMPT", "")
    if not value:
        # Gitea records run_attempt in its Actions API but its first-attempt
        # runner does not currently export the corresponding GitHub variable.
        # The receipt verifier still compares this value with that API before
        # accepting reuse, so a later attempt cannot be mistaken for the first.
        return 1
    if not POSITIVE_RE.fullmatch(value):
        raise ReceiptError("receipt input GITHUB_RUN_ATTEMPT is invalid")
    return int(value)


def build_receipt(env: Mapping[str, str]) -> dict[str, object]:
    if require(env, "GITHUB_EVENT_NAME") != "pull_request":
        raise ReceiptError("verification receipts are emitted only for pull requests")
    repository = require(env, "GITHUB_REPOSITORY", re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))
    pr_number = require(env, "CODEWIRE_PR_NUMBER", POSITIVE_RE)
    base_commit = require(env, "CODEWIRE_BASE_COMMIT", HEX40_RE)
    head_commit = require(env, "CODEWIRE_HEAD_COMMIT", HEX40_RE)
    head_tree = require(env, "CODEWIRE_HEAD_TREE", HEX40_RE)
    policy_commit = require(env, "CODEWIRE_POLICY_COMMIT", HEX40_RE)
    target_base = require(env, "CODEWIRE_TARGET_BASE_COMMIT", HEX40_RE)
    if policy_commit != base_commit or target_base != base_commit:
        raise ReceiptError("trusted policy and target base must equal the exact PR base")
    if head_commit != require(env, "GITHUB_SHA", HEX40_RE):
        raise ReceiptError("receipt head does not equal the workflow head")

    cw_state = require(env, "CODEWIRE_CW_PACKAGE_STATE")
    desktop_state = require(env, "CODEWIRE_DESKTOP_PACKAGE_STATE")
    if cw_state not in STATES or desktop_state not in STATES:
        raise ReceiptError("receipt contains an invalid artifact state")
    selection = require(env, "CODEWIRE_SELECTION")
    if not selection.startswith("|valid:v2|") or not selection.endswith("|complete|"):
        raise ReceiptError("receipt selection is invalid")
    if (desktop_state != "unaffected") != ("|rust_pkg_codewire_desktop|" in selection):
        raise ReceiptError("desktop artifact state disagrees with selected verification")

    return {
        "schema": RECEIPT_SCHEMA,
        "repository": repository,
        "event": "pull_request",
        "pull_request": int(pr_number),
        "workflow_path": f"ci.yaml@refs/pull/{pr_number}/head",
        "run": {
            "id": int(require(env, "GITHUB_RUN_ID", POSITIVE_RE)),
            "attempt": run_attempt(env),
            "job": "Required verification",
        },
        "source": {
            "base_commit": base_commit,
            "head_commit": head_commit,
            "head_tree": head_tree,
        },
        "plan": {
            "schema": require(env, "CODEWIRE_PLAN_SCHEMA"),
            "sha256": require(env, "CODEWIRE_PLAN_SHA256", HEX64_RE),
            "status": require(env, "CODEWIRE_PLAN_STATUS"),
            "trusted_policy_commit": policy_commit,
            "policy_sha256": require(env, "CODEWIRE_POLICY_SHA256", HEX64_RE),
            "graph_sha256": require(env, "CODEWIRE_GRAPH_SHA256", HEX64_RE),
            "baseline_commit": require(env, "CODEWIRE_BASELINE_COMMIT", HEX40_RE),
            "artifacts": {
                "cw_cli_release_assets": cw_state,
                "desktop_package": desktop_state,
            },
        },
        "selection": selection,
        "results": {
            "selection": require_success(env, "CODEWIRE_SELECTION_RESULT"),
            "standard": require_success(env, "CODEWIRE_STANDARD_RESULT"),
            "rust_transport": require_success(env, "CODEWIRE_RUST_TRANSPORT_RESULT"),
            "database_services": require_success(env, "CODEWIRE_DATABASE_SERVICES_RESULT"),
            "edge_kind": require_success(env, "CODEWIRE_EDGE_KIND_RESULT"),
            "cw_release_assets": require_success(env, "CODEWIRE_CW_RELEASE_ASSETS_RESULT"),
        },
    }


def encode_receipt(receipt: dict[str, object]) -> str:
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode("ascii")


def main() -> int:
    try:
        receipt = build_receipt(os.environ)
        if receipt["plan"]["schema"] != PLAN_SCHEMA:  # type: ignore[index]
            raise ReceiptError("receipt plan schema is unsupported")
        if receipt["plan"]["status"] != "trusted":  # type: ignore[index]
            raise ReceiptError("pull-request receipt requires a trusted plan")
    except ReceiptError as exc:
        print(f"verification receipt: {exc}", file=sys.stderr)
        return 2
    print(f"{PREFIX}{encode_receipt(receipt)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
