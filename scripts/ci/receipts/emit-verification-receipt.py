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
PREFIX = "CODEWIRE_CI_VERIFICATION_RECEIPT="
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")


class ReceiptError(RuntimeError):
    pass


SELECTION_RE = re.compile(r"^\|valid:v3\|(?:[a-z0-9_]+\|)*complete\|$")


def require(env: Mapping[str, str], key: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(key, "")
    if not value or (pattern and not pattern.fullmatch(value)):
        raise ReceiptError(f"receipt input {key} is invalid")
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
    if head_commit != require(env, "GITHUB_SHA", HEX40_RE):
        raise ReceiptError("receipt head does not equal the workflow head")
    require(env, "VERIFICATION_SELECTION", SELECTION_RE)

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
    }


def encode_receipt(receipt: dict[str, object]) -> str:
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode("ascii")


def main() -> int:
    try:
        receipt = build_receipt(os.environ)
    except ReceiptError as exc:
        print(f"verification receipt: {exc}", file=sys.stderr)
        return 2
    print(f"{PREFIX}{encode_receipt(receipt)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
