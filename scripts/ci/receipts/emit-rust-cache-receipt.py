#!/usr/bin/env python3
"""Emit one canonical-main Rust dependency-cache receipt in the job log."""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from typing import Mapping


RECEIPT_SCHEMA = "codewire.ci-rust-cache-receipt/v2"
PREFIX = "CODEWIRE_CI_RUST_CACHE_RECEIPT="
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
KEY_RE = re.compile(
    r"^codewire-rust-deps-v1-(generic|kind)-"
    r"(host-debug|host-ci|kind-ci|cw-cross-ci|desktop-release)-"
    r"[0-9a-f]{64}-[0-9a-f]{32}$"
)
FLAVORS = {
    "HOST_DEBUG": ("host-debug", "generic", "target/ci-cache/host-debug"),
    "HOST_CI": ("host-ci", "generic", "target/ci-cache/host-ci"),
    "KIND_CI": ("kind-ci", "kind", "target/ci-cache/kind-ci"),
    "CW_CROSS_CI": ("cw-cross-ci", "generic", "target/ci-cache/cw-cross-ci"),
    "DESKTOP_RELEASE": (
        "desktop-release",
        "generic",
        "target/ci-cache/desktop-release",
    ),
}


class ReceiptError(RuntimeError):
    pass


def require(env: Mapping[str, str], key: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(key, "")
    if not value or (pattern and not pattern.fullmatch(value)):
        raise ReceiptError(f"receipt input {key} is invalid")
    return value


def run_attempt(env: Mapping[str, str]) -> int:
    value = env.get("GITHUB_RUN_ATTEMPT", "") or "1"
    if not POSITIVE_RE.fullmatch(value):
        raise ReceiptError("receipt input GITHUB_RUN_ATTEMPT is invalid")
    return int(value)


def build_receipt(env: Mapping[str, str]) -> dict[str, object]:
    event = require(env, "GITHUB_EVENT_NAME")
    if event not in {"push", "workflow_dispatch"}:
        raise ReceiptError("Rust cache receipts require a canonical-main event")
    if require(env, "GITHUB_REF") != "refs/heads/main":
        raise ReceiptError("Rust cache receipts require refs/heads/main")
    repository = require(
        env,
        "GITHUB_REPOSITORY",
        re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"),
    )
    head_commit = require(env, "CODEWIRE_CACHE_HEAD_COMMIT", HEX40_RE)
    head_tree = require(env, "CODEWIRE_CACHE_HEAD_TREE", HEX40_RE)
    if head_commit != require(env, "GITHUB_SHA", HEX40_RE):
        raise ReceiptError("cache receipt head does not equal the workflow head")

    caches = []
    for env_name, (flavor, runner_pool, path) in FLAVORS.items():
        compatibility = require(
            env, f"CODEWIRE_RUST_CACHE_{env_name}_COMPATIBILITY", HEX64_RE
        )
        availability = env.get(f"CODEWIRE_RUST_CACHE_{env_name}_AVAILABLE", "")
        if availability not in {"true", "false"}:
            raise ReceiptError(f"cache availability for {flavor} is invalid")
        key = env.get(f"CODEWIRE_RUST_CACHE_{env_name}_KEY", "")
        if availability == "true":
            if not KEY_RE.fullmatch(key):
                raise ReceiptError(f"available cache key for {flavor} is invalid")
            expected_prefix = (
                f"codewire-rust-deps-v1-{runner_pool}-{flavor}-{compatibility}-"
            )
            if not key.startswith(expected_prefix):
                raise ReceiptError(f"cache key for {flavor} does not match its binding")
        elif key:
            raise ReceiptError(f"unavailable cache key for {flavor} must be empty")
        caches.append(
            {
                "flavor": flavor,
                "runner_pool": runner_pool,
                "compatibility": compatibility,
                "key": key if availability == "true" else None,
                "path": path,
                "max_bytes": 4294967296,
                "available": availability == "true",
            }
        )

    return {
        "schema": RECEIPT_SCHEMA,
        "repository": repository,
        "event": event,
        "workflow_path": "rust-cache-refresh.yaml@refs/heads/main",
        "run": {
            "id": int(require(env, "GITHUB_RUN_ID", POSITIVE_RE)),
            "attempt": run_attempt(env),
            "job": "Publish Rust cache receipt",
        },
        "source": {"head_commit": head_commit, "head_tree": head_tree},
        "caches": caches,
    }


def encode_receipt(receipt: dict[str, object]) -> str:
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(raw).decode("ascii")


def main() -> int:
    try:
        receipt = build_receipt(os.environ)
    except ReceiptError as exc:
        print(f"Rust cache receipt: {exc}", file=sys.stderr)
        return 2
    print(f"{PREFIX}{encode_receipt(receipt)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
