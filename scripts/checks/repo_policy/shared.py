#!/usr/bin/env python3
"""Repository policy checks for Codewire.

This is intentionally stdlib-only. These checks run in CI and during local
preflight, so they should not depend on the JavaScript toolchain unless the
check is explicitly validating JavaScript package output.
"""

from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[3]


def read_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def read_json(rel: str) -> Any:
    return json.loads(read_text(rel))



def stable_json(value: Any) -> str:
    return json.dumps(sort_json(value), ensure_ascii=False, separators=(",", ":"))


def sort_json(value: Any) -> Any:
    if isinstance(value, list):
        return [sort_json(item) for item in value]
    if isinstance(value, dict):
        return {key: sort_json(value[key]) for key in sorted(value)}
    return value


def run(
    args: list[str],
    *,
    cwd: Path = ROOT,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    result = subprocess.run(
        args,
        cwd=cwd,
        env=merged_env,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise RuntimeError(f"{args[0]} {' '.join(args[1:])} failed: {detail}")
    return result


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def walk_files(directory: Path) -> list[Path]:
    return [path for path in directory.rglob("*") if path.is_file()]


def report(prefix: str, failures: list[str], *, error_annotation: bool = False) -> int:
    if failures:
        for failure in failures:
            if error_annotation:
                print(f"::error::{prefix}: {failure}", file=sys.stderr)
            else:
                print(f"{prefix}: {failure}", file=sys.stderr)
        return 1
    return 0


def git_source_files() -> list[str]:
    result = run(

        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        check=True,
    )
    return [
        path
        for path in result.stdout.split("\0")
        if path and (ROOT / path).is_file()
    ]
