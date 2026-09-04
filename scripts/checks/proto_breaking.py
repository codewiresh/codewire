#!/usr/bin/env python3
"""Run Buf breaking checks with exact, reviewed internal contract retirements."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
RETIREMENTS = ROOT / "scripts/checks/contracts/proto-retirements.sha256"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
INTERNAL_PREFIX = "proto/codewire/internal/"


class PolicyError(RuntimeError):
    """An intentional-retirement policy violation."""


def parse_retirements(text: str) -> dict[str, str]:
    retirements: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 2 or SHA256_RE.fullmatch(fields[0]) is None:
            raise PolicyError(f"invalid retirement entry on line {line_number}")
        digest, path = fields
        if (
            not path.startswith(INTERNAL_PREFIX)
            or not path.endswith(".proto")
            or ".." in Path(path).parts
        ):
            raise PolicyError(
                f"retirement path must name an internal proto: {path}"
            )
        if path in retirements:
            raise PolicyError(f"duplicate retirement path: {path}")
        retirements[path] = digest
    return retirements


def validate_deletions(
    deleted_digests: dict[str, str], retirements: dict[str, str]
) -> None:
    for path, digest in deleted_digests.items():
        expected = retirements.get(path)
        if expected is None:
            raise PolicyError(f"unreviewed proto deletion: {path}")
        if digest != expected:
            raise PolicyError(
                f"retired proto digest mismatch for {path}: "
                f"expected {expected}, got {digest}"
            )


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def deleted_proto_digests(base_sha: str) -> dict[str, str]:
    paths = git_output(
        "diff",
        "--no-renames",
        "--diff-filter=D",
        "--name-only",
        base_sha,
        "--",
        "proto",
    ).splitlines()
    deleted: dict[str, str] = {}
    for path in paths:
        if not path.endswith(".proto"):
            continue
        content = subprocess.run(
            ["git", "show", f"{base_sha}:{path}"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        deleted[path] = hashlib.sha256(content).hexdigest()
    return deleted


def run_breaking(base_sha: str) -> None:
    resolved_base = git_output("rev-parse", "--verify", f"{base_sha}^{{commit}}").strip()
    retirements = parse_retirements(RETIREMENTS.read_text(encoding="utf-8"))
    for path in retirements:
        if (ROOT / path).exists():
            raise PolicyError(f"retired proto is present in the current tree: {path}")
    deleted = deleted_proto_digests(resolved_base)
    validate_deletions(deleted, retirements)

    buf = os.environ.get("BUF") or shutil.which("buf")
    if not buf:
        raise PolicyError("buf executable not found")
    subprocess.run(
        [
            buf,
            "breaking",
            "--limit-to-input-files",
            "--against",
            f"../.git#commit={resolved_base},subdir=proto",
        ],
        cwd=ROOT / "proto",
        check=True,
    )
    print(
        "proto breaking policy: OK "
        f"({len(deleted)} reviewed deletion(s), retained files strict)"
    )


def self_test() -> None:
    digest = "a" * 64
    path = "proto/codewire/internal/v1/retired.proto"
    parsed = parse_retirements(f"# reviewed\n{digest}  {path}\n")
    assert parsed == {path: digest}
    validate_deletions({path: digest}, parsed)

    for deleted, allowed, fragment in [
        ({"proto/codewire/internal/v1/other.proto": digest}, parsed, "unreviewed"),
        ({path: "b" * 64}, parsed, "digest mismatch"),
    ]:
        try:
            validate_deletions(deleted, allowed)
        except PolicyError as error:
            assert fragment in str(error)
        else:
            raise AssertionError(f"policy accepted invalid deletion: {fragment}")

    for entry in [
        f"{digest} proto/codewire/v1/public.proto",
        f"{digest} proto/codewire/internal/../v1/traversal.proto",
        f"not-a-digest {path}",
        f"{digest} {path}\n{digest} {path}",
    ]:
        try:
            parse_retirements(entry)
        except PolicyError:
            pass
        else:
            raise AssertionError(f"policy accepted invalid retirement: {entry!r}")
    print("proto breaking retirement policy self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-sha")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            if not args.base_sha:
                parser.error("--base-sha is required unless --self-test is used")
            run_breaking(args.base_sha)
    except (PolicyError, subprocess.CalledProcessError) as error:
        print(f"proto breaking policy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
