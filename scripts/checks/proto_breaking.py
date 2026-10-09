#!/usr/bin/env python3
"""Run Buf checks with exact preimages for reviewed prelaunch clean breaks."""

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
PREIMAGES = ROOT / "scripts/checks/contracts/proto-breaking-preimages.sha256"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CODEWIRE_PREFIX = "proto/codewire/"


class PolicyError(RuntimeError):
    """An intentional clean-break policy violation."""


Preimage = tuple[str, str, str]


def parse_preimages(text: str) -> set[Preimage]:
    preimages: set[Preimage] = set()
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if (
            len(fields) != 3
            or fields[0] not in {"delete", "replace"}
            or SHA256_RE.fullmatch(fields[1]) is None
        ):
            raise PolicyError(f"invalid preimage entry on line {line_number}")
        mode, digest, path = fields
        if (
            not path.startswith(CODEWIRE_PREFIX)
            or not path.endswith(".proto")
            or ".." in Path(path).parts
        ):
            raise PolicyError(f"preimage path must name a Codewire proto: {path}")
        entry = (mode, digest, path)
        if entry in preimages:
            raise PolicyError(f"duplicate preimage entry: {path}")
        preimages.add(entry)
    return preimages


def validate_changes(
    deleted_digests: dict[str, str],
    replaced_digests: dict[str, str],
    current_preimages: set[Preimage],
    base_preimages: set[Preimage],
    current_paths: set[str],
) -> tuple[list[str], set[Preimage]]:
    removed_preimages = base_preimages - current_preimages
    if removed_preimages:
        _, _, path = sorted(removed_preimages)[0]
        raise PolicyError(f"historical preimage entry was removed: {path}")

    for mode, _, path in current_preimages:
        if mode == "delete" and path in current_paths:
            raise PolicyError(f"retired proto is present in the current tree: {path}")

    active_preimages = current_preimages - base_preimages
    active_by_path: dict[str, tuple[str, str]] = {}
    for mode, digest, path in active_preimages:
        if path in active_by_path:
            raise PolicyError(f"multiple active preimage entries for {path}")
        active_by_path[path] = (mode, digest)

    for path, digest in deleted_digests.items():
        allowance = active_by_path.get(path)
        if allowance is None or allowance[0] != "delete":
            raise PolicyError(f"unreviewed proto deletion: {path}")
        expected = allowance[1]
        if digest != expected:
            raise PolicyError(
                f"deleted proto preimage mismatch for {path}: "
                f"expected {expected}, got {digest}"
            )
    excluded: list[str] = []
    for path, (mode, expected) in active_by_path.items():
        changed_digests = deleted_digests if mode == "delete" else replaced_digests
        digest = changed_digests.get(path)
        if digest is None:
            raise PolicyError(f"unused active {mode} preimage: {path}")
        if digest != expected:
            raise PolicyError(
                f"{mode} proto preimage mismatch for {path}: "
                f"expected {expected}, got {digest}"
            )
        if mode == "replace":
            excluded.append(path.removeprefix("proto/"))
    return sorted(excluded), active_preimages


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return result.stdout


def changed_proto_digests(base_sha: str, diff_filter: str) -> dict[str, str]:
    paths = git_output(
        "diff",
        "--no-renames",
        f"--diff-filter={diff_filter}",
        "--name-only",
        base_sha,
        "--",
        "proto",
    ).splitlines()
    changed: dict[str, str] = {}
    for path in paths:
        if not path.endswith(".proto"):
            continue
        content = subprocess.run(
            ["git", "show", f"{base_sha}:{path}"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        changed[path] = hashlib.sha256(content).hexdigest()
    return changed


def base_preimages(base_sha: str) -> set[Preimage]:
    relative = PREIMAGES.relative_to(ROOT).as_posix()
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{base_sha}:{relative}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if exists.returncode != 0:
        return set()
    return parse_preimages(git_output("show", f"{base_sha}:{relative}"))


def run_breaking(base_sha: str) -> None:
    resolved_base = git_output("rev-parse", "--verify", f"{base_sha}^{{commit}}").strip()
    current_preimages = parse_preimages(PREIMAGES.read_text(encoding="utf-8"))
    historical_preimages = base_preimages(resolved_base)
    deleted = changed_proto_digests(resolved_base, "D")
    replaced = changed_proto_digests(resolved_base, "M")
    current_paths = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "proto").rglob("*.proto")
    }
    excluded, active = validate_changes(
        deleted,
        replaced,
        current_preimages,
        historical_preimages,
        current_paths,
    )

    buf = os.environ.get("BUF") or shutil.which("buf")
    if not buf:
        raise PolicyError("buf executable not found")
    checked_paths = [
        path.relative_to(ROOT / "proto").as_posix()
        for path in sorted((ROOT / "proto").rglob("*.proto"))
        if path.relative_to(ROOT / "proto").as_posix() not in excluded
    ]
    if not checked_paths:
        raise PolicyError("no protobuf files remain under strict breaking checks")
    command = [
        buf,
        "breaking",
        "--exclude-imports",
        "--against",
        f"../.git#commit={resolved_base},subdir=proto",
    ]
    for path in checked_paths:
        command.extend(["--path", path])
    # Buf fetches the comparison tree with Git. Join its automatic maintenance
    # before returning so verification owns the complete process family.
    environment = os.environ.copy()
    try:
        config_count = int(environment.get("GIT_CONFIG_COUNT") or "0")
    except ValueError:
        raise PolicyError("invalid inherited Git configuration count") from None
    if config_count < 0:
        raise PolicyError("invalid inherited Git configuration count")
    for key in ("maintenance.autoDetach", "gc.autoDetach"):
        environment[f"GIT_CONFIG_KEY_{config_count}"] = key
        environment[f"GIT_CONFIG_VALUE_{config_count}"] = "false"
        config_count += 1
    environment["GIT_CONFIG_COUNT"] = str(config_count)
    subprocess.run(command, cwd=ROOT / "proto", check=True, env=environment)
    print(
        "proto breaking policy: OK "
        f"({sum(mode == 'delete' for mode, _, _ in active)} reviewed deletion(s), "
        f"{sum(mode == 'replace' for mode, _, _ in active)} reviewed replacement(s), "
        "all others strict)"
    )


def self_test() -> None:
    digest = "a" * 64
    deleted_path = "proto/codewire/internal/v1/retired.proto"
    replaced_path = "proto/codewire/v1/replaced.proto"
    parsed = parse_preimages(
        f"# reviewed\ndelete {digest} {deleted_path}\n"
        f"replace {digest} {replaced_path}\n"
    )
    assert parsed == {
        ("delete", digest, deleted_path),
        ("replace", digest, replaced_path),
    }
    excluded, active = validate_changes(
        {deleted_path: digest},
        {replaced_path: digest},
        parsed,
        set(),
        {replaced_path},
    )
    assert excluded == ["codewire/v1/replaced.proto"]
    assert active == parsed

    historical_replace = {("replace", digest, replaced_path)}
    excluded, active = validate_changes(
        {},
        {replaced_path: digest},
        historical_replace,
        historical_replace,
        {replaced_path},
    )
    assert excluded == []
    assert active == set()

    for deleted, replaced, current, historical, paths, fragment in [
        (
            {"proto/codewire/internal/v1/other.proto": digest},
            {},
            parsed,
            set(),
            {replaced_path},
            "unreviewed",
        ),
        (
            {deleted_path: "b" * 64},
            {replaced_path: digest},
            parsed,
            set(),
            {replaced_path},
            "preimage mismatch",
        ),
        (
            {deleted_path: digest},
            {replaced_path: "b" * 64},
            parsed,
            set(),
            {replaced_path},
            "preimage mismatch",
        ),
        (
            {},
            {},
            {("replace", digest, replaced_path)},
            set(),
            {replaced_path},
            "unused active replace",
        ),
        (
            {},
            {},
            set(),
            {("replace", digest, replaced_path)},
            {replaced_path},
            "historical preimage entry was removed",
        ),
        (
            {},
            {},
            {("delete", digest, deleted_path)},
            {("delete", digest, deleted_path)},
            {deleted_path},
            "retired proto is present",
        ),
    ]:
        try:
            validate_changes(
                deleted,
                replaced,
                current,
                historical,
                paths,
            )
        except PolicyError as error:
            assert fragment in str(error)
        else:
            raise AssertionError(f"policy accepted invalid change: {fragment}")

    for entry in [
        f"replace {digest} third_party/public.proto",
        f"replace {digest} proto/codewire/internal/../v1/traversal.proto",
        f"unknown {digest} {deleted_path}",
        f"replace not-a-digest {deleted_path}",
        f"delete {digest} {deleted_path}\ndelete {digest} {deleted_path}",
    ]:
        try:
            parse_preimages(entry)
        except PolicyError:
            pass
        else:
            raise AssertionError(f"policy accepted invalid preimage: {entry!r}")
    print("proto breaking preimage policy self-test: OK")


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
