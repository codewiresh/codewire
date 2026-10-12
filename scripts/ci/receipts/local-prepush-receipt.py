#!/usr/bin/env python3
"""Emit and verify short-lived, exact-tree local verification receipts.

A receipt has a scope. ``push`` records the fast pre-push check; ``merge``
records merge qualification. Each receipt lists exactly the checks that ran,
the checks reused from an exact-tree pass, and the selected checks that did
not run locally (for example Kind, which post-merge CI owns).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence


SCHEMA = "codewire.local-verification-receipt/v2"
SCOPES = ("push", "merge")
EXPIRY_SECONDS = 8 * 60 * 60
MAX_RECEIPT_BYTES = 64 * 1024
HEX40 = set("0123456789abcdef")
CHECK_NAME = re.compile(r"^[a-z0-9][a-z0-9:._-]{0,95}$")
MAX_CHECKS = 256

POLICY_PATHS = (
    "scripts/ci/select/select-verification.sh",
)
PLANNER_PATHS = (
    "scripts/ci/select/select-verification.sh",
)
ENTRYPOINT_PATHS = (
    ".githooks/pre-push",
    "scripts/dev/pre-push.sh",
    "scripts/dev/preflight.sh",
    "scripts/dev/preflight-push.sh",
    "scripts/dev/preflight-environment.sh",
    "scripts/ci/receipts/local-prepush-receipt.py",
    "scripts/ci/verify/run-product-verification.sh",
    "scripts/ci/verify/run-integration-verification.sh",
    "scripts/ci/verify/kind-e2e.sh",
)
TOOLCHAIN_PATHS = (
    "rust-toolchain.toml",
    "go.mod",
    "go.sum",
    "package.json",
    "bun.lock",
)


class ReceiptError(RuntimeError):
    """One stable, non-sensitive receipt rejection reason."""


def fail(reason: str) -> ReceiptError:
    return ReceiptError(reason)


def run_git(root: Path, *args: str, text: bool = True) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise fail("git-state-unavailable") from exc
    return completed.stdout


def repository_root() -> Path:
    try:
        output = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise fail("repository-unavailable") from exc
    if not output:
        raise fail("repository-unavailable")
    return Path(output).resolve(strict=True)


def exact_commit(root: Path, value: str) -> str:
    resolved = str(run_git(root, "rev-parse", "--verify", f"{value}^{{commit}}")).strip()
    if len(resolved) != 40 or any(char not in HEX40 for char in resolved):
        raise fail("commit-invalid")
    return resolved


def exact_tree(root: Path, commit: str) -> str:
    tree = str(run_git(root, "rev-parse", f"{commit}^{{tree}}")).strip()
    if len(tree) != 40 or any(char not in HEX40 for char in tree):
        raise fail("tree-invalid")
    return tree


def common_dir(root: Path) -> Path:
    value = str(
        run_git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")
    ).strip()
    if not value:
        raise fail("common-directory-unavailable")
    return Path(value).resolve(strict=True)


def clean_worktree(root: Path) -> None:
    status = str(
        run_git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
    )
    if status:
        raise fail("dirty-worktree")


def remote_url(root: Path, requested: str | None) -> str:
    candidates: list[str] = []
    if requested:
        candidates.append(requested)
    candidates.extend(("gitea", "origin"))
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            value = subprocess.run(
                ["git", "-C", os.fspath(root), "remote", "get-url", candidate],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if value and "\n" not in value and "\r" not in value:
            return value
    raise fail("canonical-remote-unavailable")


def resolve_base(root: Path, requested: str | None) -> str:
    if requested and set(requested) != {"0"}:
        return exact_commit(root, requested)
    for candidate in ("gitea/main", "origin/main", "main"):
        try:
            return exact_commit(root, candidate)
        except ReceiptError:
            continue
    raise fail("canonical-base-unavailable")


def changed_paths(root: Path, base: str, head: str) -> list[str]:
    commands = (
        ("diff", "--name-only", "-z", f"{base}...{head}"),
        ("diff", "--name-only", "-z", base, head),
    )
    raw: bytes | None = None
    for command in commands:
        try:
            raw = subprocess.run(
                ["git", "-C", os.fspath(root), *command],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            break
        except (OSError, subprocess.CalledProcessError):
            continue
    if raw is None:
        raise fail("changed-paths-unavailable")
    paths: list[str] = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        try:
            path = encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise fail("changed-path-invalid") from exc
        if "\n" in path or "\r" in path:
            raise fail("changed-path-invalid")
        paths.append(path)
    return sorted(set(paths))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def paths_digest(paths: Sequence[str]) -> str:
    return sha256_bytes("".join(f"{path}\n" for path in paths).encode("utf-8"))


def committed_path_digest(root: Path, head: str, paths: Sequence[str]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode("utf-8") + b"\0")
        try:
            value = subprocess.run(
                ["git", "-C", os.fspath(root), "show", f"{head}:{path}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            value = b"<absent>"
        digest.update(hashlib.sha256(value).digest())
    return digest.hexdigest()


def parse_selector_output(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            raise fail("selection-malformed")
        fields[key] = value
    required = {"selector_version", "classification", "selection", "required_local_mode"}
    if set(fields) != required:
        raise fail("selection-malformed")
    if not fields["selection"].startswith(f"|valid:{fields['selector_version']}|"):
        raise fail("selection-malformed")
    if not fields["selection"].endswith("|complete|"):
        raise fail("selection-malformed")
    if fields["required_local_mode"] not in {"default", "integration", "kind", "full"}:
        raise fail("selection-malformed")
    return fields


def invoke_selector(root: Path, paths: Sequence[str], full: bool = False) -> dict[str, str]:
    selector = root / "scripts/ci/select/select-verification.sh"
    environment = os.environ.copy()
    environment.pop("GITHUB_OUTPUT", None)
    environment.pop("GITHUB_EVENT_PATH", None)
    if full:
        environment.update(GITHUB_EVENT_NAME="workflow_dispatch", VERIFICATION_REQUEST="all")
        command = [os.fspath(selector)]
        path_file: Path | None = None
    else:
        # Local qualification mirrors pull-request CI without the Kind opt-in:
        # Kind is a dev-loop tool here and a post-merge CI gate.
        environment.update(GITHUB_EVENT_NAME="pull_request", KIND_E2E_OPT_IN="false")
        fd, path_name = tempfile.mkstemp(prefix="codewire-prepush-paths.")
        path_file = Path(path_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for path in paths:
                handle.write(f"{path}\n")
        command = [os.fspath(selector), os.fspath(path_file)]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise fail("selection-unavailable") from exc
    finally:
        if path_file is not None:
            path_file.unlink(missing_ok=True)
    return parse_selector_output(completed.stdout)


def selected_checks(selection: str) -> list[str]:
    tokens = [token for token in selection.split("|") if token]
    if len(tokens) < 2 or not tokens[0].startswith("valid:") or tokens[-1] != "complete":
        raise fail("selection-malformed")
    return tokens[1:-1]


def current_context(
    root: Path,
    *,
    head_value: str,
    base_value: str | None,
    remote_name: str | None,
) -> dict[str, Any]:
    clean_worktree(root)
    head = exact_commit(root, head_value)
    tree = exact_tree(root, head)
    base = resolve_base(root, base_value)
    paths = changed_paths(root, base, head)
    initial = invoke_selector(root, paths)
    mode = initial["required_local_mode"]
    effective = invoke_selector(root, paths, full=True) if mode == "full" else initial
    selection = effective["selection"]
    common = common_dir(root)
    canonical_url = remote_url(root, remote_name)
    repository_id = sha256_bytes(canonical_url.encode("utf-8"))
    worktree_id = sha256_bytes(os.fspath(root).encode("utf-8"))
    policy_digest = committed_path_digest(root, head, POLICY_PATHS)
    planner_digest = committed_path_digest(root, head, PLANNER_PATHS)
    entrypoint_digest = committed_path_digest(root, head, ENTRYPOINT_PATHS)
    toolchain_digest = committed_path_digest(root, head, TOOLCHAIN_PATHS)
    path_digest = paths_digest(paths)
    plan_material = {
        "base_commit": base,
        "head_commit": head,
        "head_tree": tree,
        "paths_sha256": path_digest,
        "classification": initial["classification"],
        "selection": selection,
        "mode": mode,
        "policy_sha256": policy_digest,
        "planner_sha256": planner_digest,
    }
    plan_digest = sha256_bytes(
        json.dumps(plan_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    return {
        "repository": {
            "id": repository_id,
            "canonical_url": canonical_url,
            "git_common_dir": os.fspath(common),
        },
        "worktree": {"id": worktree_id, "real_path": os.fspath(root)},
        "source": {"commit": head, "tree": tree, "base_commit": base},
        "policy": {
            "id": "codewire/local-ci-policy-v3",
            "version": initial["selector_version"],
            "digest": policy_digest,
        },
        "planner": {
            "id": "codewire/select-verification",
            "version": initial["selector_version"],
            "digest": planner_digest,
        },
        "plan": {
            "digest": plan_digest,
            "changed_paths_digest": path_digest,
            "classification": initial["classification"],
            "selected_checks": selected_checks(selection),
            "selection": selection,
            "required_local_mode": mode,
        },
        "verification": {
            "entrypoint_id": "scripts/dev/preflight.sh",
            "entrypoint_version": 2,
            "digest": entrypoint_digest,
        },
        "toolchain": {"digest": toolchain_digest},
        "runner": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        },
    }


def check_list(value: str | Sequence[str]) -> list[str]:
    if isinstance(value, str):
        names = [item for item in value.split(",") if item]
    else:
        names = list(value)
    if len(names) > MAX_CHECKS:
        raise fail("execution-invalid")
    for name in names:
        if not isinstance(name, str) or not CHECK_NAME.match(name):
            raise fail("execution-invalid")
    if len(set(names)) != len(names):
        raise fail("execution-invalid")
    return names


def execution_record(scope: str, ran: Sequence[str], reused: Sequence[str],
                     not_run: Sequence[str]) -> dict[str, Any]:
    """Validate the honest record of what this qualification executed."""
    if scope not in SCOPES:
        raise fail("execution-invalid")
    ran_names = check_list(ran)
    reused_names = check_list(reused)
    not_run_names = check_list(not_run)
    every = [*ran_names, *reused_names, *not_run_names]
    if len(set(every)) != len(every) or not (ran_names or reused_names):
        raise fail("execution-invalid")
    return {
        "scope": scope,
        "ran": ran_names,
        "reused": reused_names,
        "not_run": not_run_names,
    }


def validated_execution(document: dict[str, Any]) -> dict[str, Any]:
    execution = document.get("execution")
    if not isinstance(execution, dict) or set(execution) != {"scope", "ran", "reused", "not_run"}:
        raise fail("execution-invalid")
    for key in ("ran", "reused", "not_run"):
        if not isinstance(execution[key], list):
            raise fail("execution-invalid")
    record = execution_record(
        execution["scope"], execution["ran"], execution["reused"], execution["not_run"]
    )
    if record != execution:
        raise fail("execution-invalid")
    return record


def receipt_path(context: dict[str, Any], scope: str) -> Path:
    if scope not in SCOPES:
        raise fail("execution-invalid")
    common = Path(context["repository"]["git_common_dir"])
    # One file per scope: a later push check never replaces merge evidence.
    return (
        common
        / "codewire-receipts"
        / "prepush-v2"
        / context["repository"]["id"]
        / context["worktree"]["id"]
        / f"{context['source']['commit']}.{scope}.json"
    )


def ensure_private_directories(common: Path, leaf: Path) -> None:
    current = common
    relative = leaf.relative_to(common)
    for part in relative.parts:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise fail("receipt-directory-unsafe")
        os.chmod(current, 0o700)


def emit_receipt(context: dict[str, Any], execution: dict[str, Any]) -> Path:
    now = int(time.time())
    document = {
        "schema": SCHEMA,
        **context,
        "execution": execution,
        "created_at": now,
        "expires_at": now + EXPIRY_SECONDS,
        "result": "success",
    }
    path = receipt_path(context, execution["scope"])
    common = Path(context["repository"]["git_common_dir"])
    ensure_private_directories(common, path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.stem}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def load_receipt(path: Path, common: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise fail("missing") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise fail("receipt-file-unsafe")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise fail("receipt-permissions-unsafe")
    if info.st_size <= 0 or info.st_size > MAX_RECEIPT_BYTES:
        raise fail("receipt-size-invalid")
    current = path.parent
    while current != common:
        directory_info = current.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.getuid()
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise fail("receipt-directory-unsafe")
        current = current.parent

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise fail("malformed")
            document[key] = value
        return document

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise fail("malformed") from exc
    if not isinstance(document, dict):
        raise fail("malformed")
    return document


def verify_receipt(context: dict[str, Any], accepted_scopes: Sequence[str]) -> tuple[Path, dict[str, Any]]:
    """Accept the strongest valid scope; report the strongest present failure."""
    failure: ReceiptError | None = None
    for scope in sorted(accepted_scopes, key=lambda name: SCOPES.index(name), reverse=True):
        try:
            return verify_scope_receipt(context, scope)
        except ReceiptError as exc:
            if failure is None or str(failure) == "missing":
                failure = exc
    raise failure if failure is not None else fail("missing")


def verify_scope_receipt(context: dict[str, Any], scope: str) -> tuple[Path, dict[str, Any]]:
    path = receipt_path(context, scope)
    document = load_receipt(path, Path(context["repository"]["git_common_dir"]))
    expected_keys = {
        "schema",
        "repository",
        "worktree",
        "source",
        "policy",
        "planner",
        "plan",
        "verification",
        "toolchain",
        "runner",
        "execution",
        "created_at",
        "expires_at",
        "result",
    }
    if set(document) != expected_keys or document.get("schema") != SCHEMA:
        raise fail("schema-mismatch")
    for key, expected in context.items():
        if document.get(key) != expected:
            raise fail(f"{key}-mismatch")
    created = document.get("created_at")
    expires = document.get("expires_at")
    if not isinstance(created, int) or not isinstance(expires, int):
        raise fail("expiry-invalid")
    if expires - created != EXPIRY_SECONDS or created > int(time.time()) + 300:
        raise fail("expiry-invalid")
    if int(time.time()) > expires:
        raise fail("expired")
    if document.get("result") != "success":
        raise fail("result-not-success")
    execution = validated_execution(document)
    if execution["scope"] != scope:
        raise fail("scope-mismatch")
    return path, execution


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check-clean")
    emit = subparsers.add_parser("emit")
    emit.add_argument("--verified-base", required=True)
    emit.add_argument("--verified-mode", required=True)
    emit.add_argument("--verified-selection", required=True)
    emit.add_argument("--scope", required=True, choices=SCOPES)
    emit.add_argument("--ran", required=True)
    emit.add_argument("--reused", default="")
    emit.add_argument("--not-run", default="")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--head", default="HEAD")
    verify.add_argument("--base")
    verify.add_argument("--remote-name")
    # A feature-branch push accepts either scope. A direct canonical-main
    # update (the only case that passes --base) requires merge qualification.
    verify.add_argument("--accept-scope", choices=("any", "merge"))
    path = subparsers.add_parser("path")
    path.add_argument("--scope", default="merge", choices=SCOPES)
    path.add_argument("--head", default="HEAD")
    path.add_argument("--base")
    path.add_argument("--remote-name")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        root = repository_root()
        if arguments.command == "check-clean":
            clean_worktree(root)
            print("receipt_precondition=clean")
            return 0
        context = current_context(
            root,
            head_value=arguments.head if arguments.command != "emit" else "HEAD",
            base_value=(
                arguments.base
                if arguments.command != "emit"
                else arguments.verified_base
            ),
            remote_name=arguments.remote_name if arguments.command != "emit" else None,
        )
        if arguments.command == "emit":
            execution = execution_record(
                arguments.scope, arguments.ran, arguments.reused, arguments.not_run
            )
            if context["source"]["base_commit"] != arguments.verified_base:
                raise fail("verified-base-mismatch")
            if context["plan"]["required_local_mode"] != arguments.verified_mode:
                raise fail("verified-mode-mismatch")
            if context["plan"]["selection"] != arguments.verified_selection:
                raise fail("verified-selection-mismatch")
            path = emit_receipt(context, execution)
            print("receipt=emitted")
            print("reason=exact-tree")
            print(f"scope={execution['scope']}")
            print(f"receipt_path={path}")
            return 0
        if arguments.command == "path":
            print(receipt_path(context, arguments.scope))
            return 0
        accept_scope = arguments.accept_scope or ("merge" if arguments.base else "any")
        accepted_scopes = SCOPES if accept_scope == "any" else ("merge",)
        path, execution = verify_receipt(context, accepted_scopes)
        print("receipt=accepted")
        print("reason=exact-tree")
        print(f"scope={execution['scope']}")
        print(f"ran={','.join(execution['ran'])}")
        print(f"reused={','.join(execution['reused'])}")
        print(f"not_run={','.join(execution['not_run'])}")
        print(f"receipt_path={path}")
        return 0
    except ReceiptError as exc:
        print("receipt=invalid")
        print(f"reason={exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
