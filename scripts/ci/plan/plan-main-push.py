#!/usr/bin/env python3
"""Choose CI's artifact facts for a push to main.

CI runs this file from the previous main commit's checkout
(.trusted-ci-policy), so a push never uses its own policy to reduce its own
checks: the planner and graph are the previous main's, and a push that changes
policy leaves every artifact unclassified.

It plans the cw, desktop and workspace-verification facts against the previous
main commit only when main CI's verdict verified that commit
(main-ci-verdict.py, the predicate Dev delivery uses too): its own ci.yaml
push run on main printed the verdict marker, after every selected capability
group succeeded or an exact tested-tree receipt was accepted. A superseded run
verified nothing and a failed run proved nothing; the commits they carried are
covered only by keeping every artifact selected, as is a pending or missing
run, any missing or unexpected fact, an unavailable push baseline (a force
push) and a planner failure.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Callable

HERE = Path(__file__).resolve().parent
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
ZERO_SHA = "0" * 40
MAIN_REF = "refs/heads/main"
REPORTED_ARTIFACTS = (
    "cw_cli_release_assets",
    "desktop_package",
    "workspace_image_verification",
)


def load(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


planner = load("codewire_ci_main_push_planner", "planner.py")
adapter = load("codewire_ci_main_push_adapter", "apply-verification-plan.py")
verdicts = load("codewire_ci_main_push_verdict", "main-ci-verdict.py")

# The previous main commit is not a verified baseline.
Unproven = verdicts.Unproven
ForgejoFactory = Callable[[dict[str, str]], "verdicts.ForgejoAPI"]


def git(repository: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise Unproven(f"git {args[0]} failed")
    return completed.stdout.strip()


def resolve(repository: Path, revision: str) -> str:
    commit = git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if not HEX40_RE.fullmatch(commit):
        raise Unproven("git returned an invalid commit")
    return commit


def push_baseline(repository: Path, head: str, before: str) -> str:
    """The previous main commit, when the push extends it."""
    if not HEX40_RE.fullmatch(before) or before == ZERO_SHA:
        raise Unproven("push-baseline-unavailable")
    try:
        resolved = resolve(repository, before)
    except Unproven as exc:
        raise Unproven("push-baseline-unavailable") from exc
    if resolved != before or before == head:
        raise Unproven("push-baseline-unavailable")
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", before, head],
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        # A force push (or any rewrite) leaves no range to plan.
        raise Unproven("push-baseline-unavailable")
    return before


def forgejo_api(environ: dict[str, str]) -> "verdicts.ForgejoAPI":
    """The repository API with the job token, as the receipt check uses it."""
    return verdicts.ForgejoAPI.from_environ(environ)


def verified_predecessor_run(api: "verdicts.ForgejoAPI", repository: Path, before: str) -> int:
    """The previous main commit's CI push run, when main CI's verdict verified it."""
    tree = git(repository, "rev-parse", f"{before}^{{tree}}")
    result = verdicts.verdict(api, before, tree)
    if not result.verified:
        raise Unproven(f"predecessor-{result.reason}")
    return result.run_id


def planned_outputs(repository: Path, head: str, before: str) -> dict[str, str]:
    document = planner.plan(repository, before, head, trusted_policy_revision=before)
    for reason in document.get("degraded_reasons", []):
        print(f"main artifact facts: planner degraded: {reason}")
    for name in REPORTED_ARTIFACTS:
        fact = document["artifacts"].get(name, {})
        explanations = fact.get("explanations") or ["no explanation"]
        print(f"main artifact facts: {name}={fact.get('state')} ({explanations[0]})")
    with tempfile.TemporaryDirectory(prefix="codewire-main-push-plan-") as temporary:
        plan_path = Path(temporary) / "plan.json"
        plan_path.write_text(json.dumps(document, sort_keys=True) + "\n")
        outputs = adapter.trusted_plan_outputs(plan_path)
    if outputs.get("ci_head_commit") != head:
        raise adapter.AdapterError("plan head does not match the pushed commit")
    return outputs


def choose_outputs(
    repository: Path,
    head: str,
    before: str,
    environ: dict[str, str],
    api_factory: ForgejoFactory = forgejo_api,
) -> dict[str, str]:
    head = resolve(repository, head)
    try:
        if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != MAIN_REF:
            raise Unproven("not-main-push")
        baseline = push_baseline(repository, head, before)
        run_id = verified_predecessor_run(api_factory(environ), repository, baseline)
        print(
            f"main artifact facts: {baseline} was verified by CI run {run_id}; "
            f"planning {baseline}..{head} with that commit's policy"
        )
        return planned_outputs(repository, head, baseline)
    except Unproven as exc:
        reason = str(exc)
    except (
        planner.PlannerError,
        adapter.AdapterError,
        OSError,
        UnicodeError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ) as exc:
        reason = f"planner-failed: {exc}"
    print(f"main artifact facts: every artifact stays selected ({reason})")
    tree = git(repository, "rev-parse", f"{head}^{{tree}}")
    return adapter.unclassified_outputs(argparse.Namespace(head=head, head_tree=tree))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=".")
    parser.add_argument("--head", required=True)
    parser.add_argument("--before", default="")
    parser.add_argument("--output", required=True, help="file that receives key=value outputs")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        outputs = choose_outputs(
            Path(args.repository).resolve(), args.head, args.before, dict(os.environ)
        )
    except (Unproven, adapter.AdapterError, OSError) as exc:
        print(f"main artifact facts: {exc}", file=sys.stderr)
        return 2
    rendered = "".join(f"{key}={value}\n" for key, value in outputs.items())
    with Path(args.output).open("a", encoding="utf-8") as handle:
        handle.write(rendered)
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
