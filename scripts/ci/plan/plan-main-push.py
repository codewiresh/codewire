#!/usr/bin/env python3
"""Choose CI's artifact facts for a push to main.

CI runs this file from the previous main commit's checkout
(.trusted-ci-policy), so a push never uses its own policy to reduce its own
checks: the planner and graph are the previous main's, and a push that changes
policy leaves every artifact unclassified.

It plans the cw, desktop and workspace-verification facts against the previous
main commit only when that commit's own CI push run verified it: the run
succeeded and dispatched its capability groups, so its Policy verification job
ran. A superseded run dispatches nothing and a failed run proved nothing; the
commits they carried are covered only by keeping every artifact selected, as
is any missing or unexpected fact, an unavailable push baseline (a force push)
and a planner failure.
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
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
SERVER_URL_RE = re.compile(r"^https?://[^/]+$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ZERO_SHA = "0" * 40
WORKFLOW = "ci.yaml"
MAIN_REF = "refs/heads/main"
API_LIMIT = 100
DISPATCH_PROOF_JOB = "Policy verification"
REQUIRED_JOB = "Required verification"
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


class Unproven(Exception):
    """The previous main commit is not a verified baseline."""


Fetch = Callable[[str], Any]


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


def forgejo_fetch(environ: dict[str, str]) -> Fetch:
    """GET a repository API path with the job token, as the receipt check does."""
    server_url = environ.get("GITHUB_SERVER_URL", "")
    repository = environ.get("GITHUB_REPOSITORY", "")
    token = environ.get("GITEA_TOKEN", "")
    if not SERVER_URL_RE.fullmatch(server_url):
        raise Unproven("invalid-server-url")
    if not REPOSITORY_RE.fullmatch(repository):
        raise Unproven("invalid-repository")
    if not token or any(character in token for character in "\r\n\""):
        raise Unproven("gitea-token-unavailable")
    api_base = f"{server_url.rstrip('/')}/api/v1/repos/{repository}"

    def fetch(path: str) -> Any:
        with tempfile.TemporaryDirectory(prefix="codewire-main-push-") as temporary:
            config = Path(temporary) / "curl-auth"
            descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as handle:
                handle.write(f'header = "Authorization: token {token}"\n')
            body = Path(temporary) / "body.json"
            try:
                completed = subprocess.run(
                    [
                        "curl", "--silent", "--show-error", "--max-time", "30",
                        "--config", str(config), "--output", str(body),
                        "--write-out", "%{http_code}", f"{api_base}{path}",
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise Unproven("forgejo-api-unavailable") from exc
            if completed.returncode != 0 or completed.stdout.strip() != "200":
                raise Unproven("forgejo-api-unavailable")
            try:
                return json.loads(body.read_text())
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise Unproven("forgejo-api-malformed") from exc

    return fetch


def succeeded(record: dict[str, Any]) -> bool:
    status = record.get("status")
    conclusion = record.get("conclusion")
    return (status == "completed" and conclusion == "success") or (
        status == "success" and conclusion in (None, "success")
    )


def bounded(document: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(document, list):
        items = document
    elif (
        isinstance(document, dict)
        and isinstance(document.get(key), list)
        and isinstance(document.get("total_count"), int)
        and not isinstance(document.get("total_count"), bool)
        and document["total_count"] == len(document[key])
    ):
        items = document[key]
    else:
        raise Unproven("forgejo-api-malformed")
    if len(items) > API_LIMIT:
        raise Unproven("forgejo-api-ambiguous")
    return [item for item in items if isinstance(item, dict)]


def verified_predecessor_run(fetch: Fetch, before: str) -> int:
    """The previous main commit's CI push run, when it verified that commit."""
    runs = bounded(
        fetch(
            f"/actions/runs?head_sha={before}&workflow_id={WORKFLOW}"
            f"&page=1&limit={API_LIMIT}"
        ),
        "workflow_runs",
    )
    candidates = [
        run
        for run in runs
        if (run.get("head_sha") or run.get("commit_sha")) == before
        and (run.get("event") or run.get("trigger_event")) == "push"
        and (
            run.get("path") == f"{WORKFLOW}@{MAIN_REF}"
            or (run.get("workflow_id") == WORKFLOW and run.get("prettyref") == "main")
        )
        and isinstance(run.get("id"), int)
        and not isinstance(run.get("id"), bool)
        and run["id"] > 0
    ]
    if not candidates:
        raise Unproven("predecessor-run-not-found")
    run = max(candidates, key=lambda candidate: candidate["id"])
    if not succeeded(run):
        raise Unproven("predecessor-run-not-successful")
    run_id = run["id"]
    jobs = bounded(
        fetch(f"/actions/runs/{run_id}/jobs?page=1&limit={API_LIMIT}"), "jobs"
    )

    def named(name: str) -> list[dict[str, Any]]:
        return [
            job
            for job in jobs
            if job.get("name") == name and job.get("run_id", run_id) == run_id
        ]

    required = named(REQUIRED_JOB)
    if len(required) != 1 or not succeeded(required[0]):
        raise Unproven("predecessor-run-not-successful")
    dispatch = named(DISPATCH_PROOF_JOB)
    if len(dispatch) != 1:
        raise Unproven("predecessor-jobs-ambiguous")
    if not succeeded(dispatch[0]):
        # Skipped: the run was superseded (or reused a receipt) and verified
        # nothing itself, so the commits it carried are still unverified.
        raise Unproven("predecessor-run-dispatched-nothing")
    return run_id


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
    fetch_factory: Callable[[dict[str, str]], Fetch] = forgejo_fetch,
) -> dict[str, str]:
    head = resolve(repository, head)
    try:
        if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != MAIN_REF:
            raise Unproven("not-main-push")
        baseline = push_baseline(repository, head, before)
        run_id = verified_predecessor_run(fetch_factory(environ), baseline)
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
