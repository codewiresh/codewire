#!/usr/bin/env python3
"""One release delivery at a time per workflow, without a queue of no-op runs.

The owner's plan (2026-11-12, recorded on #3013): a scheduled deploy-prod or
cli-release run that finds another run of its workflow ahead of it ends at
once without delivering; a dispatched run waits its turn and always delivers;
a running publication is never cancelled. The workflows have no concurrency
group, so Forgejo queues nothing: before, every scheduled run waited in one
group behind the running one, three at a time (ForgejoCiJobWaitingTooLong),
only to find nothing to deliver. A per-run group did not help: Forgejo
evaluates the group before the run has an ID, so every run shared it.

The first job of each run ("Find the release to deliver") runs this before it
names a release. Another unfinished run of the workflow on main is ahead when
  - it is still looking: its first job has not ended and its run ID is lower,
    so it started first; or
  - it is delivering: its first job succeeded and its release selection job
    ("Verify canonical ... release tag") has not been skipped or ended
    without success.
A run that found nothing is not ahead, even while Forgejo is still settling
its skipped jobs: that took about 20 minutes for one cli-release run on
2026-11-12, so counting it would make every later schedule skip in turn.

A scheduled run that cannot read the other runs skips too; the next schedule,
five minutes later, looks again. A dispatch whose turn does not come within
its bound, or that cannot read the other runs, fails with the reason, and is
dispatched again.

Usage: release-turn.py deploy-prod|cli-release (reads GITHUB_EVENT_NAME,
GITHUB_RUN_ID, GITHUB_SERVER_URL, GITHUB_REPOSITORY and GITEA_TOKEN). Writes
turn=go or turn=skip to GITHUB_OUTPUT; exits 1 when a dispatch fails.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Callable

HERE = Path(__file__).resolve().parent
MAIN_REF = "refs/heads/main"
FIND_JOB = "Find the release to deliver"
SELECTION_JOBS = {
    "deploy-prod": "Verify canonical release tag",
    "cli-release": "Verify canonical CLI release tag",
}
UNFINISHED_RUN_STATES = ("waiting", "blocked", "running", "unknown")
POLL_SECONDS = 30
# Longer than one release: deploy-prod's longest path (publish, both platform
# builds, finish) and cli-release's macOS build each fit well inside it.
WAIT_SECONDS = 180 * 60
UNREADABLE_LIMIT = 5

GO = "go"
SKIP = "skip"


def load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load("codewire_ci_release_turn_verdict", HERE.parent / "plan" / "main-ci-verdict.py")
Unproven = verdicts.Unproven


class Failed(Exception):
    """A dispatch cannot take its turn."""


def unfinished_main_runs(api, workflow_file: str) -> list[dict]:
    statuses = "".join(f"&status={status}" for status in UNFINISHED_RUN_STATES)
    runs = verdicts.bounded(
        api.get_json(f"/actions/runs?workflow_id={workflow_file}{statuses}&page=1&limit={verdicts.API_LIMIT}"),
        "workflow_runs",
    )
    return [
        run for run in runs
        if (
            run.get("path") == f"{workflow_file}@{MAIN_REF}"
            or (run.get("workflow_id") == workflow_file and run.get("prettyref") == "main")
        )
        and verdicts.positive_id(run) is not None
    ]


def job_state(jobs: list[dict], name: str, run_id: int) -> str | None:
    """The job's state, or None when the run has no such job (an older workflow)."""
    if not any(job.get("name") == name for job in jobs):
        return None
    return verdicts.state_of(verdicts.named_job(jobs, name, run_id))


def ahead_reason(workflow: str, run: dict, jobs: list[dict], own_run_id: int) -> str | None:
    """Why the run is ahead of this one, or None when it is not."""
    run_id = run["id"]
    found = job_state(jobs, FIND_JOB, run_id)
    if found in (None, "not-started", "running"):
        if run_id < own_run_id:
            return f"{workflow} run {run_id} started first and is still looking for a release"
        return None
    if found != "success":
        return None
    selection = job_state(jobs, SELECTION_JOBS[workflow], run_id)
    if selection in ("not-started", "running", "success"):
        return f"{workflow} run {run_id} is delivering a release"
    return None


def decide(api, workflow: str, own_run_id: int) -> str | None:
    """The first run ahead of this one, as a reason, or None when it is this run's turn."""
    workflow_file = f"{workflow}.yaml"
    for run in sorted(unfinished_main_runs(api, workflow_file), key=lambda record: record["id"]):
        if run["id"] == own_run_id:
            continue
        reason = ahead_reason(workflow, run, verdicts.jobs_of(api, run["id"]), own_run_id)
        if reason:
            return reason
    return None


def scheduled_turn(api, workflow: str, own_run_id: int, log: Callable[[str], None] = print) -> str:
    """GO when nothing is ahead; SKIP when a run is ahead or the runs are unreadable."""
    try:
        reason = decide(api, workflow, own_run_id)
    except Unproven as exc:
        log(f"::warning::the other {workflow} runs are unreadable ({exc}); this scheduled run delivers "
            f"nothing, and the next one looks again")
        return SKIP
    if reason:
        log(f"{reason}; this scheduled run delivers nothing, and the next one looks again")
        return SKIP
    log(f"no other {workflow} run is looking or delivering; this run looks for a release")
    return GO


def dispatched_turn(
    api,
    workflow: str,
    own_run_id: int,
    *,
    poll_seconds: float = POLL_SECONDS,
    wait_seconds: float = WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> str:
    """Wait until no run is ahead (GO); raise Failed past the bound or when unreadable."""
    deadline = clock() + wait_seconds
    unreadable = 0
    last_reason = None
    while True:
        try:
            reason = decide(api, workflow, own_run_id)
            unreadable = 0
        except Unproven as exc:
            unreadable += 1
            if unreadable >= UNREADABLE_LIMIT:
                raise Failed(f"the other {workflow} runs are unreadable ({exc}) after {unreadable} tries; "
                             f"dispatch this release again") from exc
            reason = f"the other {workflow} runs are unreadable ({exc}); trying again"
        if reason is None:
            log(f"no other {workflow} run is looking or delivering; this dispatch delivers now")
            return GO
        if clock() >= deadline:
            raise Failed(f"still waiting after {int(wait_seconds)} s ({reason}); dispatch this release "
                         f"again when that run ends")
        if reason != last_reason:
            log(f"{reason}; this dispatch waits its turn")
            last_reason = reason
        sleep(poll_seconds)


def say(line: str) -> None:
    # Each decision reaches the job log as it is made, not at exit.
    print(line, flush=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in SELECTION_JOBS:
        print("usage: release-turn.py deploy-prod|cli-release", file=sys.stderr)
        return 2
    workflow = argv[1]
    # Reading the other runs needs only the job token, never OIDC request credentials.
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        os.environ.pop(name, None)
    environ = dict(os.environ)
    event = environ.get("GITHUB_EVENT_NAME", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    if event not in ("schedule", "workflow_dispatch"):
        print(f"::error::release turn: unsupported event '{event}'")
        return 1
    try:
        if not run_id.isdigit() or int(run_id) <= 0:
            raise Unproven("invalid-run-id")
        api = verdicts.ForgejoAPI.from_environ(environ)
    except Unproven as exc:
        if event == "workflow_dispatch":
            print(f"::error::release turn: cannot read the other {workflow} runs ({exc})")
            return 1
        print(f"::warning::the other {workflow} runs are unreadable ({exc}); this scheduled run delivers nothing")
        turn = SKIP
    else:
        if event == "schedule":
            turn = scheduled_turn(api, workflow, int(run_id), log=say)
        else:
            try:
                turn = dispatched_turn(api, workflow, int(run_id), log=say)
            except Failed as exc:
                print(f"::error::release turn: {exc}")
                return 1
    output = environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"turn={turn}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
