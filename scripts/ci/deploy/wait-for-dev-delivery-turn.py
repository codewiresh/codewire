#!/usr/bin/env python3
"""One Dev delivery at a time; the newest waits; none is ever cancelled.

The owner's rule (2026-11-10, #4071, recorded on #3013): "the Dev delivery in
flight always finishes and publishes. At most one delivery waits behind it,
always the newest; newer commits replace the waiting one, and the ones in
between are skipped. When the in-flight delivery finishes, the waiting one
starts." It replaces cancelling older deliveries (2026-10-21 and 2026-10-24),
which starved Dev under a steady merge rate: each delivery was cancelled by
the next before it could publish.

Each Deploy Dev push run on main that selected a delivery runs this as its
"Dev delivery turn" job, between selection and the image builds, and polls:

- a newer commit's run has reached its own turn (its turn job is waiting for
  a runner, running, or let it build): this run is replaced. It builds
  nothing and ends; the newer delivery carries its change. A newer run that
  is still selecting, or selected nothing (a documentation-only push), does
  not replace it;
- another run is in flight (it has its turn and its builds or publish job
  has not ended): this run waits;
- otherwise it is this run's turn: it builds and publishes as before, and is
  never stopped. Its publish job still signs only a commit main CI verified
  and only while it moves Dev forward, so a red commit's delivery ends
  without publishing and the next one starts.

A run of the workflow from before this job counts as in flight while its
builds or publish job has not ended.

This job may delay a delivery but never prevents one: anything unreadable for
UNREADABLE_LIMIT polls in a row, or a wait past WAIT_SECONDS, lets this run
build, with a warning. It writes turn=go or turn=replaced to GITHUB_OUTPUT.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Callable

HERE = Path(__file__).resolve().parent
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW = "deploy-dev.yaml"
MAIN_REF = "refs/heads/main"
SELECTION_JOB = "Deploy selection"
TURN_JOB = "Dev delivery turn"
BUILD_JOBS = ("Build and push the service runtime images", "Build and push the daemon runtime image")
PUBLISH_JOB = "Publish the exact runtime image set"
UNFINISHED_RUN_STATES = ("waiting", "blocked", "running", "unknown")
POLL_SECONDS = 30
# Longer than one delivery: the builds' 60 min bound plus publishing.
WAIT_SECONDS = 80 * 60
UNREADABLE_LIMIT = 5

GO = "go"
WAIT = "wait"
REPLACED = "replaced"


def load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load("codewire_ci_dev_delivery_turn_verdict", HERE.parent / "plan" / "main-ci-verdict.py")
Unproven = verdicts.Unproven


def git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repository, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, check=False, timeout=60,
    )


def is_proper_ancestor(repository: Path, older: str, newer: str) -> bool:
    if older == newer:
        return False
    return git(repository, "merge-base", "--is-ancestor", older, newer).returncode == 0


def unfinished_main_runs(api) -> list[dict]:
    statuses = "".join(f"&status={status}" for status in UNFINISHED_RUN_STATES)
    runs = verdicts.bounded(
        api.get_json(f"/actions/runs?workflow_id={WORKFLOW}{statuses}&page=1&limit={verdicts.API_LIMIT}"),
        "workflow_runs",
    )
    return [
        run for run in runs
        if (run.get("trigger_event") or run.get("event")) == "push"
        and (
            run.get("path") == f"{WORKFLOW}@{MAIN_REF}"
            or (run.get("workflow_id") == WORKFLOW and run.get("prettyref") == "main")
        )
        and verdicts.positive_id(run) is not None
        and HEX40_RE.fullmatch(run.get("head_sha") or run.get("commit_sha") or "")
    ]


def job_state(jobs: list[dict], name: str, run_id: int) -> str | None:
    """The job's state, or None when the run has no such job (an older workflow)."""
    if not any(job.get("name") == name for job in jobs):
        return None
    return verdicts.state_of(verdicts.named_job(jobs, name, run_id))


def delivering(jobs: list[dict], run_id: int) -> bool:
    """Whether the run's builds or publish job has not ended yet."""
    return any(job_state(jobs, name, run_id) in ("not-started", "running")
               for name in (*BUILD_JOBS, PUBLISH_JOB))


def claims_turn(jobs: list[dict], run_id: int) -> bool:
    """Whether the run has reached its turn: waiting at it, or let through it and still delivering."""
    turn = job_state(jobs, TURN_JOB, run_id)
    if turn is None:
        # A run from before the turn job: it delivers once selection is done.
        return job_state(jobs, SELECTION_JOB, run_id) == "success" and delivering(jobs, run_id)
    if turn == "running":
        return True
    if turn == "not-started":
        # Waiting for a runner once selection chose a delivery; a selection that
        # chose none skips the turn job instead.
        return job_state(jobs, SELECTION_JOB, run_id) == "success"
    return turn == "success" and delivering(jobs, run_id)


def in_flight(jobs: list[dict], run_id: int) -> bool:
    """Whether the run was let through its turn and its delivery has not ended."""
    turn = job_state(jobs, TURN_JOB, run_id)
    if turn is None:
        return job_state(jobs, SELECTION_JOB, run_id) == "success" and delivering(jobs, run_id)
    return turn == "success" and delivering(jobs, run_id)


def decide(api, repository: Path, head: str, own_run_id: int) -> tuple[str, str]:
    """GO, WAIT or REPLACED for this run, with the reason."""
    waiting_for = None
    for run in sorted(unfinished_main_runs(api), key=lambda record: record["id"], reverse=True):
        run_id = run["id"]
        commit = run.get("head_sha") or run.get("commit_sha")
        if run_id == own_run_id or commit == head:
            continue
        jobs = verdicts.jobs_of(api, run_id)
        if is_proper_ancestor(repository, head, commit):
            if claims_turn(jobs, run_id):
                return REPLACED, f"Deploy Dev run {run_id} for the newer {commit} has reached its turn"
            continue
        if waiting_for is None and in_flight(jobs, run_id):
            waiting_for = f"Deploy Dev run {run_id} for {commit} is in flight"
    if waiting_for:
        return WAIT, waiting_for
    return GO, "no other delivery is in flight"


def wait_for_turn(
    api,
    repository: Path,
    head: str,
    own_run_id: int,
    *,
    poll_seconds: float = POLL_SECONDS,
    wait_seconds: float = WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> str:
    """Poll until this run may build (GO) or a newer delivery replaces it (REPLACED)."""
    deadline = clock() + wait_seconds
    unreadable = 0
    last_reason = None
    while True:
        try:
            verdict, reason = decide(api, repository, head, own_run_id)
            unreadable = 0
        except Unproven as exc:
            unreadable += 1
            if unreadable >= UNREADABLE_LIMIT:
                log(f"::warning::cannot read the other Dev deliveries ({exc}) after {unreadable} tries; "
                    f"{head} builds now")
                return GO
            verdict, reason = WAIT, f"the other Dev deliveries are unreadable ({exc}); trying again"
        if verdict == GO:
            log(f"Dev delivery turn for {head}: {reason}; it builds and publishes now")
            return GO
        if verdict == REPLACED:
            log(f"Dev delivery turn for {head}: {reason}, and that delivery carries {head}'s change; "
                f"this run builds nothing")
            return REPLACED
        if clock() >= deadline:
            log(f"::warning::Dev delivery turn for {head}: still waiting after {int(wait_seconds)} s "
                f"({reason}); it builds now")
            return GO
        if reason != last_reason:
            log(f"Dev delivery turn for {head}: {reason}; waiting")
            last_reason = reason
        sleep(poll_seconds)


def main() -> int:
    # Reading the other runs needs only the job token, never OIDC request credentials.
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        os.environ.pop(name, None)
    environ = dict(os.environ)
    head = environ.get("GITHUB_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    turn = GO
    if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != MAIN_REF:
        print("only a push to main takes a Dev delivery turn; building now")
    elif not HEX40_RE.fullmatch(head) or not run_id.isdigit():
        print("::warning::the workflow commit or run is invalid; building now")
    else:
        try:
            api = verdicts.ForgejoAPI.from_environ(environ)
            turn = wait_for_turn(api, Path.cwd(), head, int(run_id))
        except Exception as exc:  # noqa: BLE001 - the turn may delay a delivery, never prevent it
            print(f"::warning::the Dev delivery turn stopped ({exc}); building now")
            turn = GO
    output = environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"turn={turn}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
