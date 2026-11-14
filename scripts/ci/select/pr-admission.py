#!/usr/bin/env python3
"""At most ADMITTED_LIMIT pull request CI runs at once, oldest first (infra#2471).

The owner, 2026-11-13: "We'd like less faster runs is better than a bunch of
slow runs." Two build runners finish about 17 pull request builds an hour; at
a peak 28 runs were in flight at once, every job of every run waited, and the
metal hosts' drives saturated. A run now waits before its first real job
until fewer than ADMITTED_LIMIT pull request runs are admitted, and runs are
admitted in the order they started, across every pull request.

ci.yaml's first job, "PR admission", runs this; Verification selection needs
it and every other job needs selection, so a waiting run holds no build or
test slot. It runs on the untrusted light runner, whose 240-minute job cap is
the gate's (infra#2471); a waiting gate is one idle poll. A newer push to the
same pull request still cancels the run, gate and all.

A run is admitted when its "PR admission" job succeeded and the run has not
ended; a run from before the gate counts as admitted while it runs, and so
does a run whose jobs cannot be read, so one odd run never opens the gate for
every other. A run whose gate has not ended is waiting. A blocked run, one
awaiting approval, holds no slot until it is approved. This run is admitted
when the admitted runs and the waiting runs that started before it are fewer
than ADMITTED_LIMIT.

The gate may delay a run but never stops one, and never fails its job:
- a push, a schedule or a dispatch is admitted at once, as is a closed pull
  request;
- when WAITING_LIMIT gates or more would be waiting with this one, it is
  admitted with an overflow warning, so waiting gates never fill the light
  runner and starve the admitted runs' own light jobs. Overflow admissions a
  day are the signal to watch;
- the run list unreadable for UNREADABLE_LIMIT polls in a row, or a wait past
  WAIT_SECONDS, admits it with a warning. The deadline is checked before every
  request, each at most 30 s, so a slow Forgejo never runs the gate past its
  job's 235 minutes.
It writes admission=admitted, overflow, unreadable, deadline or not-a-pull-request
to GITHUB_OUTPUT.
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
WORKFLOW = "ci.yaml"
GATE_JOB = "PR admission"
# Not "blocked": a run awaiting approval holds no slot until it is approved.
UNFINISHED_RUN_STATES = ("waiting", "running", "unknown")
ADMITTED_LIMIT = 6
# Waiting gates hold light runner slots. The light runner takes 24 jobs
# (owner, 2026-11-14: faster jobs, not more of them; infra#2471), so at most 6
# wait and at least 18 slots stay for every repository's real light jobs.
WAITING_LIMIT = 6
POLL_SECONDS = 45
# Inside the gate job's 235 minutes and the light runner's 240-minute cap.
WAIT_SECONDS = 230 * 60
UNREADABLE_LIMIT = 5

ADMITTED = "admitted"
WAIT = "wait"
OVERFLOW = "overflow"
UNREADABLE = "unreadable"
DEADLINE = "deadline"
NOT_A_PULL_REQUEST = "not-a-pull-request"


def load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load("codewire_ci_pr_admission_verdict", HERE.parent / "plan" / "main-ci-verdict.py")
Unproven = verdicts.Unproven


class DeadlineReached(Exception):
    """The wait's deadline passed in the middle of a poll."""


def unfinished_pull_request_runs(api) -> list[dict]:
    """ci.yaml's pull request runs that have not ended; one page, as the filter keeps it short."""
    statuses = "".join(f"&status={status}" for status in UNFINISHED_RUN_STATES)
    runs = verdicts.bounded(
        api.get_json(f"/actions/runs?workflow_id={WORKFLOW}{statuses}&page=1&limit={verdicts.API_LIMIT}"),
        "workflow_runs",
    )
    return [
        run for run in runs
        if str(run.get("trigger_event") or run.get("event") or "").startswith("pull_request")
        and run.get("status") != "blocked"
        and verdicts.positive_id(run) is not None
    ]


def gate_state(jobs: list[dict], run_id: int) -> str | None:
    """The run's gate job state, or None for a run from before the gate."""
    if not any(job.get("name") == GATE_JOB for job in jobs):
        return None
    return verdicts.state_of(verdicts.named_job(jobs, GATE_JOB, run_id))


def decide(api, own_run_id: int, *, limit: int = ADMITTED_LIMIT,
           waiting_limit: int = WAITING_LIMIT, deadline: float | None = None,
           clock: Callable[[], float] = time.monotonic) -> tuple[str, str]:
    """ADMITTED, OVERFLOW or WAIT for this run, with the reason.

    Only the run list itself unreadable raises Unproven; past the deadline,
    before any request, it raises DeadlineReached."""
    def in_time() -> None:
        if deadline is not None and clock() >= deadline:
            raise DeadlineReached
    in_time()
    admitted = waiting_ahead = unreadable = 0
    for run in unfinished_pull_request_runs(api):
        run_id = run["id"]
        if run_id == own_run_id:
            continue
        in_time()
        try:
            gate = gate_state(verdicts.jobs_of(api, run_id), run_id)
        except Unproven:
            # Two gates, a run deleted mid-poll, too many jobs: it holds a slot.
            unreadable += 1
            gate = None
        if gate is None or gate == "success":
            admitted += 1
        elif gate in ("not-started", "running") and run_id < own_run_id:
            waiting_ahead += 1
    ahead = admitted + waiting_ahead
    if unreadable:
        admitted_text = f"{admitted} pull request runs admitted ({unreadable} unreadable, counted as admitted)"
    else:
        admitted_text = f"{admitted} pull request runs admitted"
    if ahead < limit:
        return ADMITTED, f"{admitted_text} and {waiting_ahead} waiting ahead, under {limit}"
    if waiting_ahead >= waiting_limit:
        return OVERFLOW, (f"{waiting_ahead} gates already wait ahead of this one, the most the light runner "
                          f"holds beside the admitted runs' own jobs")
    return WAIT, f"{admitted_text} and {waiting_ahead} waiting ahead; {limit} at once"


def wait_for_admission(
    api,
    own_run_id: int,
    *,
    poll_seconds: float = POLL_SECONDS,
    wait_seconds: float = WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> str:
    """Poll until this run is admitted; every way out admits it."""
    deadline = clock() + wait_seconds
    unreadable = 0
    last_reason = None
    while True:
        try:
            verdict, reason = decide(api, own_run_id, deadline=deadline, clock=clock)
            unreadable = 0
        except DeadlineReached:
            verdict, reason = WAIT, "the deadline passed during a poll"
        except Unproven as exc:
            unreadable += 1
            if unreadable >= UNREADABLE_LIMIT:
                log(f"::warning::PR admission: cannot read the other pull request runs ({exc}) after "
                    f"{unreadable} tries; this run starts now")
                return UNREADABLE
            verdict, reason = WAIT, f"the other pull request runs are unreadable ({exc}); trying again"
        if verdict == ADMITTED:
            log(f"PR admission: {reason}; this run starts now")
            return ADMITTED
        if verdict == OVERFLOW:
            log(f"::warning::PR admission overflow: {reason}; this run starts now, over the limit")
            return OVERFLOW
        if clock() >= deadline:
            log(f"::warning::PR admission: still waiting after {int(wait_seconds)} s ({reason}); "
                f"this run starts now")
            return DEADLINE
        if reason != last_reason:
            log(f"PR admission: {reason}; waiting")
            last_reason = reason
        sleep(max(0.0, min(poll_seconds, deadline - clock())))


def say(line: str) -> None:
    # Each decision reaches the job log as it is made, not at exit.
    print(line, flush=True)


def main() -> int:
    # Reading the other runs needs only the job token, never OIDC request credentials.
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        os.environ.pop(name, None)
    environ = dict(os.environ)
    run_id = environ.get("GITHUB_RUN_ID", "")
    if not environ.get("GITHUB_EVENT_NAME", "").startswith("pull_request") or environ.get("PR_ACTION") == "closed":
        print("PR admission: not an open pull request's run; it starts now")
        admission = NOT_A_PULL_REQUEST
    elif not run_id.isdigit():
        print("::warning::PR admission: the run is invalid; it starts now")
        admission = UNREADABLE
    else:
        try:
            admission = wait_for_admission(verdicts.ForgejoAPI.from_environ(environ), int(run_id), log=say)
        except Exception as exc:  # noqa: BLE001 - the gate may delay a run, never stop it
            print(f"::warning::PR admission stopped ({exc}); this run starts now")
            admission = UNREADABLE
    output = environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"admission={admission}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
