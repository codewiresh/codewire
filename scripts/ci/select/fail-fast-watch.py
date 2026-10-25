#!/usr/bin/env python3
"""A pull request's CI run stops at its first failed job (infra#1632).

Main CI runs every selected job to the end. A pull request's run is only a
merge gate, so once one job has failed, the rest of it only holds runners.
This watcher, a job of the same run that nothing needs, polls the run's jobs
and cancels the run once any other job has ended in failure.

The failed job stays visibly "failure" with its full log (#3126, #3119 A17):
Forgejo's run cancel stops only jobs that have not finished, and the watcher
cancels only after the failure is recorded, never from inside a failing job.
Required verification then ends cancelled, which is not success, so the pull
request stays blocked.

Only the latest attempt of each job counts, so a rerun of a failed job is
never cancelled for its earlier attempt. The watcher never fails its run:
anything unreadable is retried, and it gives up quietly at its deadline.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Callable

HERE = Path(__file__).resolve().parent
WATCHER_JOB = "Stop at the first failed job"
# Jobs that are not checks: the selection that starts the run and the
# aggregate that reads every result.
NOT_CHECKS = frozenset({"Verification selection", "Required verification", WATCHER_JOB})
POLL_SECONDS = 20
# The watcher runs on a light runner, whose runner stops any task after 25
# minutes (infra#1632: run 21980's rerun timed out while every check still
# queued, and the killed watcher showed as a failed check). It therefore ends
# quietly before that bound; a run still going then continues unwatched.
LIGHT_TASK_LIMIT_MINUTES = 25
DEADLINE_SECONDS = 22 * 60
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")


def load_verdicts() -> ModuleType:
    path = HERE.parent / "plan" / "main-ci-verdict.py"
    spec = importlib.util.spec_from_file_location("codewire_ci_fail_fast_verdict", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load_verdicts()


def latest_attempts(jobs: list[dict]) -> dict[str, dict]:
    """Each job name's latest attempt."""
    latest: dict[str, dict] = {}
    for job in jobs:
        name = job.get("name")
        if not isinstance(name, str) or name in NOT_CHECKS:
            continue
        try:
            attempt = verdicts.job_attempt(job)
        except verdicts.Unproven:
            attempt = 1
        if name not in latest or attempt >= latest[name][0]:
            latest[name] = (attempt, job)
    return {name: job for name, (_, job) in latest.items()}


def watch(
    api,
    run_id: int,
    *,
    poll_seconds: float = POLL_SECONDS,
    deadline_seconds: float = DEADLINE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> str:
    """Poll until a check fails (cancel the run), all finish, or the deadline."""
    deadline = clock() + deadline_seconds
    while True:
        try:
            checks = latest_attempts(verdicts.jobs_of(api, run_id))
            states = {name: verdicts.state_of(job) for name, job in checks.items()}
        except verdicts.Unproven as exc:
            log(f"::warning::cannot read this run's jobs ({exc}); trying again")
            states = None
        if states is not None:
            failed = sorted(name for name, state in states.items() if state == "failure")
            if failed:
                # Said before the cancel, which also stops this job.
                log(f"stopping this pull request's run at its first failure: {', '.join(failed)} "
                    f"failed; the jobs still running are cancelled, and the failed job keeps its "
                    f"result and log")
                status = api.post(f"/actions/runs/{run_id}/cancel")
                if status in (200, 202, 204):
                    return "cancelled"
                log(f"::warning::Forgejo refused to cancel run {run_id} (HTTP {status}); the run continues")
                return "refused"
            if states and all(state in ("success", "skipped", "cancelled") for state in states.values()):
                log("every check finished without a failure; nothing to stop")
                return "finished"
        if clock() >= deadline:
            log("the watcher's deadline passed; the run continues unwatched")
            return "deadline"
        sleep(poll_seconds)


def say(line: str) -> None:
    print(line, flush=True)


def main() -> int:
    environ = dict(os.environ)
    if environ.get("GITHUB_EVENT_NAME") != "pull_request":
        print("only a pull request's run stops at its first failure; main runs every job")
        return 0
    run_id = environ.get("GITHUB_RUN_ID", "")
    if not POSITIVE_RE.fullmatch(run_id):
        print("::warning::the run ID is invalid; not watching")
        return 0
    try:
        api = verdicts.ForgejoAPI.from_environ(environ)
    except verdicts.Unproven as exc:
        print(f"::warning::the Forgejo API is unusable ({exc}); not watching")
        return 0
    watch(api, int(run_id), log=say)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
