#!/usr/bin/env python3
"""A CI run stops at its first failed job (infra#1632; owner, 2026-10-25).

Owner, 2026-10-25: "Again, if any of these things fail, then we just stop
everything." A pull request's and a main push's run both stop, in two ways.

- In a pull request run nothing new starts after a failure: each costly job
  (the build, the test jobs, the Kind jobs) begins with `--at-start`, which
  reads the run's jobs once and ends the job there, naming the check that
  failed, when one already has. No job waits for this. Until 2026-11-16 a
  watcher job did it by cancelling the run, and on 2026-11-15 those watchers
  held 6,450 slot-minutes of the light runner, a third of its task time, to
  save about 110 job-minutes: every minute saved was work that had not
  started, a build already running was never stopped by the cancel, and a
  watcher that died turned one green run red (infra#1534, codewire#3013).
  Work already running when a check fails runs to its end.
- A main push run is watched by this script as a job of the run that nothing
  needs: it polls the run's jobs and acts on the first failure. It first gives
  a test job that failed on its first attempt one
  immediate rerun, in the same run (a flake must not cost main a whole cycle;
  runs 21922 and 22110). Policy, a job's second failure and any other job
  cancel the run. Rerunning restarts Required verification and Dev delivery
  after the job, so the tip still reaches Dev when the rerun passes.

The failed job stays visibly "failure" with its full log (#3126): Forgejo's
run cancel stops only jobs that have not finished, and the watcher cancels
only after the failure is recorded, never from inside a failing job. Required
verification then ends cancelled, which is not success, so nothing merges and
Dev delivers nothing.

Before a rerun the watcher keeps the first attempt's evidence: once a job is
rerun, Forgejo serves only its newest attempt's log, so a rerun that passes
would hide the flake (main run 23658, 2026-10-26). It prints the failure lines
of the failed attempt's log, with a few lines of context and at most
EVIDENCE_LINES lines, in a group named after the job, plus one warning naming
the job and its first failing test. Flakes are fixed at their cause, never
hidden by retries. The fetch is bounded by LOG_FETCH_SECONDS; when it fails the
watcher says so and reruns anyway.

Only the latest attempt of each job counts. The watcher never fails its run:
anything unreadable is retried, and it gives up quietly at its deadline,
asking the next link of its chain to take over (WATCH_LINKS). `--at-start`
never stops a job for anything but a check whose latest attempt has ended in
failure: an unreadable or malformed answer starts the job.
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
# A light runner stops any task after 25 minutes, so one watcher job covers
# only DEADLINE_SECONDS of a run. ci.yaml chains WATCH_LINKS of them, each
# starting when the one before reaches its deadline: 4 x 22 minutes covers
# main runs (verifying p50 65 min on 2026-10-25) and pull request runs; a run
# still going after 88 minutes continues unwatched.
WATCH_LINKS = 4
WATCHER_JOBS = frozenset({WATCHER_JOB, *(f"{WATCHER_JOB} ({link})" for link in range(2, WATCH_LINKS + 1))})
# Jobs that are not checks: the selection that starts the run, the aggregate
# that reads every result, main's Dev delivery trigger and the watchers.
NOT_CHECKS = frozenset({"Verification selection", "Required verification",
                        "Start Dev delivery of the verified commit", *WATCHER_JOBS})
# Test families whose failure on main may be a load flake, so it gets one
# immediate rerun. Policy is deterministic, and its advisory and expiry checks
# stay blocking (#3119): a Policy failure always stops the run.
RETRYABLE_RE = re.compile(
    r"^(Contracts verification|Standard verification|Tooling / delivery contract verification|Compile every Rust target"
    r"|Build test archives|Rust checks"
    r"|Rust / .+|Database verification|Service control-plane verification"
    r"|Service runtime-plane verification)$"
)
POLL_SECONDS = 20
LIGHT_TASK_LIMIT_MINUTES = 25
DEADLINE_SECONDS = 22 * 60
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
# The failed attempt's evidence, printed before its rerun. Only matching lines
# and their context are printed, never the whole log: CI masks registered
# secrets, and this keeps anything else a test printed out of the watcher.
LOG_FETCH_SECONDS = 8
EVIDENCE_LINES = 200
EVIDENCE_LINE_CHARS = 400
CONTEXT_BEFORE = 2
CONTEXT_AFTER = 3
EVIDENCE_RE = re.compile(
    r"::error|FAIL |FAILED|panicked at|Error:|AssertionError|timed out|TIMEOUT|==> first failure:"
)
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# The first failing test: nextest's FAIL line, libtest's "... FAILED" line,
# a panicking test thread, then the script a family runner names on its
# "==> first failure:" line (#4040: script-test families print only that).
FIRST_TEST_RES = (
    re.compile(r"\bFAIL \[\s*[0-9.]+s\]\s+(?:\([^)]*\)\s+)?(\S.*?)\s*$"),
    re.compile(r"\btest (\S+) \.\.\. FAILED\b"),
    re.compile(r"thread '([^']+)' panicked at"),
    re.compile(r"==> first failure: (\S.*?)\s*$"),
)


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


def latest_attempts(jobs: list[dict]) -> dict[str, tuple[int, dict]]:
    """Each check's latest attempt, as (attempt, job)."""
    latest: dict[str, tuple[int, dict]] = {}
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
    return latest


def failure_evidence(log_text: str) -> tuple[list[str], str | None]:
    """The log's failure lines with context, at most EVIDENCE_LINES, and the
    first failing test, if the log names one."""
    lines = [ANSI_RE.sub("", line) for line in log_text.splitlines()]
    hits = [index for index, line in enumerate(lines) if EVIDENCE_RE.search(line)]
    first_test = None
    for pattern in FIRST_TEST_RES:
        for index in hits:
            match = pattern.search(lines[index])
            if match:
                first_test = match.group(1)[:EVIDENCE_LINE_CHARS]
                break
        if first_test:
            break
    keep: list[int] = []
    for index in hits:
        start = max(index - CONTEXT_BEFORE, keep[-1] + 1 if keep else 0)
        keep.extend(range(start, min(index + CONTEXT_AFTER + 1, len(lines))))
    summary: list[str] = []
    previous = None
    for index in keep:
        if previous is not None and index != previous + 1:
            summary.append("| --")
        # A leading "| " keeps a quoted line from acting as a workflow command.
        summary.append("| " + lines[index][:EVIDENCE_LINE_CHARS])
        previous = index
    if len(summary) > EVIDENCE_LINES:
        omitted = len(summary) - (EVIDENCE_LINES - 1)
        summary = summary[:EVIDENCE_LINES - 1] + [f"| ... {omitted} more lines not shown"]
    return summary, first_test


def keep_evidence(api, name: str, job_id: int, log: Callable[[str], None]) -> None:
    """Print the failed attempt's evidence before its rerun replaces its log.

    Never raises: a failed fetch is reported and the rerun goes ahead."""
    try:
        text = api.get_text(f"/actions/jobs/{job_id}/logs", max_seconds=LOG_FETCH_SECONDS)
    except Exception as exc:  # noqa: BLE001 - evidence must never block the rerun
        reason = exc.args[0] if isinstance(exc, verdicts.Unproven) and exc.args else type(exc).__name__
        log(f"::warning::{name} failed its first attempt; its log could not be fetched ({reason}), "
            f"so its evidence is lost; rerunning anyway")
        return
    summary, first_test = failure_evidence(text)
    log(f"::group::{name}: first attempt's failure lines")
    for line in summary or ["| (no failure lines matched in the log)"]:
        log(line)
    log("::endgroup::")
    test = f"first failing test: {first_test}" if first_test else "no failing test named in its log"
    log(f"::warning::{name} failed its first attempt and is rerun once as a possible flake; {test}; "
        f"its failure lines are in this watcher's log. Fix a flake at its cause.")


def watch(
    api,
    run_id: int,
    *,
    main: bool = False,
    poll_seconds: float = POLL_SECONDS,
    deadline_seconds: float = DEADLINE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> str:
    """Poll until the run is stopped, every check finishes, or the deadline."""
    deadline = clock() + deadline_seconds
    # Reruns this watcher asked for; until Forgejo shows the new attempt, the
    # old failed attempt is neither rerun again nor a reason to stop.
    requested: set[str] = set()
    while True:
        try:
            checks = latest_attempts(verdicts.jobs_of(api, run_id))
            states = {name: (attempt, job, verdicts.state_of(job)) for name, (attempt, job) in checks.items()}
        except verdicts.Unproven as exc:
            log(f"::warning::cannot read this run's jobs ({exc}); trying again")
            states = None
        if states is not None:
            failed = sorted(name for name, (_, _, state) in states.items() if state == "failure")
            retry = [name for name in failed
                     if main and RETRYABLE_RE.fullmatch(name) and states[name][0] == 1]
            stop = [name for name in failed if name not in retry]
            retry = [name for name in retry if name not in requested]
            if stop:
                # Said before the cancel, which also stops this job.
                kind = "pull request" if not main else "main"
                log(f"stopping this {kind} run at its first failure: {', '.join(stop)} failed; the jobs "
                    f"still running are cancelled, and the failed job keeps its result and log")
                status = api.post(f"/actions/runs/{run_id}/cancel")
                if status in (200, 202, 204):
                    return "cancelled"
                log(f"::warning::Forgejo refused to cancel run {run_id} (HTTP {status}); the run continues")
                return "refused"
            for name in retry:
                requested.add(name)
                keep_evidence(api, name, states[name][1]['id'], log)
                log(f"rerunning {name} once at once, as a possible flake; a second failure stops the run")
                status = api.post(f"/actions/jobs/{states[name][1]['id']}/rerun")
                if status not in (200, 201, 202, 204):
                    log(f"::warning::Forgejo refused to rerun {name} (HTTP {status}); stopping the run")
                    if api.post(f"/actions/runs/{run_id}/cancel") in (200, 202, 204):
                        return "cancelled"
                    return "refused"
            if not failed and states and all(state in ("success", "skipped", "cancelled")
                                             for _, _, state in states.values()):
                log("every check finished without a failure; nothing to stop")
                return "finished"
        if clock() >= deadline:
            log("this watcher's deadline passed; the next link of the chain takes over")
            return "deadline"
        sleep(poll_seconds)


def failed_first(checks: dict[str, tuple[int, dict]]) -> list[str]:
    """The checks whose latest attempt ended in failure, the earliest first.

    Jobs this script stopped at their start are failures too, so the order
    matters: the first to end is the cause. A job without a readable end time
    sorts after those with one, by name."""
    failed = [(str(job.get("completed_at") or job.get("stopped_at") or "~"), name)
              for name, (_, job) in checks.items() if ended_in_failure(job)]
    return [name for _, name in sorted(failed)]


def ended_in_failure(job: dict) -> bool:
    """Whether Forgejo says, in so many words, that this job failed.

    Stricter than verdicts.state_of, which reads a completed job with a
    conclusion it does not know as a failure: right for a verdict, which must
    not pass what it cannot read, and wrong here, where the doubt must start
    the job."""
    status, conclusion = job.get("status"), job.get("conclusion")
    return status == "failure" or (status == "completed" and conclusion == "failure")


def at_start(api, run_id: int, log: Callable[[str], None] = print) -> str:
    """"stop" when a check of this run has already failed, otherwise "go".

    Asked once by a costly job before it does anything. It can only stop a
    job, never cancel a run, and anything unreadable is "go": a job that
    should have been stopped costs minutes, a job stopped wrongly would turn a
    green run red."""
    try:
        failed = failed_first(latest_attempts(verdicts.jobs_of(api, run_id)))
    except Exception as exc:  # noqa: BLE001 - whatever goes wrong here, the job starts
        log(f"::warning::cannot read this run's jobs ({type(exc).__name__}: {exc}); starting this job anyway")
        return "go"
    if not failed:
        log("no check of this run has failed; starting")
        return "go"
    also = f"; also failed by now: {', '.join(failed[1:])}" if failed[1:] else ""
    log(f"::error::not started: {failed[0]} failed first in this run{also}. Nothing new starts after a "
        f"failure (infra#1632), so this job did not run; fix {failed[0]}")
    return "stop"


def say(line: str) -> None:
    print(line, flush=True)


def handover(result: str, environ: dict[str, str]) -> None:
    """Tell ci.yaml whether the next watcher link should start."""
    output = environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"continue={'true' if result == 'deadline' else 'false'}\n")


def main_at_start(environ: dict[str, str]) -> int:
    """`--at-start`: exit 1 to end a pull request's job before it starts."""
    if environ.get("GITHUB_EVENT_NAME") != "pull_request":
        print("only a pull request's jobs ask at their start; starting")
        return 0
    run_id = environ.get("GITHUB_RUN_ID", "")
    if not POSITIVE_RE.fullmatch(run_id):
        print("::warning::the run ID is invalid; starting this job anyway")
        return 0
    try:
        api = verdicts.ForgejoAPI.from_environ(environ)
        return 1 if at_start(api, int(run_id), log=say) == "stop" else 0
    except Exception as exc:  # noqa: BLE001 - only a failed check may stop a job (codewire#5024 review)
        print(f"::warning::asking at the start failed ({type(exc).__name__}: {exc}); starting this job anyway")
        return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    environ = dict(os.environ)
    if argv == ["--at-start"]:
        return main_at_start(environ)
    if argv:
        print("usage: fail-fast-watch.py [--at-start]", file=sys.stderr)
        return 2
    event, ref = environ.get("GITHUB_EVENT_NAME"), environ.get("GITHUB_REF")
    on_main = event == "push" and ref == "refs/heads/main"
    if event != "pull_request" and not on_main:
        print("only pull request and main push runs are watched")
        handover("finished", environ)
        return 0
    run_id = environ.get("GITHUB_RUN_ID", "")
    if not POSITIVE_RE.fullmatch(run_id):
        print("::warning::the run ID is invalid; not watching")
        handover("finished", environ)
        return 0
    try:
        api = verdicts.ForgejoAPI.from_environ(environ)
    except verdicts.Unproven as exc:
        print(f"::warning::the Forgejo API is unusable ({exc}); not watching")
        handover("finished", environ)
        return 0
    handover(watch(api, int(run_id), main=on_main, log=say), environ)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
