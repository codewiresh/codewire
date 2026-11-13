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

The light runner this job runs on cancels any job after 25 minutes, sooner
than one delivery takes (#4476: Deploy Dev 46838 was cancelled waiting behind
46824). So a run still waiting after WAIT_SECONDS defers: it builds nothing
and ends with turn=deferred, and the delivery in flight hands the turn on when
it ends. Its last job runs this with --hand-on: it finds the newest Deploy Dev
run after its own that selected a delivery and, when that run deferred or its
turn job was cancelled or failed, reruns that run's turn job, which takes its
turn as above. Older deferred runs stay replaced by the newest. The handover
reruns a job with the job token only, as main CI's Dev delivery job does; a
handover that cannot start fails with a "missed trigger" line.

A newer commit's run is one with a higher run ID: on main every later push
gets a higher one, and a rerun keeps its run's ID. Ancestry cannot decide it,
because this job's checkout holds only its own commit, not a newer one (the
first version did, and so never saw itself replaced). A run of the workflow
from before this job counts as in flight while its builds or publish job has
not ended.

This job may delay a delivery but never prevents one: anything unreadable for
UNREADABLE_LIMIT polls in a row lets this run build, with a warning. It writes
turn=go, turn=replaced or turn=deferred to GITHUB_OUTPUT.
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
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW = "deploy-dev.yaml"
MAIN_REF = "refs/heads/main"
SELECTION_JOB = "Deploy selection"
TURN_JOB = "Dev delivery turn"
DEFERRED_JOB = "Deferred to the delivery in flight"
BUILD_JOBS = ("Build and push the service runtime images", "Build and push the daemon runtime image")
PUBLISH_JOB = "Publish the exact runtime image set"
UNFINISHED_RUN_STATES = ("waiting", "blocked", "running", "unknown")
POLL_SECONDS = 30
# Inside the light runner's 25-minute job cap (#4476); past it the run defers.
WAIT_SECONDS = 20 * 60
# How long the handover waits for the newest run's turn to settle.
HAND_ON_SECONDS = 10 * 60
UNREADABLE_LIMIT = 5

GO = "go"
WAIT = "wait"
REPLACED = "replaced"
DEFERRED = "deferred"


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


def decide(api, head: str, own_run_id: int) -> tuple[str, str]:
    """GO, WAIT or REPLACED for this run, with the reason."""
    waiting_for = None
    for run in sorted(unfinished_main_runs(api), key=lambda record: record["id"], reverse=True):
        run_id = run["id"]
        commit = run.get("head_sha") or run.get("commit_sha")
        if run_id == own_run_id or commit == head:
            continue
        jobs = verdicts.jobs_of(api, run_id)
        if run_id > own_run_id:
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
    head: str,
    own_run_id: int,
    *,
    poll_seconds: float = POLL_SECONDS,
    wait_seconds: float = WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> str:
    """Poll until this run may build (GO), a newer delivery replaces it (REPLACED), or it defers."""
    deadline = clock() + wait_seconds
    unreadable = 0
    last_reason = None
    while True:
        try:
            verdict, reason = decide(api, head, own_run_id)
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
            log(f"Dev delivery turn for {head}: still waiting after {int(wait_seconds)} s ({reason}); "
                f"it defers, and that delivery hands the turn on when it ends")
            return DEFERRED
        if reason != last_reason:
            log(f"Dev delivery turn for {head}: {reason}; waiting")
            last_reason = reason
        sleep(poll_seconds)


def later_main_runs(api, own_run_id: int) -> list[dict]:
    """Deploy Dev's push runs on main after this one, finished or not.

    Unfiltered, the list is every Deploy Dev run there ever was, so its
    total_count exceeds the page and verdicts.bounded() refuses it as
    malformed (Deploy Dev 47202's handover, #4502). Forgejo lists runs newest
    first, so the first page holds every run after this one unless more than
    a page came after it, which is ambiguous and refused.
    """
    document = api.get_json(f"/actions/runs?workflow_id={WORKFLOW}&page=1&limit={verdicts.API_LIMIT}")
    runs = document.get("workflow_runs") if isinstance(document, dict) else None
    total = document.get("total_count") if isinstance(document, dict) else None
    if (not isinstance(runs, list) or not isinstance(total, int) or isinstance(total, bool)
            or len(runs) > verdicts.API_LIMIT or total < len(runs)):
        raise Unproven("forgejo-api-malformed")
    ids = [run_id for run in runs if isinstance(run, dict) and (run_id := verdicts.positive_id(run))]
    if total > len(runs) and ids and min(ids) > own_run_id:
        raise Unproven("forgejo-api-ambiguous")
    return [
        run for run in runs
        if isinstance(run, dict) and (verdicts.positive_id(run) or 0) > own_run_id
        and (run.get("trigger_event") or run.get("event")) == "push"
        and (
            run.get("path") == f"{WORKFLOW}@{MAIN_REF}"
            or (run.get("workflow_id") == WORKFLOW and run.get("prettyref") == "main")
        )
    ]


def next_turn(api, own_run_id: int) -> tuple[str, dict | None, str]:
    """What the newest later run that selected a delivery needs: "rerun" its turn job, "settle" or "none"."""
    for run in sorted(later_main_runs(api, own_run_id), key=lambda record: record["id"], reverse=True):
        run_id = run["id"]
        jobs = verdicts.jobs_of(api, run_id)
        selection = job_state(jobs, SELECTION_JOB, run_id)
        turn = job_state(jobs, TURN_JOB, run_id)
        if selection in ("not-started", "running"):
            return "none", None, f"Deploy Dev run {run_id} is still selecting; it takes its own turn"
        if selection != "success" or turn is None or turn == "skipped":
            # Selected nothing (a documentation-only push), or failed before its turn.
            continue
        if turn == "not-started":
            return "none", None, f"Deploy Dev run {run_id} has yet to take its turn; it takes it itself"
        if turn == "running":
            # It may be deferring on a decision made while this run was in flight.
            return "settle", None, f"Deploy Dev run {run_id} is at its turn"
        if turn in ("cancelled", "failure"):
            return "rerun", verdicts.named_job(jobs, TURN_JOB, run_id), (
                f"Deploy Dev run {run_id}'s turn job ended {turn}")
        deferred = job_state(jobs, DEFERRED_JOB, run_id)
        if deferred in ("not-started", "running"):
            return "settle", None, f"Deploy Dev run {run_id} is deferring"
        if deferred == "success":
            return "rerun", verdicts.named_job(jobs, TURN_JOB, run_id), f"Deploy Dev run {run_id} deferred"
        return "none", None, f"Deploy Dev run {run_id} took its turn"
    return "none", None, "no later delivery is waiting"


def hand_on(
    api,
    own_run_id: int,
    *,
    poll_seconds: float = POLL_SECONDS,
    wait_seconds: float = HAND_ON_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> int:
    """Hand the turn to the newest waiting delivery; 0 when done or none is owed, 1 on a missed trigger."""
    deadline = clock() + wait_seconds
    while True:
        try:
            action, job, reason = next_turn(api, own_run_id)
        except Unproven as exc:
            action, job, reason = "settle", None, f"the later Dev deliveries are unreadable ({exc})"
        if action == "none":
            log(f"Dev delivery handover from run {own_run_id}: {reason}; nothing to hand on")
            return 0
        if action == "rerun":
            status = api.post(f"/actions/jobs/{job['id']}/rerun")
            if status in (200, 201, 204):
                log(f"Dev delivery handover from run {own_run_id}: {reason}; reran its turn job {job['id']}")
                return 0
            if status != 400:
                log(f"::error::missed trigger: {reason}, and Forgejo refused to rerun its turn job "
                    f"{job['id']} (HTTP {status}); rerun that job by hand")
                return 1
            # 400: the job started again between the read and the rerun; look again.
            reason = f"turn job {job['id']} started again"
        if clock() >= deadline:
            log(f"::error::missed trigger: after {int(wait_seconds)} s, {reason}; the waiting delivery may "
                f"not have its turn. Rerun the newest deferred run's \"{TURN_JOB}\" job by hand")
            return 1
        sleep(poll_seconds)


def say(line: str) -> None:
    # Each decision reaches the job log as it is made, not at exit.
    print(line, flush=True)


def main(argv: list[str] | None = None) -> int:
    # Reading the other runs needs only the job token, never OIDC request credentials.
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        os.environ.pop(name, None)
    environ = dict(os.environ)
    head = environ.get("GITHUB_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--hand-on"]:
        if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != MAIN_REF:
            print("only a push to main hands a Dev delivery turn on")
            return 0
        if not run_id.isdigit():
            print("::error::missed trigger: the workflow run is invalid; nothing was handed on")
            return 1
        return hand_on(verdicts.ForgejoAPI.from_environ(environ), int(run_id), log=say)
    if argv:
        raise SystemExit("usage: wait-for-dev-delivery-turn.py [--hand-on]")
    turn = GO
    if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != MAIN_REF:
        print("only a push to main takes a Dev delivery turn; building now")
    elif not HEX40_RE.fullmatch(head) or not run_id.isdigit():
        print("::warning::the workflow commit or run is invalid; building now")
    else:
        try:
            api = verdicts.ForgejoAPI.from_environ(environ)
            turn = wait_for_turn(api, head, int(run_id), log=say)
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
