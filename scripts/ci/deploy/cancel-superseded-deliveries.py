#!/usr/bin/env python3
"""Cancel the older Dev deliveries that can never sign (#2892).

A Deploy Dev run signs only after its own commit's main CI verdict. Main CI
runs queue one at a time, and a queued run that starts after main moved on
prints "superseded" and verifies nothing (ci.yaml, "Skip a superseded main
commit"), and no rerun of it can verify anything either, since main never
moves back. So once a newer commit M is on main, an older commit S whose main
CI has not started, or recorded it as superseded, can never be verified. Its
delivery would build a set that never signs. A red or unverified run is
different: rerunning it can still verify S, so its delivery is kept.

Deploy Dev runs no longer cancel each other through a concurrency group, which
cancelled every older delivery on every push and starved Dev under steady
merges. Instead each run's selection job runs this once, as the only decision
point, and cancels an older commit's Deploy Dev push run on main only when:

- S is a proper ancestor of M, so M's delivery carries S's change and Dev
  never moves backwards;
- S's own main CI can no longer verify it: its ci.yaml push run's selection
  has not started, or that selection recorded S as superseded;
- S's run has not started publishing, so no set is left half signed.

A delivery is never cancelled while its commit can still be verified by its
own main CI (codewire-4f, 2026-10-21, on #2892). Every commit main CI verifies
therefore keeps its delivery, Dev advances on every verdict, and since main
CI verifies one commit at a time, at most about two sets build at once: the
verifying commit's and the newest one's. An older run never decides to skip
itself; if it is registered only after this ran, both deliver, in order, as
promote-dev accepts only descendants of Dev's current source.

Cancelling is an optimisation, never a gate: anything unreadable keeps the
older delivery, and once loaded this script always exits 0 so its own run
still delivers; the workflow step also continues on error.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable

HERE = Path(__file__).resolve().parent
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW = "deploy-dev.yaml"
MAIN_REF = "refs/heads/main"
SELECTION_JOB = "Deploy selection"
BUILD_JOBS = ("Build and push the service runtime images", "Build and push the daemon runtime image")
PUBLISH_JOB = "Publish the exact runtime image set"
UNFINISHED_RUN_STATES = ("waiting", "blocked", "running", "unknown")
# Main CI's first job, and the line its "Skip a superseded main commit" step
# prints when main had moved past the commit as the run started.
CI_SELECTION_JOB = "Verification selection"
CI_SUPERSEDED_RE = re.compile(r"superseded by [0-9a-f]{40}: main's queued run verifies")

# Where an older Deploy Dev run is in its delivery.
CANCELLABLE = "cancellable"  # publication has not started
PUBLISHING = "publishing"    # publication started or finished: never stopped
ENDED = "ended"              # nothing left to stop


def load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load("codewire_ci_cancel_superseded_verdict", HERE.parent / "plan" / "main-ci-verdict.py")
Unproven = verdicts.Unproven


def git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repository, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, check=False, timeout=60,
    )


def is_proper_ancestor(repository: Path, older: str, head: str) -> bool:
    if older == head:
        return False
    return git(repository, "merge-base", "--is-ancestor", older, head).returncode == 0


def tree_of(repository: Path, commit: str) -> str:
    completed = git(repository, "rev-parse", "--verify", f"{commit}^{{tree}}")
    tree = completed.stdout.strip()
    if completed.returncode != 0 or not HEX40_RE.fullmatch(tree):
        raise Unproven(f"the tree of {commit} is unavailable")
    return tree


def unfinished_main_runs(api) -> list[dict]:
    statuses = "".join(f"&status={status}" for status in UNFINISHED_RUN_STATES)
    runs = verdicts.bounded(
        api.get_json(
            f"/actions/runs?workflow_id={WORKFLOW}{statuses}&page=1&limit={verdicts.API_LIMIT}"
        ),
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


def delivery_stage(api, run_id: int) -> str:
    jobs = verdicts.jobs_of(api, run_id)
    publish = verdicts.state_of(verdicts.named_job(jobs, PUBLISH_JOB, run_id))
    if publish == "not-started":
        return CANCELLABLE
    if publish in ("running", "success", "failure"):
        return PUBLISHING
    return ENDED


def unverifiable_reason(api, repository: Path, older: str) -> str | None:
    """Why older's own main CI can no longer verify it, or None while it still can."""
    result = verdicts.verdict(api, older, tree_of(repository, older))
    if result.state == verdicts.SUPERSEDED:
        return result.describe(older)
    if result.state != verdicts.PENDING:
        # Verified, red or unverified (a rerun can still verify it), or no
        # main CI run registered yet: keep it.
        return None
    run_id = result.run_id
    selection = verdicts.named_job(verdicts.jobs_of(api, run_id), CI_SELECTION_JOB, run_id)
    state = verdicts.state_of(selection)
    if state == "not-started":
        return (f"main CI run {run_id} for {older} has not started; main has moved past {older}, "
                f"so it will verify nothing")
    if state == "success" and CI_SUPERSEDED_RE.search(
        api.get_text(f"/actions/jobs/{selection['id']}/logs")
    ):
        return f"main CI run {run_id} recorded {older} as superseded; it verifies nothing"
    # Running (it may already have passed its supersession check), failed
    # (a rerun can still verify it) or verifying: it can still be verified.
    return None


def cancel_superseded(
    api,
    repository: Path,
    head: str,
    *,
    log: Callable[[str], None] = print,
) -> list[int]:
    """Cancel each older delivery that can never sign; return the cancelled run IDs."""
    cancelled: list[int] = []
    try:
        runs = unfinished_main_runs(api)
    except Unproven as exc:
        log(f"::warning::cannot list unfinished Deploy Dev runs ({exc}); cancelling nothing")
        return cancelled
    for run in sorted(runs, key=lambda record: record["id"]):
        run_id = run["id"]
        older = run.get("head_sha") or run.get("commit_sha")
        if not is_proper_ancestor(repository, older, head):
            continue
        try:
            if delivery_stage(api, run_id) != CANCELLABLE:
                continue
            reason = unverifiable_reason(api, repository, older)
            if reason is None:
                log(f"Deploy Dev run {run_id} for {older} keeps delivering: its main CI can still "
                    f"verify it")
                continue
            # Read the jobs again just before cancelling: a run that started
            # publishing is never stopped.
            if delivery_stage(api, run_id) != CANCELLABLE:
                log(f"Deploy Dev run {run_id} for {older} started publishing; it is left to finish")
                continue
            status = api.post(f"/actions/runs/{run_id}/cancel")
        except Unproven as exc:
            log(f"::warning::cannot read or cancel Deploy Dev run {run_id} ({exc}); it is left to finish")
            continue
        if status in (200, 202, 204):
            cancelled.append(run_id)
            log(f"cancelled Deploy Dev run {run_id} for {older}, which can never sign ({reason}); "
                f"{head}'s delivery carries its change")
        else:
            log(f"::warning::Forgejo refused to cancel Deploy Dev run {run_id} for {older} "
                f"(HTTP {status}); it builds a set that never signs")
    log(f"cancel-superseded: cancelled {len(cancelled)} older Deploy Dev run(s) for {head}")
    return cancelled


def main() -> int:
    # Cancelling needs only the job token, never the job's OIDC request
    # credentials.
    for name in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        os.environ.pop(name, None)
    environ = dict(os.environ)
    if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != MAIN_REF:
        print("only a push to main supersedes Dev deliveries; cancelling nothing")
        return 0
    head = environ.get("GITHUB_SHA", "")
    if not HEX40_RE.fullmatch(head):
        print("::warning::the workflow commit is invalid; cancelling nothing")
        return 0
    try:
        api = verdicts.ForgejoAPI.from_environ(environ)
        cancel_superseded(api, Path.cwd(), head)
    except Exception as exc:  # noqa: BLE001 - an optimisation never fails delivery
        print(f"::warning::superseded-delivery cancellation stopped ({exc}); this run still delivers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
