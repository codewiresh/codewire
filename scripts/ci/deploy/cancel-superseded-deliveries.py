#!/usr/bin/env python3
"""At most two Dev deliveries build at once, and none that can never sign.

The owner's rule (2026-10-21, on infra#1594): "we need to cancel older if > 2".
A Deploy Dev run signs only after its own commit's main CI verdict. Each run's
selection job runs this once, as the only place one delivery stops another.
It walks the active Deploy Dev push runs on main from the newest, and keeps
building:

- this run, and any run of a commit that is not a proper ancestor of it (a
  rerun of this commit, or a newer or unrelated one), since this run cannot
  speak for those;
- a run that has started publishing. Publishing signs and dispatches, so it is
  never stopped: a cancelled run never signs or dispatches anything, and no set
  is left half signed. Such a run finishes within minutes;
- the newest run whose commit main CI has already verified, unless a newer
  commit is verified too. Every green main commit newer than Dev's source is
  delivered (owner, 2026-10-24: "if main is green, why would dev not be
  deployed?"), so a green delivery is never cancelled for one that may still
  go red;
- the newest runs whose own main CI can still verify them, until two are
  building.

It cancels every other run of an older commit before it publishes, whether it
is still queued or already building:

- a run with a newer verified commit, which delivers its change;
- a run whose main CI can no longer verify it: its ci.yaml push run's
  selection has not started, so main moved past it, or that selection
  recorded it as superseded. It would build a set that never signs;
- a run still being verified beyond the two building. If its main CI passes
  later, main CI's final job restarts it (rerun-dev-publish.py), so a
  cancelled delivery is never lost.

A red or unverified main CI run is not a reason to cancel, because a rerun can
still verify it. Only older commits are cancelled, so a newer delivery carries
each cancelled change and Dev never moves backwards. Only Deploy Dev push runs
on main are considered: main CI, releases, the release dry run and Production
runs always finish. An older run never cancels itself; the newer runs'
selections decide for it.

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
# Deliveries that build at once (owner, 2026-10-21, on infra#1594).
ACTIVE_DELIVERY_LIMIT = 2
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


def commit_verified(api, repository: Path, commit: str) -> bool:
    """Whether main CI verified this commit; anything unreadable is not verified."""
    try:
        return verdicts.verdict(api, commit, tree_of(repository, commit)).verified
    except Unproven:
        return False


def never_sign_reason(api, older: str, result) -> str | None:
    """Why older's own main CI can no longer verify it, or None while it still can."""
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
    """Cancel the older deliveries beyond two, or that can never sign; return their run IDs."""
    cancelled: list[int] = []
    try:
        runs = unfinished_main_runs(api)
    except Unproven as exc:
        log(f"::warning::cannot list unfinished Deploy Dev runs ({exc}); cancelling nothing")
        return cancelled
    # First pass, from the newest: which runs build regardless, and how far
    # each older cancellable run's own main CI has got.
    building = 0
    newer_verified = False
    candidates: list[tuple[int, str, str | None, bool]] = []  # run, commit, never-sign reason, verified
    for run in sorted(runs, key=lambda record: record["id"], reverse=True):
        run_id = run["id"]
        older = run.get("head_sha") or run.get("commit_sha")
        if not is_proper_ancestor(repository, older, head):
            # This run, a rerun of its commit, or a newer or unrelated commit.
            building += 1
            newer_verified = newer_verified or commit_verified(api, repository, older)
            continue
        try:
            stage = delivery_stage(api, run_id)
            if stage == ENDED:
                continue
            if stage == PUBLISHING:
                building += 1
                newer_verified = newer_verified or commit_verified(api, repository, older)
                continue
            result = verdicts.verdict(api, older, tree_of(repository, older))
            verified = result.verified
            if newer_verified:
                reason = f"newer commit's main CI has passed, and that delivery carries {older}'s change"
            else:
                reason = never_sign_reason(api, older, result)
                if reason is not None:
                    reason = f"it can never sign: {reason}"
            candidates.append((run_id, older, reason, verified and not newer_verified))
            newer_verified = newer_verified or verified
        except Unproven as exc:
            building += 1
            log(f"::warning::cannot read Deploy Dev run {run_id} or its main CI ({exc}); it is left to finish")
    # Second pass: the newest green delivery keeps its place first, then the
    # newest still being verified, up to two building.
    keep: set[int] = set()
    for run_id, older, reason, verified in candidates:
        if reason is None and verified:
            keep.add(run_id)
            building += 1
            log(f"Deploy Dev run {run_id} for {older} keeps delivering: main CI verified {older} and no "
                f"newer commit is verified yet")
    for run_id, older, reason, verified in candidates:
        if reason is not None or run_id in keep:
            continue
        if building < ACTIVE_DELIVERY_LIMIT:
            keep.add(run_id)
            building += 1
            log(f"Deploy Dev run {run_id} for {older} keeps delivering: its main CI can still "
                f"verify it, and it is one of the newest {ACTIVE_DELIVERY_LIMIT} that can")
    for run_id, older, reason, verified in candidates:
        if run_id in keep:
            continue
        if reason is None:
            reason = (f"{ACTIVE_DELIVERY_LIMIT} newer deliveries are building, and at most "
                      f"{ACTIVE_DELIVERY_LIMIT} build at once; if its main CI passes, main CI "
                      f"restarts it")
        try:
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
            log(f"cancelled Deploy Dev run {run_id} for {older} ({reason}); "
                f"{head}'s delivery carries its change")
        else:
            log(f"::warning::Forgejo refused to cancel Deploy Dev run {run_id} for {older} "
                f"(HTTP {status}); it keeps building")
    log(f"cancel-superseded: cancelled {len(cancelled)} older Deploy Dev run(s) for {head}")
    return sorted(cancelled)


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
