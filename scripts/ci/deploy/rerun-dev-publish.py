#!/usr/bin/env python3
"""Start Dev delivery of the commit main CI just verified (#2892).

CI's final job runs this on a push to main, after Required verification. It
reads main CI's verdict for its own commit with the shared predicate
(main-ci-verdict.py); only a verified verdict from this very run goes on.

Deploy Dev's push run for the same commit builds the runtime images and then
runs its publish job, which signs and dispatches only on a verified verdict,
and only while the commit is main's head. Whichever finishes last delivers:

- the publish job has not started yet: it reads this verdict itself;
- it already finished without delivering (it ran while CI was still running):
  this reruns exactly that job, of the Deploy Dev run whose head is this
  commit, with the job token; a rerun keeps the run's push event and actor,
  which the publisher identity requires;
- it is running: wait, bounded, then decide. When the bound runs out this
  fails loudly with one "missed trigger" line and starts nothing else.

A missing Deploy Dev run, builds that failed, and a run cancelled because a
newer push superseded it deliver nothing; that is logged and is no error.
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
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
DEPLOY_WORKFLOW = "deploy-dev.yaml"
SELECTION_JOB = "Deploy selection"
BUILD_JOBS = ("Build and push the service runtime images", "Build and push the daemon runtime image")
PUBLISH_JOB = "Publish the exact runtime image set"
# dispatch-deploy-dev.sh prints this once promote-dev accepted the commit.
DELIVERED = "[dispatch-deploy-dev] accepted canonical source {sha} as deploy run"
DEFAULT_WAIT_SECONDS = 600
DEFAULT_POLL_SECONDS = 15


def load_verdicts() -> ModuleType:
    path = HERE.parent / "plan" / "main-ci-verdict.py"
    spec = importlib.util.spec_from_file_location("codewire_ci_dev_publish_verdict", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load_verdicts()


def skipped_reason(jobs: list[dict], run_id: int, sha: str) -> str:
    states = {}
    for name in (SELECTION_JOB, *BUILD_JOBS):
        try:
            states[name] = verdicts.state_of(verdicts.named_job(jobs, name, run_id))
        except verdicts.Unproven:
            states[name] = "unknown"
    if "cancelled" in states.values():
        return f"Deploy Dev run {run_id} was cancelled, superseded by a newer push; nothing to deliver for {sha}"
    if "failure" in states.values():
        return f"Deploy Dev run {run_id}'s builds failed; nothing to deliver for {sha}, fix forward"
    return f"Deploy Dev run {run_id} selected nothing to deliver for {sha}"


def trigger(
    api,
    sha: str,
    tree: str,
    own_run_id: int,
    *,
    wait_seconds: float = DEFAULT_WAIT_SECONDS,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    log: Callable[[str], None] = print,
) -> int:
    """0 when nothing is owed or the publish job was started; 1 on a missed trigger."""
    try:
        result = verdicts.verdict(api, sha, tree)
        if not result.verified:
            log(f"{result.describe(sha)}; starting no Dev delivery")
            return 0
        if result.run_id != own_run_id:
            log(f"main CI verdict for {sha} comes from ci.yaml run {result.run_id}, not this run "
                f"{own_run_id}; that run starts its delivery")
            return 0
        log(result.describe(sha))
        runs = verdicts.main_push_runs(api, DEPLOY_WORKFLOW, sha)
        if not runs:
            log(f"no Deploy Dev push run for {sha}; nothing to deliver")
            return 0
        run_id = max(run["id"] for run in runs)
        deadline = clock() + wait_seconds
        waiting_logged = False
        refused = False
        while True:
            jobs = verdicts.jobs_of(api, run_id)
            publish = verdicts.named_job(jobs, PUBLISH_JOB, run_id)
            job_id = publish["id"]
            state = verdicts.state_of(publish)
            if state == "skipped":
                log(skipped_reason(jobs, run_id, sha))
                return 0
            if state == "cancelled":
                log(f"Deploy Dev run {run_id}'s publish job was cancelled, superseded by a newer push; "
                    f"nothing to deliver for {sha}")
                return 0
            if state == "not-started":
                log(f"Deploy Dev run {run_id}'s publish job {job_id} has not started; "
                    f"it reads this verdict itself when it runs")
                return 0
            if state == "success" or state == "failure":
                if DELIVERED.format(sha=sha) in api.get_text(f"/actions/jobs/{job_id}/logs"):
                    log(f"Deploy Dev run {run_id}'s publish job {job_id} already delivered {sha}")
                    return 0
                if refused:
                    # Refused although the job was not running: no race.
                    log(f"::error::missed trigger: Forgejo refused to rerun Deploy Dev run {run_id}'s "
                        f"finished publish job {job_id} (HTTP 400); {sha} is not delivered")
                    return 1
                status = api.post(f"/actions/jobs/{job_id}/rerun")
                if status in (200, 201, 204):
                    log(f"reran Deploy Dev run {run_id}'s publish job {job_id} for {sha}; "
                        f"it signs and dispatches only while {sha} is main's head")
                    return 0
                if status != 400:
                    log(f"::error::missed trigger: Forgejo refused to rerun Deploy Dev run {run_id}'s "
                        f"publish job {job_id} (HTTP {status}); {sha} is not delivered")
                    return 1
                # 400: the job started again between the read and the rerun.
                refused = True
            else:
                refused = False
            if clock() >= deadline:
                log(f"::error::missed trigger: Deploy Dev run {run_id}'s publish job {job_id} was still "
                    f"running after {int(wait_seconds)} s, so main CI's verdict did not reach it and {sha} "
                    f"is not delivered. Rerun that job once it finishes; it signs only while {sha} is "
                    f"main's head.")
                return 1
            if not waiting_logged:
                log(f"Deploy Dev run {run_id}'s publish job {job_id} is running; waiting up to "
                    f"{int(wait_seconds)} s for it to finish")
                waiting_logged = True
            sleep(poll_seconds)
    except verdicts.Unproven as exc:
        log(f"::error::missed trigger: cannot read the records Dev delivery of {sha} needs ({exc})")
        return 1


def seconds(environ: dict[str, str], key: str, default: int) -> int:
    value = environ.get(key, "")
    if not value:
        return default
    if not re.fullmatch(r"[0-9]+", value):
        raise SystemExit(f"{key} must be a whole number of seconds")
    return int(value)


def main() -> int:
    environ = dict(os.environ)
    if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != "refs/heads/main":
        print("::error::only main CI's push run starts Dev delivery", file=sys.stderr)
        return 2
    sha = environ.get("GITHUB_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    if not HEX40_RE.fullmatch(sha) or not POSITIVE_RE.fullmatch(run_id):
        print("::error::the workflow commit or run is invalid", file=sys.stderr)
        return 2
    completed = subprocess.run(
        ["git", "rev-parse", "--verify", f"{sha}^{{tree}}"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=60,
    )
    tree = completed.stdout.strip()
    if completed.returncode != 0 or not HEX40_RE.fullmatch(tree):
        print(f"::error::the tree of {sha} is unavailable", file=sys.stderr)
        return 2
    try:
        api = verdicts.ForgejoAPI.from_environ(environ)
    except verdicts.Unproven as exc:
        print(f"::error::missed trigger: the Forgejo API is unusable ({exc})", file=sys.stderr)
        return 1
    return trigger(
        api, sha, tree, int(run_id),
        wait_seconds=seconds(environ, "CODEWIRE_DEV_PUBLISH_WAIT_SECONDS", DEFAULT_WAIT_SECONDS),
        poll_seconds=seconds(environ, "CODEWIRE_DEV_PUBLISH_POLL_SECONDS", DEFAULT_POLL_SECONDS),
    )


if __name__ == "__main__":
    raise SystemExit(main())
