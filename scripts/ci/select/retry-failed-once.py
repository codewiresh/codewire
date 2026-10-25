#!/usr/bin/env python3
"""A main push run retries its failed test jobs once (infra#1534).

A superseded main run verifies nothing, so Dev's next delivery hangs on the
tip run alone, and one flaky test there used to cost a whole main cycle (about
65 minutes plus queue; main CI runs 21922 and 22110, 2026-10-25). Once the
tip run's Required verification has failed, this job reruns, with the job
token, exactly the test jobs that failed on their first attempt. Forgejo then
runs Required verification and Dev delivery again after them. A real failure
fails again and the run stays red.

It retries only:
- a push to main whose commit is still main's tip (a newer push verifies the
  cumulative change instead);
- test families, never Policy verification, whose advisory and expiry checks
  stay blocking (#3119) and are not flaky;
- a job on its first attempt: nothing is ever retried twice, and this job is
  never rerun by its own reruns (Forgejo skips a job that is still running).

It never fails its run: anything unreadable means no retry.
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
# Test families whose failures may be load flakes. Policy is deterministic.
RETRYABLE_RE = re.compile(
    r"^(Standard verification|Tooling / delivery contract verification|Compile every Rust target"
    r"|Rust / .+|Database verification|Service control-plane verification"
    r"|Service runtime-plane verification)$"
)
POSITIVE_RE = re.compile(r"^[1-9][0-9]*$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


def load_verdicts() -> ModuleType:
    path = HERE.parent / "plan" / "main-ci-verdict.py"
    spec = importlib.util.spec_from_file_location("codewire_ci_retry_verdict", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verdicts = load_verdicts()


def to_retry(jobs: list[dict]) -> tuple[list[dict], list[str]]:
    """The failed retryable jobs to rerun, and the names already retried.

    Each job name's latest attempt decides. A latest attempt above 1 means the
    job was retried already, so it is never retried again.
    """
    latest: dict[str, tuple[int, dict]] = {}
    for job in jobs:
        name = job.get("name")
        if not isinstance(name, str) or not RETRYABLE_RE.fullmatch(name):
            continue
        attempt = verdicts.job_attempt(job)
        if name not in latest or attempt > latest[name][0]:
            latest[name] = (attempt, job)
    rerun, retried = [], []
    for name, (attempt, job) in sorted(latest.items()):
        if verdicts.state_of(job) != "failure":
            continue
        if attempt > 1:
            retried.append(name)
        else:
            rerun.append(job)
    return rerun, retried


def retry(api, run_id: int, *, log: Callable[[str], None] = print) -> str:
    try:
        rerun, retried = to_retry(verdicts.jobs_of(api, run_id))
    except verdicts.Unproven as exc:
        log(f"::warning::cannot read this run's jobs ({exc}); retrying nothing")
        return "unreadable"
    if retried:
        log(f"already retried once: {', '.join(retried)}; the run stays red")
        return "already-retried"
    if not rerun:
        log("no failed test job to retry (a Policy failure is never retried); the run stays red")
        return "nothing"
    names = ", ".join(job["name"] for job in rerun)
    # Said before the reruns, which also restart Required verification.
    log(f"retrying once, as a possible flake: {names}")
    refused = []
    for job in rerun:
        status = api.post(f"/actions/jobs/{job['id']}/rerun")
        if status not in (200, 201, 202, 204):
            refused.append(f"{job['name']} (HTTP {status})")
    if refused:
        log(f"::warning::Forgejo refused to rerun {', '.join(refused)}; the run stays red")
        return "refused"
    return "retried"


def main_tip() -> str | None:
    try:
        output = subprocess.run(
            ["git", "ls-remote", "origin", "refs/heads/main"],
            capture_output=True, text=True, timeout=60, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in output.splitlines():
        sha, _, ref = line.partition("\t")
        if ref == "refs/heads/main" and HEX40_RE.fullmatch(sha):
            return sha
    return None


def main(environ: dict[str, str] | None = None, tip: Callable[[], str | None] = main_tip) -> int:
    environ = dict(os.environ) if environ is None else environ
    if environ.get("GITHUB_EVENT_NAME") != "push" or environ.get("GITHUB_REF") != "refs/heads/main":
        print("only a push to main retries its failed jobs")
        return 0
    run_id = environ.get("GITHUB_RUN_ID", "")
    sha = environ.get("GITHUB_SHA", "")
    if not POSITIVE_RE.fullmatch(run_id) or not HEX40_RE.fullmatch(sha):
        print("::warning::the run or commit is invalid; retrying nothing")
        return 0
    current = tip()
    if current != sha:
        print(f"main has moved on to {current or 'an unreadable commit'}; its run verifies this change, "
              "so nothing is retried here")
        return 0
    try:
        api = verdicts.ForgejoAPI.from_environ(environ)
    except verdicts.Unproven as exc:
        print(f"::warning::the Forgejo API is unusable ({exc}); retrying nothing")
        return 0
    retry(api, int(run_id), log=lambda line: print(line, flush=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
