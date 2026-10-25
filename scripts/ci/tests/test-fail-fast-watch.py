#!/usr/bin/env python3
"""A pull request's CI run stops at its first failed job (infra#1632).

Recorded-response tests of scripts/ci/select/fail-fast-watch.py, and the
ci.yaml job that runs it: it cancels the run only after another job has ended
in failure (never from inside a failing job, so that job keeps its result and
log, #3126), counts only each job's latest attempt, stops quietly when every
check finished, never runs on a push to main, and nothing needs it.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_fail_fast_watch", ROOT / "scripts/ci/select/fail-fast-watch.py"
)
assert SPEC and SPEC.loader
watcher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = watcher
SPEC.loader.exec_module(watcher)

RUN = 77


def job(job_id: int, name: str, status: str, attempt: int = 1) -> dict:
    return {"id": job_id, "run_id": RUN, "name": name, "status": status, "attempt": attempt}


def base(policy: str = "running", rust: str = "running", **extra) -> list[dict]:
    return [
        job(1, "Verification selection", "success"),
        job(2, "Policy verification", policy),
        job(3, "Rust / transport packages", rust),
        job(4, "Required verification", "blocked"),
        job(5, watcher.WATCHER_JOB, "running"),
        *extra.get("more", []),
    ]


class FakeForgejo:
    def __init__(self, polls: list, cancel_status: int = 204):
        self.polls = polls
        self.served = 0
        self.cancel_status = cancel_status
        self.posts: list[str] = []

    def get_json(self, path: str):
        assert path == f"/actions/runs/{RUN}/jobs?page=1&limit=100", path
        poll = self.polls[min(self.served, len(self.polls) - 1)]
        self.served += 1
        if isinstance(poll, Exception):
            raise poll
        return {"total_count": len(poll), "jobs": poll}

    def post(self, path: str) -> int:
        self.posts.append(path)
        return self.cancel_status


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    def __call__(self) -> float:
        return self.now


class WatchTests(unittest.TestCase):
    def watch(self, api: FakeForgejo, deadline: float = 600):
        lines: list[str] = []
        clock = Clock()
        result = watcher.watch(api, RUN, poll_seconds=20, deadline_seconds=deadline,
                               sleep=clock.sleep, clock=clock, log=lines.append)
        return result, "\n".join(lines)

    def test_the_first_failure_cancels_the_run(self) -> None:
        api = FakeForgejo([base(), base(), base(policy="failure")])
        result, log = self.watch(api)
        self.assertEqual((result, api.posts), ("cancelled", [f"/actions/runs/{RUN}/cancel"]))
        self.assertEqual(api.served, 3)
        self.assertIn("stopping this pull request's run at its first failure: Policy verification failed", log)

    def test_success_and_skips_finish_without_cancelling(self) -> None:
        api = FakeForgejo([base(), base(policy="success", rust="skipped")])
        result, log = self.watch(api)
        self.assertEqual((result, api.posts), ("finished", []))
        self.assertIn("without a failure", log)

    def test_a_rerun_of_a_failed_job_is_not_cancelled_for_its_earlier_attempt(self) -> None:
        rerun = [job(2, "Policy verification", "failure", attempt=1),
                 job(6, "Policy verification", "running", attempt=2)]
        jobs = [j for j in base() if j["name"] != "Policy verification"] + rerun
        finished = [j for j in jobs if j["id"] != 6] + [job(6, "Policy verification", "success", attempt=2)]
        finished = [j if j["id"] != 3 else job(3, "Rust / transport packages", "success") for j in finished]
        api = FakeForgejo([jobs, finished])
        result, _ = self.watch(api)
        self.assertEqual((result, api.posts), ("finished", []))

    def test_the_selection_aggregate_and_watcher_never_count(self) -> None:
        jobs = [job(1, "Verification selection", "failure"), job(4, "Required verification", "failure"),
                job(5, watcher.WATCHER_JOB, "failure"), job(2, "Policy verification", "success")]
        api = FakeForgejo([jobs])
        result, _ = self.watch(api)
        self.assertEqual((result, api.posts), ("finished", []))

    def test_unreadable_jobs_are_retried_and_a_refused_cancel_is_reported(self) -> None:
        api = FakeForgejo([watcher.verdicts.Unproven("forgejo-api-unavailable"), base(rust="failure")],
                          cancel_status=403)
        result, log = self.watch(api)
        self.assertEqual((result, api.posts), ("refused", [f"/actions/runs/{RUN}/cancel"]))
        self.assertIn("cannot read this run's jobs", log)
        self.assertIn("HTTP 403", log)

    def test_the_deadline_ends_the_watch_quietly(self) -> None:
        api = FakeForgejo([base()])
        result, _ = self.watch(api, deadline=60)
        self.assertEqual((result, api.posts), ("deadline", []))

    def test_main_never_watches_a_push_and_never_fails(self) -> None:
        for environ in ({"GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ID": "77"},
                        {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ID": "x"},
                        {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_RUN_ID": "77"}):
            with self.subTest(environ), mock.patch.dict(os.environ, environ, clear=True), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(watcher.main(), 0)


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.jobs = yaml.safe_load((ROOT / ".gitea/workflows/ci.yaml").read_text())["jobs"]

    def test_the_watcher_runs_on_pull_requests_only_and_nothing_needs_it(self) -> None:
        job_ = self.jobs["fail-fast"]
        self.assertEqual(job_["name"], watcher.WATCHER_JOB)
        self.assertEqual(job_["needs"], ["verification-selection"])
        self.assertIn("github.event_name == 'pull_request'", job_["if"])
        self.assertIn("scripts/ci/select/fail-fast-watch.py", job_["steps"][-1]["run"])
        for name, other in self.jobs.items():
            needs = other.get("needs") or []
            self.assertNotIn("fail-fast", [needs] if isinstance(needs, str) else needs, name)

    def test_the_watcher_ends_quietly_before_its_runner_stops_it(self) -> None:
        # A light runner kills a task after 25 minutes, and a killed watcher
        # shows as a failed check (run 21980's rerun). Its own deadline comes
        # first, then the job's timeout, then the runner's limit.
        timeout = self.jobs["fail-fast"]["timeout-minutes"]
        self.assertLess(watcher.DEADLINE_SECONDS + 2 * watcher.POLL_SECONDS, timeout * 60)
        self.assertLess(timeout, watcher.LIGHT_TASK_LIMIT_MINUTES)
        self.assertIn("UNTRUSTED_LIGHT", self.jobs["fail-fast"]["runs-on"])

    def test_the_jobs_it_ignores_are_ci_yamls_own(self) -> None:
        names = {job_["name"] for job_ in self.jobs.values()}
        self.assertTrue(watcher.NOT_CHECKS <= names, watcher.NOT_CHECKS - names)

    def test_no_job_cancels_its_own_run(self) -> None:
        # #3126: a failing job that cancels its own run is relabelled cancelled.
        for name, job_ in self.jobs.items():
            if name == "fail-fast":
                continue
            for step in job_.get("steps", []):
                self.assertNotIn("/cancel", step.get("run", ""), name)


if __name__ == "__main__":
    unittest.main(verbosity=1)
