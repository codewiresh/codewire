#!/usr/bin/env python3
"""One Dev delivery at a time; the newest waits; none is ever cancelled.

Recorded-response tests of scripts/ci/deploy/wait-for-dev-delivery-turn.py on a
real history A-B-C-D.

Rule (owner, 2026-11-10, #4071, recorded on #3013): the Dev delivery in flight
always finishes and publishes. At most one delivery waits behind it, the
newest; a newer commit replaces the waiting one, and the ones in between are
skipped. When the in-flight delivery finishes, the waiting one starts.

Old rule (2026-10-21 and 2026-10-24): a newer green commit cancelled an older
delivery before it published. Under a steady merge rate every delivery was
cancelled by the next one, and Dev did not advance for over an hour.
"""

from __future__ import annotations

import importlib.util
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/plan/tests"))
import verdict_fixtures as fx  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_dev_delivery_turn", ROOT / "scripts/ci/deploy/wait-for-dev-delivery-turn.py"
)
assert SPEC and SPEC.loader
turn = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = turn
SPEC.loader.exec_module(turn)

DEPLOY_LIST = (
    "/actions/runs?workflow_id=deploy-dev.yaml&status=waiting&status=blocked&status=running"
    "&status=unknown&page=1&limit=100"
)


def history(directory: Path, names: str = "ABCD") -> list[str]:
    """Commits on one line, oldest first."""
    environ = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

    def run(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=directory, env=environ, check=True,
                              capture_output=True, text=True).stdout.strip()

    run("init", "-q")
    commits = []
    for name in names:
        (directory / f"{name}.rs").write_text(f"{name}\n")
        run("add", "-A")
        run("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-q", "-m", name)
        commits.append(run("rev-parse", "HEAD"))
    return commits


def deploy_run(run_id: int, sha: str) -> dict:
    return fx.run(sha, run_id=run_id, workflow="deploy-dev.yaml", status="running")


# A delivery's jobs in each phase: selection, turn, both builds, publish.
PHASES = {
    "selecting": ("running", "blocked", "blocked", "blocked"),
    "docs-only": ("success", "skipped", "skipped", "skipped"),
    "turn-queued": ("success", "waiting", "blocked", "blocked"),
    "waiting": ("success", "running", "blocked", "blocked"),
    "building": ("success", "success", "running", "blocked"),
    "publishing": ("success", "success", "success", "running"),
    "published": ("success", "success", "success", "success"),
    "replaced": ("success", "success", "skipped", "skipped"),
    "red": ("success", "success", "success", "skipped"),
}


def deploy_jobs(run_id: int, phase: str, *, turn_job: bool = True) -> list[dict]:
    selection, turn_state, builds, publish = PHASES[phase]
    base = run_id * 10
    jobs = [
        {"id": base + 1, "run_id": run_id, "name": "Deploy selection", "status": selection},
        {"id": base + 2, "run_id": run_id, "name": "Build and push the service runtime images", "status": builds},
        {"id": base + 3, "run_id": run_id, "name": "Build and push the daemon runtime image", "status": builds},
        {"id": base + 4, "run_id": run_id, "name": "Publish the exact runtime image set", "status": publish},
    ]
    if turn_job:
        jobs.append({"id": base + 5, "run_id": run_id, "name": "Dev delivery turn", "status": turn_state})
    return jobs


class FakeForgejo:
    """Deploy Dev runs whose phases change from one poll to the next."""

    repository = fx.REPOSITORY

    def __init__(self, polls):
        # Each poll: {run_id: (sha, phase)} or an exception.
        self.polls = polls
        self.poll = 0
        self.calls: list[str] = []

    def state(self):
        state = self.polls[min(self.poll, len(self.polls) - 1)]
        if isinstance(state, Exception):
            raise state
        return state

    def get_json(self, path: str):
        self.calls.append(f"GET {path}")
        if path == DEPLOY_LIST:
            state = self.state()
            runs = [deploy_run(run_id, sha) for run_id, (sha, *_rest) in sorted(state.items())]
            return {"total_count": len(runs), "workflow_runs": runs}
        match = re.fullmatch(r"/actions/runs/(\d+)/jobs\?page=1&limit=100", path)
        assert match, path
        run_id = int(match.group(1))
        sha, phase, *old = self.state()[run_id]
        jobs = deploy_jobs(run_id, phase, turn_job=not old)
        return {"total_count": len(jobs), "jobs": jobs}

    def post(self, path: str) -> int:  # pragma: no cover - the turn never posts
        self.calls.append(f"POST {path}")
        raise AssertionError(f"the Dev delivery turn must never act on a run: {path}")


class DevDeliveryTurn(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="codewire-dev-delivery-turn-test-")
        self.repo = Path(self.directory.name)
        self.a, self.b, self.c, self.d = history(self.repo)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def decide(self, state: dict, head: str, own: int):
        return turn.decide(FakeForgejo([state]), self.repo, head, own)

    def wait(self, polls: list, head: str, own: int, **options):
        api = FakeForgejo(polls)
        lines: list[str] = []
        clock = iter(range(0, 10_000, 30))

        def sleep(_seconds: float) -> None:
            api.poll += 1

        result = turn.wait_for_turn(api, self.repo, head, own, sleep=sleep,
                                    clock=lambda: next(clock), log=lines.append, **options)
        return result, "\n".join(lines), api

    def test_steady_merges_dev_still_advances_always_to_the_newest(self) -> None:
        # A is in flight. B, C and D merge one after another before A finishes:
        # each newer one replaces the waiting one, A is never stopped, and when
        # A finishes the newest, D, builds next.
        result, log, api = self.wait([
            {10: (self.a, "building"), 20: (self.b, "waiting")},
            {10: (self.a, "building"), 20: (self.b, "waiting"), 30: (self.c, "waiting")},
        ], self.b, 20)
        self.assertEqual(result, turn.REPLACED)
        self.assertIn(f"Deploy Dev run 30 for the newer {self.c} has reached its turn", log)
        result, _, _ = self.wait([
            {10: (self.a, "publishing"), 20: (self.b, "replaced"), 30: (self.c, "waiting"),
             40: (self.d, "turn-queued")},
        ], self.c, 30)
        self.assertEqual(result, turn.REPLACED)
        result, log, api = self.wait([
            {10: (self.a, "publishing"), 30: (self.c, "replaced"), 40: (self.d, "waiting")},
            {10: (self.a, "published"), 40: (self.d, "waiting")},
        ], self.d, 40)
        self.assertEqual(result, turn.GO)
        self.assertIn(f"Deploy Dev run 10 for {self.a} is in flight; waiting", log)
        self.assertIn("no other delivery is in flight; it builds and publishes now", log)
        self.assertFalse([call for call in api.calls if call.startswith("POST")])

    def test_the_newest_waiting_goes_red_and_the_next_green_waits(self) -> None:
        # B was the newest and built after A; B's main CI went red, so its
        # publish job delivered nothing and ended. C waited while B was in
        # flight and builds once B has ended; nothing was cancelled.
        result, log, api = self.wait([
            {20: (self.b, "building"), 30: (self.c, "waiting")},
            {20: (self.b, "red"), 30: (self.c, "waiting")},
        ], self.c, 30)
        self.assertEqual(result, turn.GO)
        self.assertIn(f"Deploy Dev run 20 for {self.b} is in flight; waiting", log)
        self.assertFalse([call for call in api.calls if call.startswith("POST")])

    def test_only_a_newer_run_at_its_turn_replaces_the_waiting_one(self) -> None:
        for phase, expected in (("selecting", turn.WAIT), ("docs-only", turn.WAIT),
                                ("turn-queued", turn.REPLACED), ("waiting", turn.REPLACED),
                                ("building", turn.REPLACED), ("replaced", turn.WAIT)):
            with self.subTest(newer=phase):
                verdict, _ = self.decide({10: (self.a, "building"), 20: (self.b, "waiting"),
                                          30: (self.c, phase)}, self.b, 20)
                self.assertEqual(verdict, expected)

    def test_an_older_waiting_run_is_not_in_flight(self) -> None:
        # B waits while nothing is in flight: the newer C goes now, and B steps aside.
        self.assertEqual(self.decide({20: (self.b, "waiting"), 30: (self.c, "waiting")}, self.c, 30)[0],
                         turn.GO)
        self.assertEqual(self.decide({20: (self.b, "waiting"), 30: (self.c, "waiting")}, self.b, 20)[0],
                         turn.REPLACED)

    def test_in_flight_covers_queued_builds_publishing_and_runs_from_before_the_turn_job(self) -> None:
        for phase, old, expected in (("building", False, turn.WAIT), ("publishing", False, turn.WAIT),
                                     ("published", False, turn.GO), ("red", False, turn.GO),
                                     ("replaced", False, turn.GO), ("building", True, turn.WAIT),
                                     ("published", True, turn.GO)):
            with self.subTest(older=phase, old_workflow=old):
                older = (self.a, phase, "old") if old else (self.a, phase)
                self.assertEqual(self.decide({10: older, 20: (self.b, "waiting")}, self.b, 20)[0], expected)
        queued = {10: (self.a, "building"), 20: (self.b, "waiting")}
        queued_jobs = deploy_jobs(10, "building")
        for job in queued_jobs[1:3]:
            job["status"] = "waiting"
        self.assertTrue(turn.in_flight(queued_jobs, 10))
        self.assertEqual(self.decide(queued, self.b, 20)[0], turn.WAIT)

    def test_unreadable_state_retries_then_builds(self) -> None:
        failure = turn.Unproven("forgejo-api-unavailable")
        result, log, _ = self.wait([failure, {10: (self.a, "building"), 20: (self.b, "waiting")},
                                    {20: (self.b, "waiting")}], self.b, 20)
        self.assertEqual(result, turn.GO)
        self.assertIn("unreadable", log)
        result, log, _ = self.wait([failure], self.b, 20)
        self.assertEqual(result, turn.GO)
        self.assertIn(f"after {turn.UNREADABLE_LIMIT} tries; {self.b} builds now", log)

    def test_a_wait_past_its_bound_builds(self) -> None:
        result, log, _ = self.wait([{10: (self.a, "building"), 20: (self.b, "waiting")}], self.b, 20,
                                   wait_seconds=300)
        self.assertEqual(result, turn.GO)
        self.assertIn("still waiting after 300 s", log)

    def test_main_writes_go_outside_a_push_to_main(self) -> None:
        with tempfile.NamedTemporaryFile("r") as output:
            environ = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/1/head",
                       "GITHUB_OUTPUT": output.name}
            with mock.patch.dict(os.environ, environ, clear=True), redirect_stdout(io.StringIO()):
                self.assertEqual(turn.main(), 0)
            self.assertEqual(open(output.name, encoding="utf-8").read(), "turn=go\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
