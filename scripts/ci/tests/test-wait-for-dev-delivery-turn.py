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

Old behaviour (until #4476): the waiting run polled for up to 80 minutes on a
runner that cancels every job after 25, so a delivery waiting behind a longer
one was cancelled and never reached Dev (Deploy Dev 46838, 2026-11-13). Now it
defers at 20 minutes and the delivery in flight hands the turn on.
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
DEPLOY_ALL = "/actions/runs?workflow_id=deploy-dev.yaml&page=1&limit=100"


def history(directory: Path, names: str = "ABCD") -> list[str]:
    """Commits on one line, oldest first."""
    # No auto maintenance: a detached one still writing objects/ after the last
    # commit made tearDown's cleanup fail with "Directory not empty" (#4477's
    # first CI run).
    environ = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "maintenance.auto", "GIT_CONFIG_VALUE_0": "false",
               "GIT_CONFIG_KEY_1": "gc.auto", "GIT_CONFIG_VALUE_1": "0"}

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
    "deferring": ("success", "success", "skipped", "skipped", "waiting"),
    "deferred": ("success", "success", "skipped", "skipped", "success"),
    "turn-cancelled": ("success", "cancelled", "skipped", "skipped"),
    "selection-failed": ("failure", "skipped", "skipped", "skipped"),
}


def deploy_jobs(run_id: int, phase: str, *, turn_job: bool = True) -> list[dict]:
    selection, turn_state, builds, publish, *marker = PHASES[phase]
    base = run_id * 10
    jobs = [
        {"id": base + 1, "run_id": run_id, "name": "Deploy selection", "status": selection},
        {"id": base + 2, "run_id": run_id, "name": "Build and push the service runtime images", "status": builds},
        {"id": base + 3, "run_id": run_id, "name": "Build and push the daemon runtime image", "status": builds},
        {"id": base + 4, "run_id": run_id, "name": "Publish the exact runtime image set", "status": publish},
    ]
    if turn_job:
        jobs.append({"id": base + 5, "run_id": run_id, "name": "Dev delivery turn", "status": turn_state})
        jobs.append({"id": base + 6, "run_id": run_id, "name": "Deferred to the delivery in flight",
                     "status": marker[0] if marker else "skipped"})
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
        return turn.decide(FakeForgejo([state]), head, own)

    def wait(self, polls: list, head: str, own: int, **options):
        api = FakeForgejo(polls)
        lines: list[str] = []
        clock = iter(range(0, 10_000, 30))

        def sleep(_seconds: float) -> None:
            api.poll += 1

        result = turn.wait_for_turn(api, head, own, sleep=sleep,
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

    def test_a_newer_run_is_known_by_its_run_id_not_by_this_checkout(self) -> None:
        # The turn job's checkout holds only its own commit, so a newer commit is
        # not in it; seen live on 2026-11-11 (runs 41659 and 41685 kept waiting
        # beside the newer 41693). A higher run ID is a later push on main.
        unknown = "f" * 40
        self.assertEqual(self.decide({10: (self.a, "building"), 20: (self.b, "waiting"),
                                      30: (unknown, "waiting")}, self.b, 20)[0], turn.REPLACED)
        # A lower run ID is an older push, even when its commit is unknown here.
        self.assertEqual(self.decide({10: (unknown, "waiting"), 20: (self.b, "waiting")}, self.b, 20)[0],
                         turn.GO)

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

    def test_a_wait_past_its_bound_defers_inside_the_runner_cap(self) -> None:
        # The light runner cancels a job after 25 minutes (#4476); the turn
        # defers before that instead of being cancelled, and builds nothing.
        self.assertLess(turn.WAIT_SECONDS, 25 * 60 - 2 * turn.POLL_SECONDS)
        result, log, api = self.wait([{10: (self.a, "building"), 20: (self.b, "waiting")}], self.b, 20,
                                     wait_seconds=300)
        self.assertEqual(result, turn.DEFERRED)
        self.assertIn("still waiting after 300 s", log)
        self.assertIn("hands the turn on when it ends", log)
        self.assertFalse([call for call in api.calls if call.startswith("POST")])

    def test_a_deferred_newer_run_neither_replaces_nor_is_in_flight(self) -> None:
        self.assertEqual(self.decide({20: (self.b, "waiting"), 30: (self.c, "deferred")}, self.b, 20)[0],
                         turn.GO)
        self.assertEqual(self.decide({20: (self.b, "deferred"), 30: (self.c, "waiting")}, self.c, 30)[0],
                         turn.GO)

    def test_main_writes_go_outside_a_push_to_main(self) -> None:
        with tempfile.NamedTemporaryFile("r") as output:
            environ = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/1/head",
                       "GITHUB_OUTPUT": output.name}
            with mock.patch.dict(os.environ, environ, clear=True), redirect_stdout(io.StringIO()):
                self.assertEqual(turn.main(), 0)
            self.assertEqual(open(output.name, encoding="utf-8").read(), "turn=go\n")


class HandoverForgejo(FakeForgejo):
    """Deploy Dev runs, finished or not, and the reruns the handover asks for."""

    def __init__(self, polls, rerun_status=204):
        super().__init__(polls)
        self.rerun_status = rerun_status

    def get_json(self, path: str):
        if path == DEPLOY_ALL:
            self.calls.append(f"GET {path}")
            runs = [deploy_run(run_id, sha) for run_id, (sha, *_rest) in sorted(self.state().items())]
            return {"total_count": len(runs), "workflow_runs": runs}
        return super().get_json(path)

    def post(self, path: str) -> int:
        self.calls.append(f"POST {path}")
        return self.rerun_status


class DevDeliveryHandover(unittest.TestCase):
    """The delivery that had the turn hands it to the newest one that deferred."""

    A, B, C, D = ("a" * 40, "b" * 40, "c" * 40, "d" * 40)

    def hand_on(self, polls: list, own: int = 10, rerun_status: int = 204):
        api = HandoverForgejo(polls, rerun_status)
        lines: list[str] = []
        clock = iter(range(0, 10_000, 30))

        def sleep(_seconds: float) -> None:
            api.poll += 1

        result = turn.hand_on(api, own, sleep=sleep, clock=lambda: next(clock), log=lines.append,
                              wait_seconds=300)
        return result, "\n".join(lines), [call for call in api.calls if call.startswith("POST")]

    def test_the_newest_deferred_run_gets_the_turn_and_older_ones_stay_replaced(self) -> None:
        # A published while B and then C waited too long and deferred: only C,
        # the newest, is rerun; B's change is in C.
        result, log, posts = self.hand_on([{10: (self.A, "published"), 20: (self.B, "deferred"),
                                            30: (self.C, "deferred")}])
        self.assertEqual(result, 0)
        self.assertEqual(posts, ["POST /actions/jobs/305/rerun"])
        self.assertIn("Deploy Dev run 30 deferred; reran its turn job 305", log)

    def test_a_newer_run_still_waiting_takes_its_own_turn(self) -> None:
        for phase in ("selecting", "turn-queued", "building", "replaced"):
            with self.subTest(newest=phase):
                result, _, posts = self.hand_on([{10: (self.A, "published"), 20: (self.B, "deferred"),
                                                  30: (self.C, phase)}])
                self.assertEqual((result, posts), (0, []))

    def test_a_run_that_selected_nothing_is_passed_over(self) -> None:
        for phase in ("docs-only", "selection-failed"):
            with self.subTest(newest=phase):
                result, _, posts = self.hand_on([{10: (self.A, "red"), 20: (self.B, "deferred"),
                                                  30: (self.C, phase)}])
                self.assertEqual((result, posts), (0, ["POST /actions/jobs/205/rerun"]))

    def test_a_turn_cancelled_at_the_runner_cap_is_rerun(self) -> None:
        # Deploy Dev 46838: its turn job was cancelled at 25 minutes.
        result, _, posts = self.hand_on([{10: (self.A, "published"), 20: (self.B, "turn-cancelled")}])
        self.assertEqual((result, posts), (0, ["POST /actions/jobs/205/rerun"]))

    def test_a_turn_still_deciding_settles_first(self) -> None:
        # B's last poll saw A in flight; it defers just after A ends.
        result, _, posts = self.hand_on([{10: (self.A, "published"), 20: (self.B, "waiting")},
                                         {10: (self.A, "published"), 20: (self.B, "deferring")},
                                         {10: (self.A, "published"), 20: (self.B, "deferred")}])
        self.assertEqual((result, posts), (0, ["POST /actions/jobs/205/rerun"]))
        result, _, posts = self.hand_on([{10: (self.A, "published"), 20: (self.B, "waiting")},
                                         {10: (self.A, "published"), 20: (self.B, "building")}])
        self.assertEqual((result, posts), (0, []))

    def test_nothing_later_hands_on_nothing(self) -> None:
        result, log, posts = self.hand_on([{5: (self.D, "deferred"), 10: (self.A, "published")}])
        self.assertEqual((result, posts), (0, []))
        self.assertIn("no later delivery is waiting", log)

    def test_a_refused_or_unsettled_handover_is_a_loud_missed_trigger(self) -> None:
        result, log, _ = self.hand_on([{10: (self.A, "published"), 20: (self.B, "deferred")}], rerun_status=403)
        self.assertEqual(result, 1)
        self.assertIn("::error::missed trigger", log)
        result, log, _ = self.hand_on([{10: (self.A, "published"), 20: (self.B, "waiting")}])
        self.assertEqual(result, 1)
        self.assertIn("::error::missed trigger: after 300 s", log)
        result, log, _ = self.hand_on([turn.Unproven("forgejo-api-unavailable")])
        self.assertEqual(result, 1)

    def test_main_hands_on_only_for_a_push_to_main(self) -> None:
        environ = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/1/head", "GITHUB_RUN_ID": "7"}
        with mock.patch.dict(os.environ, environ, clear=True), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(turn.main(["--hand-on"]), 0)
        self.assertIn("only a push to main", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
