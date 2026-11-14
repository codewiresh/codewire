#!/usr/bin/env python3
"""At most six pull request runs at once, oldest first (infra#2471).

Recorded-response tests of scripts/ci/select/pr-admission.py.

Owner, 2026-11-13: "We'd like less faster runs is better than a bunch of slow
runs." Old behaviour: every pull request run started at once; at a peak 28
were in flight, every job waited on every other, and a run took 35-48 minutes
for about 13 minutes of work.
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/plan/tests"))
import verdict_fixtures as fx  # noqa: E402

SPEC = importlib.util.spec_from_file_location("codewire_ci_pr_admission", ROOT / "scripts/ci/select/pr-admission.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)

UNFINISHED = ("/actions/runs?workflow_id=ci.yaml&status=waiting&status=running&status=unknown"
              "&page=1&limit=100")
# A gate job's state: "admitted" succeeded, "waiting" is still polling, "queued"
# waits for a light slot, "old" is a run from before the gate.
GATE = {"admitted": "success", "waiting": "running", "queued": "waiting", "cancelled": "cancelled"}


class FakeForgejo:
    """Unfinished ci.yaml runs whose gates change from one poll to the next."""

    repository = fx.REPOSITORY

    def __init__(self, polls, *, blocked=(), unreadable=(), on_request=None):
        # Each poll: {run_id: gate} (gate a GATE key or "old") or an exception.
        # blocked: runs whose status is blocked (awaiting approval); unreadable:
        # runs whose jobs cannot be read; on_request: called on every request.
        self.polls = polls
        self.poll = 0
        self.blocked = set(blocked)
        self.unreadable = set(unreadable)
        self.on_request = on_request

    def state(self):
        state = self.polls[min(self.poll, len(self.polls) - 1)]
        if isinstance(state, Exception):
            raise state
        return state

    def get_json(self, path: str):
        if self.on_request:
            self.on_request(path)
        if path == UNFINISHED:
            runs = [fx.run("a" * 40, run_id=run_id, event="pull_request", trigger_event="pull_request",
                           prettyref=f"refs/pull/{run_id}/head",
                           status="blocked" if run_id in self.blocked else "running")
                    for run_id in sorted(self.state(), reverse=True)]
            return {"total_count": len(runs), "workflow_runs": runs}
        run_id = int(path.split("/")[3])
        if run_id in self.unreadable:
            raise gate.Unproven("jobs-ambiguous")
        state = self.state()[run_id]
        jobs = [{"id": run_id * 10 + 1, "run_id": run_id, "name": "Verification selection", "status": "blocked"}]
        if state != "old":
            jobs.append({"id": run_id * 10, "run_id": run_id, "name": "PR admission", "status": GATE[state]})
        return {"total_count": len(jobs), "jobs": jobs}


class PrAdmission(unittest.TestCase):
    def decide(self, state: dict, own: int, *, blocked=(), unreadable=(), **options):
        return gate.decide(FakeForgejo([state], blocked=blocked, unreadable=unreadable), own, **options)

    def wait(self, polls: list, own: int, *, unreadable=(), **options):
        api = FakeForgejo(polls, unreadable=unreadable)
        lines: list[str] = []
        clock = iter(range(0, 100_000, 20))

        def sleep(_seconds: float) -> None:
            api.poll += 1

        result = gate.wait_for_admission(api, own, sleep=sleep, clock=lambda: next(clock), log=lines.append,
                                         **options)
        return result, "\n".join(lines)

    def test_under_the_limit_a_run_starts_at_once(self) -> None:
        state = {run_id: "admitted" for run_id in range(1, 6)} | {10: "waiting"}
        self.assertEqual(self.decide(state, 10)[0], gate.ADMITTED)

    def test_at_the_limit_a_run_waits_for_one_to_end(self) -> None:
        full = {run_id: "admitted" for run_id in range(1, 7)} | {10: "waiting"}
        self.assertEqual(self.decide(full, 10)[0], gate.WAIT)
        # One admitted run ends: it leaves the unfinished list, and this one starts.
        result, log = self.wait([full, {run_id: "admitted" for run_id in range(2, 7)} | {10: "waiting"}], 10)
        self.assertEqual(result, gate.ADMITTED)
        self.assertIn("6 pull request runs admitted and 0 waiting ahead; 6 at once; waiting", log)
        self.assertIn("this run starts now", log)

    def test_runs_are_admitted_oldest_first_across_pull_requests(self) -> None:
        # Four admitted, 8 and 9 waiting before 10: 8 and 9 fill the last two
        # places, so 10 waits even though only four have started.
        state = {1: "admitted", 2: "admitted", 3: "admitted", 4: "admitted", 8: "waiting", 9: "queued",
                 10: "waiting", 11: "waiting"}
        self.assertEqual(self.decide(state, 8)[0], gate.ADMITTED)
        self.assertEqual(self.decide(state, 9)[0], gate.ADMITTED)
        self.assertEqual(self.decide(state, 10)[0], gate.WAIT)
        # A newer waiting run never counts ahead of an older one.
        self.assertEqual(self.decide({1: "admitted", 10: "waiting", 11: "waiting"}, 10)[0], gate.ADMITTED)

    def test_a_run_from_before_the_gate_counts_as_admitted(self) -> None:
        state = {run_id: "old" for run_id in range(1, 7)} | {10: "waiting"}
        self.assertEqual(self.decide(state, 10)[0], gate.WAIT)

    def test_a_cancelled_gate_neither_admits_nor_waits(self) -> None:
        state = {run_id: "admitted" for run_id in range(1, 6)} | {7: "cancelled", 10: "waiting"}
        self.assertEqual(self.decide(state, 10)[0], gate.ADMITTED)

    def test_too_many_waiting_gates_overflow_rather_than_fill_the_light_runner(self) -> None:
        # Six gates already wait ahead: a seventh would crowd the light
        # runner's 24 slots that the admitted runs need, so it starts over the limit.
        self.assertEqual(gate.WAITING_LIMIT, 6)
        state = ({run_id: "admitted" for run_id in range(1, 7)}
                 | {run_id: "waiting" for run_id in range(10, 16)} | {30: "waiting"})
        verdict, reason = self.decide(state, 30)
        self.assertEqual(verdict, gate.OVERFLOW)
        self.assertIn("6 gates already wait ahead", reason)
        result, log = self.wait([state], 30)
        self.assertEqual(result, gate.OVERFLOW)
        self.assertIn("::warning::PR admission overflow", log)
        self.assertEqual(self.decide(state, 15)[0], gate.WAIT)

    def test_one_unreadable_run_holds_a_slot_and_never_opens_the_gate(self) -> None:
        # Two gates in one run, a run deleted mid-poll: its jobs cannot be read.
        # It counts as admitted, so the cap holds for everyone else.
        full = {run_id: "admitted" for run_id in range(1, 6)} | {7: "waiting", 10: "waiting"}
        verdict, reason = self.decide(full, 10, unreadable={7})
        self.assertEqual(verdict, gate.WAIT)
        self.assertIn("1 unreadable, counted as admitted", reason)
        result, log = self.wait([full], 10, wait_seconds=300, unreadable={7})
        self.assertEqual(result, gate.DEADLINE)
        self.assertNotIn("cannot read the other pull request runs", log)
        # Under the limit it still admits.
        self.assertEqual(self.decide({1: "admitted", 7: "waiting", 10: "waiting"}, 10, unreadable={7})[0],
                         gate.ADMITTED)

    def test_a_run_awaiting_approval_holds_no_slot(self) -> None:
        # Six blocked runs (awaiting approval) ahead: none holds a slot, so a
        # newer pull request starts at once instead of waiting 230 minutes.
        state = {run_id: "queued" for run_id in range(1, 7)} | {10: "waiting"}
        self.assertEqual(self.decide(state, 10, blocked=set(range(1, 7)))[0], gate.ADMITTED)
        # Not blocked, the same six hold their places: this run is not admitted at once.
        self.assertNotEqual(self.decide(state, 10)[0], gate.ADMITTED)

    def test_the_deadline_holds_inside_a_slow_poll(self) -> None:
        # Each request takes 60 s of clock: the poll stops at the deadline
        # instead of finishing its requests past the job's timeout.
        now = [0.0]
        requests: list[str] = []

        def slow(path: str) -> None:
            requests.append(path)
            now[0] += 60

        full = {run_id: "admitted" for run_id in range(1, 7)} | {10: "waiting"}
        api = FakeForgejo([full], on_request=slow)
        lines: list[str] = []
        result = gate.wait_for_admission(api, 10, wait_seconds=150, sleep=lambda s: now.__setitem__(0, now[0] + s),
                                         clock=lambda: now[0], log=lines.append)
        self.assertEqual(result, gate.DEADLINE)
        self.assertLessEqual(now[0], 150 + 60)
        self.assertLess(len(requests), 1 + len(full))

    def test_unreadable_state_retries_then_starts(self) -> None:
        failure = gate.Unproven("forgejo-api-unavailable")
        full = {run_id: "admitted" for run_id in range(1, 7)} | {10: "waiting"}
        result, log = self.wait([failure, full, {10: "waiting"}], 10)
        self.assertEqual(result, gate.ADMITTED)
        self.assertIn("unreadable", log)
        result, log = self.wait([failure], 10)
        self.assertEqual(result, gate.UNREADABLE)
        self.assertIn(f"after {gate.UNREADABLE_LIMIT} tries; this run starts now", log)

    def test_a_wait_past_its_bound_starts_inside_the_runner_cap(self) -> None:
        self.assertLess(gate.WAIT_SECONDS, 235 * 60)
        full = {run_id: "admitted" for run_id in range(1, 7)} | {10: "waiting"}
        result, log = self.wait([full], 10, wait_seconds=300)
        self.assertEqual(result, gate.DEADLINE)
        self.assertIn("::warning::PR admission: still waiting after 300 s", log)

    def test_only_an_open_pull_request_waits(self) -> None:
        for environ in ({"GITHUB_EVENT_NAME": "push"}, {"GITHUB_EVENT_NAME": "schedule"},
                        {"GITHUB_EVENT_NAME": "pull_request", "PR_ACTION": "closed"}):
            with self.subTest(environ=environ), tempfile.NamedTemporaryFile("r") as output:
                with mock.patch.dict(os.environ, environ | {"GITHUB_OUTPUT": output.name, "GITHUB_RUN_ID": "7"},
                                     clear=True), redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.main(), 0)
                with open(output.name, encoding="utf-8") as written:
                    self.assertEqual(written.read(), "admission=not-a-pull-request\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
