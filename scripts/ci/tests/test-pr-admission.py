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
# Since codewire#5146 the gate is the selection job's first step: the job, then
# the gate step, for each state; "old" is a selection job without the step.
IN_SELECTION = {"admitted": ("running", "success"), "waiting": ("running", "running"),
                "queued": ("waiting", None), "cancelled": ("cancelled", None), "old": ("running", None)}
# Job 394125's steps (run 56647's Verification selection, before the gate
# moved into it), as /actions/jobs/394125 gave them while the job ran on
# 2026-11-16: a step that has not started is "waiting", with no times.
RUNNING_SELECTION_STEPS = [
    {"number": 0, "name": "Set up job", "status": "success",
     "started": "2026-11-16T20:27:41Z", "stopped": "2026-11-16T20:28:15Z"},
    {"number": 1, "name": "noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "status": "success",
     "started": "2026-11-16T20:28:15Z", "stopped": "2026-11-16T20:28:38Z"},
    {"number": 2, "name": "Choose the commit this run verifies", "status": "success",
     "started": "2026-11-16T20:28:38Z", "stopped": "2026-11-16T20:28:39Z"},
    {"number": 9, "name": "Select capabilities and artifact facts", "status": "success",
     "started": "2026-11-16T20:28:52Z", "stopped": "2026-11-16T20:29:25Z"},
    {"number": 12, "name": "Choose the Kind workspace image source", "status": "running",
     "started": "2026-11-16T20:29:33Z", "stopped": None},
    {"number": 13, "name": "Emit trusted capability dispatch decisions", "status": "waiting",
     "started": None, "stopped": None},
    {"number": 14, "name": "Complete job", "status": "waiting", "started": None, "stopped": None},
]


def selection_steps(gate: str | None) -> list[dict]:
    """A running selection job's steps in the recorded form, its gate step GATE."""
    if gate is None:
        return RUNNING_SELECTION_STEPS
    done = gate == "success"
    return [
        {"number": 0, "name": "Set up job", "status": "success",
         "started": "2026-11-16T20:27:41Z", "stopped": "2026-11-16T20:28:15Z"},
        {"number": 1, "name": "noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "status": "success",
         "started": "2026-11-16T20:28:15Z", "stopped": "2026-11-16T20:28:16Z"},
        {"number": 2, "name": gate_module_step(), "status": gate,
         "started": None if gate == "waiting" else "2026-11-16T20:28:16Z",
         "stopped": "2026-11-16T20:40:00Z" if done else None},
        {"number": 3, "name": "noel/actions-checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
         "status": "running" if done else "waiting", "started": "2026-11-16T20:40:00Z" if done else None,
         "stopped": None},
        {"number": 4, "name": "Complete job", "status": "waiting", "started": None, "stopped": None},
    ]


def gate_module_step() -> str:
    return gate.GATE_STEP


class FakeForgejo:
    """Unfinished ci.yaml runs whose gates change from one poll to the next."""

    repository = fx.REPOSITORY

    def __init__(self, polls, *, blocked=(), unreadable=(), on_request=None, shape="job", job_shaped=()):
        # Each poll: {run_id: gate} (gate a GATE key or "old") or an exception.
        # blocked: runs whose status is blocked (awaiting approval); unreadable:
        # runs whose jobs cannot be read; on_request: called on every request.
        # shape: "job", the gate a job of its own, or "step", the selection
        # job's first step; job_shaped: runs that keep the gate job either way.
        self.polls = polls
        self.poll = 0
        self.blocked = set(blocked)
        self.unreadable = set(unreadable)
        self.on_request = on_request
        self.shape = shape
        self.job_shaped = set(job_shaped)
        self.step_reads: list[int] = []

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
        if path.startswith("/actions/jobs/"):
            run_id = int(path.rsplit("/", 1)[1]) // 10
            self.step_reads.append(run_id)
            job, step = IN_SELECTION[self.state()[run_id]]
            # Only a running selection job's steps are ever read.
            assert job == "running", (run_id, job)
            return {"id": run_id * 10 + 1, "run_id": run_id, "name": "Verification selection", "status": job,
                    "steps": selection_steps(step)}
        run_id = int(path.split("/")[3])
        if run_id in self.unreadable:
            raise gate.Unproven("jobs-ambiguous")
        state = self.state()[run_id]
        if self.shape == "step" and run_id not in self.job_shaped:
            jobs = [{"id": run_id * 10 + 1, "run_id": run_id, "name": "Verification selection",
                     "status": IN_SELECTION[state][0]}]
            return {"total_count": len(jobs), "jobs": jobs}
        jobs = [{"id": run_id * 10 + 1, "run_id": run_id, "name": "Verification selection", "status": "blocked"}]
        if state != "old":
            jobs.append({"id": run_id * 10, "run_id": run_id, "name": "PR admission", "status": GATE[state]})
        return {"total_count": len(jobs), "jobs": jobs}


class PrAdmission(unittest.TestCase):
    """Every case reads runs whose gate is the "PR admission" job."""

    SHAPE = "job"

    def decide(self, state: dict, own: int, *, blocked=(), unreadable=(), **options):
        return gate.decide(FakeForgejo([state], blocked=blocked, unreadable=unreadable, shape=self.SHAPE),
                           own, **options)

    def wait(self, polls: list, own: int, *, unreadable=(), **options):
        api = FakeForgejo(polls, unreadable=unreadable, shape=self.SHAPE)
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
        self.assertRegex(log, r"PR admission: \d+ Forgejo reads$")

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

    def test_at_most_two_gates_hold_a_light_runner_slot(self) -> None:
        # Seven gates held slots and polled for a median 2,875 s on 2026-11-16
        # while the light runner's real jobs queued: now two wait, and the
        # oldest of any more start over the limit.
        self.assertEqual(gate.WAITING_LIMIT, 2)
        state = ({run_id: "admitted" for run_id in range(1, 7)}
                 | {10: "waiting", 11: "waiting", 12: "waiting"})
        self.assertEqual(self.decide(state, 10)[0], gate.OVERFLOW)
        self.assertEqual([self.decide(state, run_id)[0] for run_id in (11, 12)], [gate.WAIT, gate.WAIT])

    @mock.patch.object(gate, "WAITING_LIMIT", 6)
    def test_too_many_waiting_gates_overflow_rather_than_fill_the_light_runner(self) -> None:
        # Seven gates wait: one more than the light runner holds beside the
        # admitted runs' jobs, so one starts over the limit. It is the oldest:
        # letting the newest in made the first six wait while later pushes
        # passed them (2026-11-15: two hours, 12 runs admitted). The cases
        # read with the limit at its earlier 6, which they were written for.
        self.assertEqual(gate.WAITING_LIMIT, 6)
        state = ({run_id: "admitted" for run_id in range(1, 7)}
                 | {run_id: "waiting" for run_id in range(10, 16)} | {30: "waiting"})
        verdict, reason = self.decide(state, 10)
        self.assertEqual(verdict, gate.OVERFLOW)
        self.assertIn("7 gates hold a light runner slot and it keeps 6", reason)
        result, log = self.wait([state], 10)
        self.assertEqual(result, gate.OVERFLOW)
        self.assertIn("::warning::PR admission overflow", log)
        for later in (11, 15, 30):
            self.assertEqual(self.decide(state, later)[0], gate.WAIT, later)
        # Nine hold a slot: the three oldest start, and exactly six stay.
        nine = state | {31: "waiting", 32: "waiting"}
        verdicts_by_run = {run_id: self.decide(nine, run_id)[0] for run_id in nine if run_id >= 10}
        self.assertEqual([run_id for run_id, verdict in verdicts_by_run.items() if verdict == gate.OVERFLOW],
                         [10, 11, 12])
        self.assertEqual(sum(verdict == gate.WAIT for verdict in verdicts_by_run.values()), 6)
        # A gate still queued for a runner holds no slot, so it never causes
        # an overflow: three running gates wait with ten more queued behind
        # them (2026-11-15: 11 of 16 waiting gates had not started, and
        # counting them would have admitted ten more runs).
        queued = ({run_id: "admitted" for run_id in range(1, 7)}
                  | {10: "waiting", 11: "waiting", 12: "waiting"}
                  | {run_id: "queued" for run_id in range(20, 30)})
        for running in (10, 11, 12):
            self.assertEqual(self.decide(queued, running)[0], gate.WAIT, running)
        # It still keeps its place in line: a running gate does not start
        # ahead of an older one that is only queued.
        self.assertEqual(self.decide({1: "admitted", 2: "admitted", 3: "admitted", 4: "admitted", 5: "admitted",
                                      8: "queued", 10: "waiting"}, 10)[0], gate.WAIT)
        # The newest arrival waits its turn once an older gate has started.
        self.assertEqual(self.wait([state, {run_id: gate_state for run_id, gate_state in state.items()
                                            if run_id != 10} | {10: "admitted"}], 30,
                                   wait_seconds=60)[0], gate.DEADLINE)
        # A gate that never leaves (its runner died) costs one place, not the
        # release: with 10 stuck among seven, 11 waits, and starts when an
        # eighth arrives.
        self.assertEqual(self.decide(state, 11)[0], gate.WAIT)
        self.assertEqual(self.decide(state | {31: "waiting"}, 11)[0], gate.OVERFLOW)

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
        api = FakeForgejo([full], on_request=slow, shape=self.SHAPE)
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
        # Selection's own 25 minutes follow the wait inside its job's 235.
        self.assertLessEqual(gate.WAIT_SECONDS + 25 * 60, 235 * 60)
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


class PrAdmissionInSelection(PrAdmission):
    """The same cases, with the gate the selection job's first step (codewire#5146)."""

    SHAPE = "step"

    def test_the_gate_step_is_read_only_while_it_can_still_wait(self) -> None:
        # A queued job's gate has not started and an ended one's has ended:
        # neither is read. An admitted gate never waits again, so a later poll
        # does not read it.
        state = ({1: "admitted", 2: "admitted", 3: "queued", 4: "cancelled", 5: "waiting", 6: "old"}
                 | {10: "waiting"})
        api = FakeForgejo([state], shape="step")
        admitted: set[int] = set()
        gate.decide(api, 10, admitted_runs=admitted)
        self.assertEqual(sorted(api.step_reads), [1, 2, 5, 6])
        self.assertEqual(admitted, {1, 2})
        api.step_reads.clear()
        gate.decide(api, 10, admitted_runs=admitted)
        self.assertEqual(sorted(api.step_reads), [5, 6])

    def test_runs_of_both_shapes_share_one_line(self) -> None:
        # While pull requests move to the new workflow, runs whose gate is a
        # job and runs whose gate is a step are counted together.
        state = {1: "admitted", 2: "admitted", 3: "admitted", 4: "admitted", 5: "admitted", 8: "waiting",
                 9: "waiting", 10: "waiting"}
        for job_shaped in ({1, 2, 3}, {4, 5, 8}, {9}):
            with self.subTest(job_shaped=job_shaped):
                api = FakeForgejo([state], shape="step", job_shaped=job_shaped)
                self.assertEqual(gate.decide(api, 8)[0], gate.ADMITTED)
                self.assertEqual(gate.decide(api, 9)[0], gate.WAIT)

    def test_the_recorded_running_job_reads_as_from_before_the_gate(self) -> None:
        # Job 394125's record, without a gate step: it counts as admitted.
        api = FakeForgejo([{1: "old", 10: "waiting"}], shape="step")
        jobs = api.get_json("/actions/runs/1/jobs?page=1&limit=100")["jobs"]
        self.assertIsNone(gate.gate_state(api, jobs, 1, set()))
        # A gate step that has not started yet ("waiting", no times) holds the
        # job's slot as a waiting gate does.
        steps = selection_steps("waiting")
        self.assertEqual((steps[2]["name"], steps[2]["started"]), (gate.GATE_STEP, None))
        holding = FakeForgejo([{1: "waiting"}], shape="step")
        holding.get_json = lambda path: ({"jobs": [{"id": 11, "run_id": 1, "name": gate.SELECTION_JOB,
                                                    "status": "running"}]}
                                         if "/runs/" in path else {"steps": steps})
        self.assertEqual(gate.gate_state(holding, holding.get_json("/actions/runs/1/jobs")["jobs"], 1, set()),
                         "running")
        # A job that has just started lists no steps yet: its gate is next.
        holding.get_json = lambda path: ({"jobs": [{"id": 11, "run_id": 1, "name": gate.SELECTION_JOB,
                                                    "status": "running"}]}
                                         if "/runs/" in path else {"steps": []})
        self.assertEqual(gate.gate_state(holding, holding.get_json("/actions/runs/1/jobs")["jobs"], 1, set()),
                         "running")


if __name__ == "__main__":
    unittest.main(verbosity=2)
