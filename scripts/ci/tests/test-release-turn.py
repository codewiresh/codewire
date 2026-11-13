#!/usr/bin/env python3
"""One release delivery at a time per workflow, without a queue of no-op runs.

Recorded-response tests of scripts/ci/release/release-turn.py.

Plan (owner, 2026-11-12, recorded on #3013): a scheduled deploy-prod or
cli-release run that finds another run of its workflow looking or delivering
ends at once without delivering; a dispatched run waits its turn and always
delivers; nothing running is cancelled. Unreadable run state makes a scheduled
run skip and a dispatch fail with the reason.

Old behaviour: one workflow-level concurrency group, in which Forgejo queued
every scheduled run behind the running one. A cli-release run that found
nothing took about 20 minutes to settle its skipped jobs on 2026-11-12, and
four runs waited behind it (ForgejoCiJobWaitingTooLong).
"""

from __future__ import annotations

import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("codewire_ci_release_turn", ROOT / "scripts/ci/release/release-turn.py")
assert SPEC and SPEC.loader
turn = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = turn
SPEC.loader.exec_module(turn)

OWN = 500
SELECTION = {"deploy-prod": "Verify canonical release tag", "cli-release": "Verify canonical CLI release tag"}

# A run's jobs in each phase: the first job, its release selection, and the
# delivery after it. Forgejo settles a run that found nothing slowly: its
# selection is skipped at once, its later jobs stay blocked for minutes.
PHASES = {
    "queued": ("waiting", "blocked", "blocked"),
    "looking": ("running", "blocked", "blocked"),
    "settling-no-op": ("success", "skipped", "blocked"),
    "selection-pending": ("success", "blocked", "blocked"),
    "verifying": ("success", "running", "blocked"),
    "publishing": ("success", "success", "running"),
    "find-failed": ("failure", "skipped", "blocked"),
    "selection-failed": ("success", "failure", "blocked"),
}


def list_path(workflow: str) -> str:
    return (f"/actions/runs?workflow_id={workflow}.yaml&status=waiting&status=blocked&status=running"
            f"&status=unknown&page=1&limit=100")


def release_run(workflow: str, run_id: int, *, ref: str = "main") -> dict:
    return {"id": run_id, "workflow_id": f"{workflow}.yaml", "prettyref": ref, "event": "schedule",
            "status": "running", "path": f"{workflow}.yaml@refs/heads/{ref}"}


def release_jobs(workflow: str, run_id: int, phase: str) -> list[dict]:
    find, selection, delivery = PHASES[phase]
    base = run_id * 10
    return [
        {"id": base + 1, "run_id": run_id, "name": "Find the release to deliver", "status": find},
        {"id": base + 2, "run_id": run_id, "name": SELECTION[workflow], "status": selection},
        {"id": base + 3, "run_id": run_id, "name": "Publish the release", "status": delivery},
    ]


class FakeForgejo:
    """Release runs whose phases change from one poll to the next."""

    def __init__(self, workflow: str, polls):
        # Each poll: {run_id: phase} (or (phase, ref)), or an exception.
        self.workflow = workflow
        self.polls = polls
        self.poll = 0
        self.calls: list[str] = []

    def state(self):
        state = self.polls[min(self.poll, len(self.polls) - 1)]
        if isinstance(state, Exception):
            raise state
        return state

    def get_json(self, path: str):
        self.calls.append(path)
        if path == list_path(self.workflow):
            runs = []
            for run_id, phase in sorted(self.state().items()):
                ref = phase[1] if isinstance(phase, tuple) else "main"
                runs.append(release_run(self.workflow, run_id, ref=ref))
            return {"total_count": len(runs), "workflow_runs": runs}
        match = re.fullmatch(r"/actions/runs/(\d+)/jobs\?page=1&limit=100", path)
        assert match, path
        phase = self.state()[int(match.group(1))]
        phase = phase[0] if isinstance(phase, tuple) else phase
        jobs = release_jobs(self.workflow, int(match.group(1)), phase)
        return {"total_count": len(jobs), "jobs": jobs}

    def post(self, path: str) -> int:  # pragma: no cover - the turn never acts on a run
        raise AssertionError(f"the release turn must never act on a run: {path}")


def scheduled(workflow: str, state) -> tuple[str, list[str]]:
    lines: list[str] = []
    verdict = turn.scheduled_turn(FakeForgejo(workflow, [state]), workflow, OWN, log=lines.append)
    return verdict, lines


class ScheduledTurn(unittest.TestCase):
    def test_alone_it_looks(self) -> None:
        self.assertEqual(scheduled("deploy-prod", {OWN: "looking"})[0], turn.GO)

    def test_an_older_run_still_looking_makes_it_skip(self) -> None:
        verdict, lines = scheduled("deploy-prod", {OWN - 5: "looking", OWN: "looking"})
        self.assertEqual(verdict, turn.SKIP)
        self.assertIn(f"run {OWN - 5} started first", lines[-1])
        # Waiting for a runner is still looking.
        self.assertEqual(scheduled("deploy-prod", {OWN - 5: "queued", OWN: "looking"})[0], turn.SKIP)

    def test_a_newer_run_still_looking_does_not(self) -> None:
        # Two runs looking at once: the lower ID goes first, the higher skips.
        self.assertEqual(scheduled("deploy-prod", {OWN: "looking", OWN + 5: "looking"})[0], turn.GO)

    def test_of_two_runs_started_in_the_same_second_exactly_one_looks(self) -> None:
        # Without a concurrency group two schedules can start together; each
        # sees the other, still queued or looking, and only the lower ID goes.
        for first, second in (("looking", "looking"), ("queued", "looking"), ("looking", "queued")):
            with self.subTest(phases=(first, second)):
                state = {OWN: first, OWN + 1: second}
                verdicts = [turn.scheduled_turn(FakeForgejo("deploy-prod", [state]), "deploy-prod", run_id,
                                                log=lambda _: None) for run_id in (OWN, OWN + 1)]
                self.assertEqual(verdicts, [turn.GO, turn.SKIP])

    def test_a_delivering_run_still_verifying_makes_it_skip(self) -> None:
        for phase in ("selection-pending", "verifying", "publishing"):
            with self.subTest(phase=phase):
                verdict, lines = scheduled("deploy-prod", {OWN - 5: phase, OWN: "looking"})
                self.assertEqual(verdict, turn.SKIP)
                self.assertIn(f"run {OWN - 5} is delivering", lines[-1])

    def test_a_rerun_of_an_older_run_waits_for_a_newer_delivery(self) -> None:
        # A whole-run rerun keeps its lower ID; the newer run is already delivering.
        self.assertEqual(scheduled("deploy-prod", {OWN: "looking", OWN + 5: "publishing"})[0], turn.SKIP)

    def test_a_chain_of_settling_no_op_runs_never_starves_it(self) -> None:
        # Each run found nothing; Forgejo is still settling their skipped jobs.
        chain = {OWN - 20: "settling-no-op", OWN - 15: "settling-no-op", OWN - 10: "settling-no-op",
                 OWN - 5: "settling-no-op", OWN: "looking"}
        self.assertEqual(scheduled("deploy-prod", chain)[0], turn.GO)
        # And the next schedule, while this one settles too, still looks.
        chain = {**chain, OWN: "settling-no-op", OWN + 5: "looking"}
        self.assertEqual(turn.scheduled_turn(FakeForgejo("deploy-prod", [chain]), "deploy-prod", OWN + 5,
                                             log=lambda _: None), turn.GO)

    def test_a_run_that_failed_before_delivering_is_not_ahead(self) -> None:
        for phase in ("find-failed", "selection-failed"):
            with self.subTest(phase=phase):
                self.assertEqual(scheduled("deploy-prod", {OWN - 5: phase, OWN: "looking"})[0], turn.GO)

    def test_runs_of_another_ref_are_ignored(self) -> None:
        self.assertEqual(scheduled("deploy-prod", {OWN - 5: ("publishing", "other"), OWN: "looking"})[0], turn.GO)

    def test_cli_release_reads_its_own_selection_job(self) -> None:
        self.assertEqual(scheduled("cli-release", {OWN - 5: "verifying", OWN: "looking"})[0], turn.SKIP)
        self.assertEqual(scheduled("cli-release", {OWN - 5: "settling-no-op", OWN: "looking"})[0], turn.GO)

    def test_unreadable_runs_make_it_skip(self) -> None:
        verdict, lines = scheduled("deploy-prod", turn.Unproven("forgejo-api-unavailable"))
        self.assertEqual(verdict, turn.SKIP)
        self.assertIn("unreadable", lines[-1])
        # A run whose jobs cannot be told apart is unreadable too.
        api = FakeForgejo("deploy-prod", [{OWN - 5: "publishing", OWN: "looking"}])
        api.get_json = mock.Mock(side_effect=[
            {"total_count": 2, "workflow_runs": [release_run("deploy-prod", OWN - 5), release_run("deploy-prod", OWN)]},
            {"total_count": 0, "jobs": [{"id": 1, "run_id": OWN - 5, "name": "Find the release to deliver",
                                         "status": "success"}] * 2},
        ])
        self.assertEqual(turn.scheduled_turn(api, "deploy-prod", OWN, log=lambda _: None), turn.SKIP)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def dispatched(api: FakeForgejo, clock: Clock, **kwargs) -> tuple[str, list[str]]:
    lines: list[str] = []

    def sleep(seconds: float) -> None:
        clock.sleep(seconds)
        api.poll += 1

    verdict = turn.dispatched_turn(api, api.workflow, OWN, sleep=sleep, clock=lambda: clock.now,
                                   log=lines.append, **kwargs)
    return verdict, lines


class DispatchedTurn(unittest.TestCase):
    def test_it_waits_for_the_delivery_in_flight_then_delivers(self) -> None:
        # The run delivering is a scheduled one (release_run's event).
        api = FakeForgejo("deploy-prod", [
            {OWN - 5: "verifying", OWN: "looking"},
            {OWN - 5: "publishing", OWN: "looking"},
            {OWN: "looking"},
        ])
        clock = Clock()
        verdict, lines = dispatched(api, clock)
        self.assertEqual(verdict, turn.GO)
        self.assertEqual(clock.sleeps, [turn.POLL_SECONDS, turn.POLL_SECONDS])
        self.assertIn("waits its turn", lines[0])
        self.assertIn("delivers now", lines[-1])

    def test_a_settling_no_op_run_does_not_hold_it(self) -> None:
        clock = Clock()
        verdict, _ = dispatched(FakeForgejo("cli-release", [{OWN - 5: "settling-no-op", OWN: "looking"}]), clock)
        self.assertEqual(verdict, turn.GO)
        self.assertEqual(clock.sleeps, [])

    def test_it_fails_past_its_bound_and_names_the_run(self) -> None:
        clock = Clock()
        with self.assertRaises(turn.Failed) as raised:
            dispatched(FakeForgejo("deploy-prod", [{OWN - 5: "publishing", OWN: "looking"}]), clock, wait_seconds=90)
        self.assertIn(f"run {OWN - 5} is delivering", str(raised.exception))
        self.assertIn("dispatch this release again", str(raised.exception))
        self.assertEqual(clock.now, 90)

    def test_brief_unreadable_state_is_retried(self) -> None:
        unreadable = turn.Unproven("forgejo-api-unavailable")
        clock = Clock()
        verdict, _ = dispatched(FakeForgejo("deploy-prod", [unreadable, unreadable, {OWN: "looking"}]), clock)
        self.assertEqual(verdict, turn.GO)

    def test_lasting_unreadable_state_fails_clearly(self) -> None:
        clock = Clock()
        with self.assertRaises(turn.Failed) as raised:
            dispatched(FakeForgejo("deploy-prod", [turn.Unproven("forgejo-api-unavailable")]), clock)
        self.assertIn("unreadable", str(raised.exception))
        self.assertEqual(len(clock.sleeps), turn.UNREADABLE_LIMIT - 1)


class Main(unittest.TestCase):
    def run_main(self, args: list[str], **environ: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory(prefix="codewire-release-turn-test-") as directory:
            output = Path(directory) / "output"
            output.touch()
            env = {"GITHUB_OUTPUT": str(output), **environ}
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(stdout):
                code = turn.main(["release-turn.py", *args])
            return code, output.read_text(), stdout.getvalue()

    def test_usage_and_events(self) -> None:
        self.assertEqual(self.run_main(["other"])[0], 2)
        code, written, out = self.run_main(["deploy-prod"], GITHUB_EVENT_NAME="push", GITHUB_RUN_ID="7")
        self.assertEqual((code, written), (1, ""))
        self.assertIn("unsupported event", out)

    def test_without_a_token_a_schedule_skips_and_a_dispatch_fails(self) -> None:
        base = {"GITHUB_RUN_ID": "7", "GITHUB_SERVER_URL": "https://git.example.invalid",
                "GITHUB_REPOSITORY": "codewire/codewire"}
        code, written, _ = self.run_main(["deploy-prod"], GITHUB_EVENT_NAME="schedule", **base)
        self.assertEqual((code, written), (0, "turn=skip\n"))
        code, written, out = self.run_main(["cli-release"], GITHUB_EVENT_NAME="workflow_dispatch", **base)
        self.assertEqual((code, written), (1, ""))
        self.assertIn("::error::", out)

    def test_it_writes_the_turn(self) -> None:
        api = FakeForgejo("deploy-prod", [{OWN - 5: "publishing", 7: "looking"}])
        with mock.patch.object(turn.verdicts.ForgejoAPI, "from_environ", return_value=api):
            code, written, _ = self.run_main(["deploy-prod"], GITHUB_EVENT_NAME="schedule", GITHUB_RUN_ID=str(OWN))
        self.assertEqual((code, written), (0, "turn=skip\n"))
        api = FakeForgejo("deploy-prod", [{OWN: "looking"}])
        with mock.patch.object(turn.verdicts.ForgejoAPI, "from_environ", return_value=api):
            code, written, _ = self.run_main(["deploy-prod"], GITHUB_EVENT_NAME="workflow_dispatch",
                                             GITHUB_RUN_ID=str(OWN))
        self.assertEqual((code, written), (0, "turn=go\n"))


def forgejo_concurrency(block, event: str) -> str:
    """How Forgejo 17.0.0 runs a workflow with this `concurrency` value.

    A port of ConfigureActionRunConcurrency (services/actions/workflows.go) and
    runner v13.2.0's EvaluateWorkflowConcurrency. A scheduled run's event is the
    push that registered its schedule, so `event` is "push" for a tick. A
    cancelling run kills every earlier run of its group that still has a job
    waiting, blocked or running (CancelPreviousWithConcurrencyGroup).
    """
    group, cancel = "", None
    if isinstance(block, str):
        group = block
    elif isinstance(block, dict):
        group = str(block.get("group") or "")
        if "cancel-in-progress" in block:
            cancel = str(block["cancel-in-progress"]).lower() == "true"
    if cancel is None:
        return "cancel" if event in ("push", "pull_request_sync") else "unlimited"
    if cancel:
        return "cancel"
    return "unlimited" if group == "" else "queue"


class Workflows(unittest.TestCase):
    """Both release workflows take the turn before they look; Forgejo neither queues nor cancels them."""

    def test_the_concurrency_model_matches_what_was_observed(self) -> None:
        # No block: each tick cancelled the scheduled run before it (cli-release 46578).
        self.assertEqual(forgejo_concurrency(None, "push"), "cancel")
        # A group whose run_id is empty at evaluation: every run queued (#4261).
        self.assertEqual(forgejo_concurrency({"group": "cli-release-", "cancel-in-progress": False}, "push"), "queue")
        self.assertEqual(forgejo_concurrency({"cancel-in-progress": True}, "workflow_dispatch"), "cancel")
        # An empty group is no group (the workflow schema requires the key).
        self.assertEqual(forgejo_concurrency({"group": "", "cancel-in-progress": False}, "push"), "unlimited")

    def test_no_run_queues_or_is_cancelled(self) -> None:
        for workflow in ("deploy-prod", "cli-release"):
            for event in ("push", "workflow_dispatch"):
                with self.subTest(workflow=workflow, event=event):
                    document = yaml.safe_load((ROOT / f".gitea/workflows/{workflow}.yaml").read_text())
                    self.assertEqual(forgejo_concurrency(document.get("concurrency"), event), "unlimited")

    def test_each_workflow_takes_the_turn(self) -> None:
        for workflow in ("deploy-prod", "cli-release"):
            with self.subTest(workflow=workflow):
                text = (ROOT / f".gitea/workflows/{workflow}.yaml").read_text()
                steps = text.split("      - name: Take this run's release turn\n", 1)
                self.assertEqual(len(steps), 2)
                self.assertTrue(steps[1].startswith(
                    "        id: turn\n        env:\n          GITEA_TOKEN: ${{ github.token }}\n"
                    f"        run: python3 -I -B scripts/ci/release/release-turn.py {workflow}\n\n"
                    "      - name: Find the pending release\n"
                    "        if: ${{ steps.turn.outputs.turn == 'go' }}\n        id: find\n"))
                self.assertNotIn("cancel-in-progress: true", text)


if __name__ == "__main__":
    unittest.main()
