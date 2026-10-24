#!/usr/bin/env python3
"""At most two Dev deliveries build at once, and none that can never sign.

Recorded-response tests of scripts/ci/deploy/cancel-superseded-deliveries.py on
a real history A-B-C, where C changes only documentation.

Old rules:
- One concurrency group cancelled the older delivery on every push, whatever
  it was, so steady merges starved Dev.
- Then a delivery was never cancelled while its own main CI could still verify
  it, however many built at once.

Rule now (owner, 2026-10-21, on infra#1594: "we need to cancel older if > 2";
owner, 2026-10-24: every green main commit newer than Dev's source is
delivered):
- This run, newer or unrelated runs and publishing runs keep building.
- The newest run whose commit main CI verified keeps building unless a newer
  commit is verified too; a newer verified commit cancels every older run.
- Then the newest runs main CI can still verify keep building, up to two; one
  cancelled beyond the two is restarted by main CI if it turns green.
- Every other older run is cancelled before it publishes, even one already
  building: one beyond the two, or one whose main CI can no longer verify it.
  A red one can still be verified by a rerun.
- Nothing unreadable cancels anything, a publishing run is never stopped, only
  Deploy Dev push runs on main are touched, and the job never fails.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/plan/tests"))
import verdict_fixtures as fx  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_cancel_superseded", ROOT / "scripts/ci/deploy/cancel-superseded-deliveries.py"
)
assert SPEC and SPEC.loader
cancel = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cancel
SPEC.loader.exec_module(cancel)

DEPLOY_LIST = (
    "/actions/runs?workflow_id=deploy-dev.yaml&status=waiting&status=blocked&status=running"
    "&status=unknown&page=1&limit=100"
)
CI_LIST_RE = re.compile(r"/actions/runs\?head_sha=([0-9a-f]{40})&workflow_id=ci\.yaml&page=1&limit=100")


def history(directory: Path) -> list[tuple[str, str]]:
    """Commits A, B and C on one line, oldest first, as (commit, tree); C changes only docs."""
    environ = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

    def run(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=directory, env=environ, check=True,
                              capture_output=True, text=True).stdout.strip()

    run("init", "-q")
    commits = []
    for name in "ABC":
        path = directory / ("docs/notes.md" if name == "C" else f"crates/{name}.rs")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{name}\n")
        run("add", "-A")
        run("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-q", "-m", name)
        commits.append((run("rev-parse", "HEAD"), run("rev-parse", "HEAD^{tree}")))
    return commits


def deploy_run(run_id: int, sha: str, **fields) -> dict:
    return fx.run(sha, run_id=run_id, workflow="deploy-dev.yaml", status="running", **fields)


def deploy_jobs(run_id: int, *, builds="running", publish="blocked") -> list[dict]:
    base = run_id * 10
    return [
        {"id": base + 1, "run_id": run_id, "name": "Deploy selection", "status": "success"},
        {"id": base + 2, "run_id": run_id, "name": "Build and push the service runtime images", "status": builds},
        {"id": base + 3, "run_id": run_id, "name": "Build and push the daemon runtime image", "status": builds},
        {"id": base + 4, "run_id": run_id, "name": "Publish the exact runtime image set", "status": publish},
    ]


class MainCI:
    """One commit's ci.yaml push run on main, in a given phase."""

    def __init__(self, run_id: int, sha: str, tree: str, phase: str):
        self.run_id, self.sha, self.tree, self.phase = run_id, sha, tree, phase

    def jobs(self) -> list[dict]:
        selection, required = {
            "queued": ("waiting", "blocked"),
            "selecting": ("running", "blocked"),
            "selection-failed": ("failure", "skipped"),
            "superseded-at-start": ("success", "blocked"),
            "verifying": ("success", "running"),
            "red": ("success", "failure"),
            "verified": ("success", "success"),
            "superseded-verdict": ("success", "success"),
        }[self.phase]
        jobs = fx.ci_jobs(self.run_id, required=required)
        jobs[0]["status"] = selection
        if self.phase in ("queued", "selecting"):
            jobs[1]["status"] = "blocked"
        return jobs

    def logs(self) -> dict[int, str]:
        selection_log = fx.log_lines("selected: policy rust")
        if self.phase == "superseded-at-start":
            selection_log = fx.log_lines(
                f"superseded by {'9' * 40}: main's queued run verifies this commit's changes")
        required_log = fx.log_lines(fx.marker(self.sha, self.tree, run_id=self.run_id))
        if self.phase == "superseded-verdict":
            required_log = fx.log_lines(f"main CI verdict: not verified; superseded by {'9' * 40}")
        return {self.run_id * 10 + 1: selection_log, fx.required_job_id(self.run_id): required_log}


class FakeForgejo:
    repository = fx.REPOSITORY

    def __init__(self, deploy_runs, deploy_jobs_by_run=None, main_ci=(), cancels=None):
        self.deploy_runs = deploy_runs
        self.jobs = dict(deploy_jobs_by_run or {})
        self.ci_runs: dict[str, list[dict]] = {}
        self.logs: dict[int, str] = {}
        for ci in main_ci:
            self.ci_runs.setdefault(ci.sha, []).append(fx.run(ci.sha, run_id=ci.run_id, status="running"))
            self.jobs[ci.run_id] = ci.jobs()
            self.logs.update(ci.logs())
        self.cancels = cancels or {}
        self.served: dict[int, int] = {}
        self.calls: list[str] = []

    def get_json(self, path: str):
        self.calls.append(f"GET {path}")
        if path == DEPLOY_LIST:
            if isinstance(self.deploy_runs, Exception):
                raise self.deploy_runs
            return {"total_count": len(self.deploy_runs), "workflow_runs": self.deploy_runs}
        match = CI_LIST_RE.fullmatch(path)
        if match:
            runs = self.ci_runs.get(match.group(1), [])
            return {"total_count": len(runs), "workflow_runs": runs}
        match = re.fullmatch(r"/actions/runs/(\d+)/jobs\?page=1&limit=100", path)
        assert match, path
        run_id = int(match.group(1))
        jobs = self.jobs[run_id]
        if isinstance(jobs, Exception):
            raise jobs
        if jobs and isinstance(jobs[0], list):
            served = self.served.get(run_id, 0)
            self.served[run_id] = served + 1
            return jobs[min(served, len(jobs) - 1)]
        return jobs

    def get_text(self, path: str) -> str:
        self.calls.append(f"GET {path}")
        match = re.fullmatch(r"/actions/jobs/(\d+)/logs", path)
        assert match, path
        return self.logs[int(match.group(1))]

    def post(self, path: str) -> int:
        self.calls.append(f"POST {path}")
        match = re.fullmatch(r"/actions/runs/(\d+)/cancel", path)
        assert match, path
        status = self.cancels.get(int(match.group(1)), 204)
        if isinstance(status, Exception):
            raise status
        return status

    def posts(self) -> list[str]:
        return [call for call in self.calls if call.startswith("POST ")]


class CancelSuperseded(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="codewire-cancel-superseded-test-")
        self.repo = Path(self.directory.name)
        (self.a, self.a_tree), (self.b, self.b_tree), (self.c, _) = history(self.repo)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def decide(self, api, head: str | None = None):
        lines: list[str] = []
        cancelled = cancel.cancel_superseded(api, self.repo, head or self.c, log=lines.append)
        return cancelled, "\n".join(lines)

    def ci_a(self, phase: str) -> MainCI:
        return MainCI(41, self.a, self.a_tree, phase)

    def ci_b(self, phase: str) -> MainCI:
        return MainCI(51, self.b, self.b_tree, phase)

    def test_three_pushes_the_verifying_delivery_completes_and_the_middle_is_cancelled(self) -> None:
        # A's main CI is verifying, B's is queued behind it, C was just pushed.
        api = FakeForgejo(
            [deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40), 50: deploy_jobs(50)},
            [self.ci_a("verifying"), self.ci_b("queued")],
        )
        cancelled, log = self.decide(api)
        self.assertEqual(cancelled, [50])
        self.assertEqual(api.posts(), ["POST /actions/runs/50/cancel"])
        self.assertIn(f"Deploy Dev run 40 for {self.a} keeps delivering", log)
        self.assertIn(f"cancelled Deploy Dev run 50 for {self.b} (it can never sign", log)
        self.assertIn("has not started; main has moved past", log)

    def test_docs_only_push_keeps_a_delivery_main_ci_can_still_verify(self) -> None:
        for phase in ("selecting", "verifying", "verified", "red", "selection-failed"):
            with self.subTest(phase):
                api = FakeForgejo([deploy_run(50, self.b)], {50: deploy_jobs(50)}, [self.ci_b(phase)])
                cancelled, log = self.decide(api)
                self.assertEqual((cancelled, api.posts()), ([], []))
                self.assertIn(f"Deploy Dev run 50 for {self.b} keeps delivering", log)

    def test_docs_only_push_cancels_a_delivery_that_can_never_sign(self) -> None:
        for phase in ("queued", "superseded-at-start", "superseded-verdict"):
            with self.subTest(phase):
                api = FakeForgejo([deploy_run(50, self.b)], {50: deploy_jobs(50)}, [self.ci_b(phase)])
                cancelled, _ = self.decide(api)
                self.assertEqual(cancelled, [50])

    # At most two deliveries build at once (owner, 2026-10-21, on infra#1594).
    def test_one_or_two_active_deliveries_all_keep_building(self) -> None:
        # Only this run.
        api = FakeForgejo([deploy_run(60, self.c)], {})
        cancelled, log = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertIn("cancelled 0 older Deploy Dev run(s)", log)
        # This run and one older delivery main CI can still verify.
        api = FakeForgejo([deploy_run(60, self.c), deploy_run(50, self.b)], {50: deploy_jobs(50)},
                          [self.ci_b("verifying")])
        cancelled, log = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertIn(f"Deploy Dev run 50 for {self.b} keeps delivering", log)

    def test_a_green_older_delivery_beats_a_newer_pending_one(self) -> None:
        # A is green and B is still being verified; C makes three. A keeps
        # building, since B may still go red, and B is the one beyond two.
        for builds in ("waiting", "running"):
            with self.subTest(builds=builds):
                api = FakeForgejo(
                    [deploy_run(60, self.c), deploy_run(50, self.b), deploy_run(40, self.a)],
                    {40: deploy_jobs(40, builds=builds), 50: deploy_jobs(50, builds=builds)},
                    [self.ci_a("verified"), self.ci_b("verifying")],
                )
                cancelled, log = self.decide(api)
                self.assertEqual(cancelled, [50])
                self.assertEqual(api.posts(), ["POST /actions/runs/50/cancel"])
                self.assertIn(f"Deploy Dev run 40 for {self.a} keeps delivering: main CI verified", log)
                self.assertIn(f"cancelled Deploy Dev run 50 for {self.b} (2 newer deliveries are building, "
                              f"and at most 2 build at once; if its main CI passes, main CI restarts it)", log)

    def test_a_green_older_delivery_is_kept_beside_a_newer_pending_one(self) -> None:
        # A is green and B, newer, is still being verified: both build.
        api = FakeForgejo(
            [deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40), 50: deploy_jobs(50)},
            [self.ci_a("verified"), self.ci_b("verifying")],
        )
        cancelled, log = self.decide(api, head=self.b)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertIn(f"Deploy Dev run 40 for {self.a} keeps delivering: main CI verified", log)

    def test_a_newer_green_commit_supersedes_an_older_green_delivery(self) -> None:
        # A and B are both green: B carries A's change, so A goes.
        api = FakeForgejo(
            [deploy_run(60, self.c), deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40), 50: deploy_jobs(50)},
            [self.ci_a("verified"), self.ci_b("verified")],
        )
        cancelled, log = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([40], ["POST /actions/runs/40/cancel"]))
        self.assertIn(f"Deploy Dev run 50 for {self.b} keeps delivering: main CI verified", log)
        self.assertIn(f"cancelled Deploy Dev run 40 for {self.a} (newer commit's main CI has passed", log)

    def test_a_green_delivery_is_not_cancelled_for_a_newer_red_one(self) -> None:
        # B went red; A stays the green delivery of record.
        api = FakeForgejo(
            [deploy_run(60, self.c), deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40), 50: deploy_jobs(50)},
            [self.ci_a("verified"), self.ci_b("red")],
        )
        cancelled, log = self.decide(api)
        self.assertEqual(cancelled, [50])
        self.assertIn(f"Deploy Dev run 40 for {self.a} keeps delivering: main CI verified", log)

    def test_a_delivery_that_can_never_sign_does_not_hold_one_of_the_two(self) -> None:
        # B can never sign, so A, which main CI is verifying, keeps the second place.
        api = FakeForgejo(
            [deploy_run(60, self.c), deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40), 50: deploy_jobs(50)},
            [self.ci_a("verifying"), self.ci_b("queued")],
        )
        cancelled, log = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([50], ["POST /actions/runs/50/cancel"]))
        self.assertIn(f"Deploy Dev run 40 for {self.a} keeps delivering", log)

    def test_a_publishing_delivery_holds_its_place_and_is_never_stopped(self) -> None:
        # B is publishing: it is never stopped, and with C it makes two, so A goes.
        api = FakeForgejo(
            [deploy_run(60, self.c), deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40), 50: deploy_jobs(50, builds="success", publish="running")},
            [self.ci_a("verified"), self.ci_b("verified")],
        )
        cancelled, _ = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([40], ["POST /actions/runs/40/cancel"]))
        # Every older run is publishing: nothing is stopped, though three run.
        api = FakeForgejo(
            [deploy_run(60, self.c), deploy_run(50, self.b), deploy_run(40, self.a)],
            {40: deploy_jobs(40, builds="success", publish="running"),
             50: deploy_jobs(50, builds="success", publish="running")},
        )
        cancelled, _ = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))

    def test_main_ci_release_dry_run_and_production_runs_are_never_cancelled(self) -> None:
        # Even if Forgejo returned them for the Deploy Dev listing, other
        # workflows' runs on main are not deliveries and are never touched.
        others = [
            fx.run(self.a, run_id=41, workflow="ci.yaml", status="running"),
            fx.run(self.a, run_id=42, workflow="cli-release.yaml", status="running",
                   event="workflow_dispatch", trigger_event="workflow_dispatch"),
            fx.run(self.a, run_id=43, workflow="cw-release-dry-run.yaml", status="running"),
            fx.run(self.a, run_id=44, workflow="deploy-prod.yaml", status="running",
                   event="workflow_dispatch", trigger_event="workflow_dispatch"),
            fx.run(self.b, run_id=45, workflow="support-images.yaml", status="running"),
        ]
        api = FakeForgejo([deploy_run(60, self.c), *others], {})
        cancelled, _ = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertEqual([call for call in api.calls if "jobs" in call], [])

    def test_a_delivery_without_a_main_ci_run_yet_is_kept(self) -> None:
        api = FakeForgejo([deploy_run(50, self.b)], {50: deploy_jobs(50)})
        cancelled, _ = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))

    def test_a_publishing_run_is_never_stopped(self) -> None:
        for name, jobs in {
            "publish running": deploy_jobs(50, builds="success", publish="running"),
            "publish finished, rerun pending": deploy_jobs(50, builds="success", publish="success"),
            "builds failed": deploy_jobs(50, builds="failure", publish="skipped"),
            "nothing selected": deploy_jobs(50, builds="skipped", publish="skipped"),
        }.items():
            with self.subTest(name):
                api = FakeForgejo([deploy_run(50, self.b)], {50: jobs}, [self.ci_b("queued")])
                cancelled, _ = self.decide(api)
                self.assertEqual((cancelled, api.posts()), ([], []))

    def test_publication_that_starts_while_deciding_is_not_cancelled(self) -> None:
        api = FakeForgejo(
            [deploy_run(50, self.b)],
            {50: [deploy_jobs(50, builds="success"), deploy_jobs(50, builds="success", publish="running")]},
            [self.ci_b("queued")],
        )
        cancelled, log = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertIn("started publishing; it is left to finish", log)

    def test_only_proper_ancestors_on_main_push_runs_are_considered(self) -> None:
        api = FakeForgejo(
            [
                deploy_run(51, self.c),                                 # this commit's own run
                deploy_run(53, "4" * 40),                               # not in this history
                deploy_run(54, self.a, event="workflow_dispatch", trigger_event="workflow_dispatch"),
                deploy_run(55, self.a, prettyref="feature"),
                deploy_run(56, self.a, trigger_event="schedule"),
            ],
            {},
            [self.ci_a("queued")],
        )
        cancelled, _ = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertEqual([call for call in api.calls if "jobs" in call], [])

    def test_a_newer_commit_is_never_cancelled_by_an_older_one(self) -> None:
        api = FakeForgejo([deploy_run(60, self.c)], {60: deploy_jobs(60)})
        cancelled, _ = self.decide(api, head=self.b)
        self.assertEqual((cancelled, api.posts()), ([], []))

    def test_unreadable_records_cancel_nothing_and_later_runs_still_decide(self) -> None:
        api = FakeForgejo(cancel.Unproven("forgejo-api-unavailable"))
        cancelled, log = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))
        self.assertIn("cannot list unfinished Deploy Dev runs", log)

        # A's jobs are unreadable; B, after it, is still decided and cancelled.
        api = FakeForgejo(
            [deploy_run(40, self.a), deploy_run(50, self.b)],
            {40: cancel.Unproven("forgejo-api-unavailable"), 50: deploy_jobs(50)},
            [self.ci_a("queued"), self.ci_b("queued")],
        )
        cancelled, log = self.decide(api)
        self.assertEqual(cancelled, [50])
        self.assertIn("cannot read Deploy Dev run 40 or its main CI", log)

        # Main CI's jobs are ambiguous: keep the delivery.
        ci = self.ci_b("queued")
        api = FakeForgejo([deploy_run(50, self.b)], {50: deploy_jobs(50)}, [ci])
        api.jobs[ci.run_id] = ci.jobs()[:2]
        cancelled, _ = self.decide(api)
        self.assertEqual((cancelled, api.posts()), ([], []))

    def test_a_refused_or_failed_cancel_is_reported_and_the_next_run_still_decides(self) -> None:
        api = FakeForgejo(
            [deploy_run(40, self.a), deploy_run(50, self.b)],
            {40: deploy_jobs(40), 50: deploy_jobs(50)},
            [self.ci_a("queued"), self.ci_b("queued")],
            cancels={40: cancel.Unproven("forgejo-api-unavailable"), 50: 403},
        )
        cancelled, log = self.decide(api)
        self.assertEqual(cancelled, [])
        self.assertEqual(api.posts(), ["POST /actions/runs/50/cancel", "POST /actions/runs/40/cancel"])
        self.assertIn("Forgejo refused to cancel Deploy Dev run 50", log)
        self.assertIn("cancelled 0 older Deploy Dev run(s)", log)

    def test_main_ci_still_names_its_selection_job_and_superseded_line(self) -> None:
        workflow = (ROOT / ".gitea/workflows/ci.yaml").read_text()
        self.assertIn(f"    name: {cancel.CI_SELECTION_JOB}\n", workflow)
        message = re.search(r'message="(superseded by \$\{canonical_main_sha\}[^"]*)"', workflow)
        self.assertIsNotNone(message, "ci.yaml no longer prints the superseded line")
        self.assertRegex(message.group(1).replace("${canonical_main_sha}", "9" * 40), cancel.CI_SUPERSEDED_RE)

    def test_main_never_fails_its_job_and_drops_the_oidc_request(self) -> None:
        for environ in (
            {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REF": "refs/pull/1/head"},
            {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "x"},
            {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": self.c},
        ):
            environ = {**environ, "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t" * 40,
                       "ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.invalid/token"}
            with self.subTest(environ), mock.patch.dict(os.environ, environ, clear=True), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cancel.main(), 0)
                self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", os.environ)
                self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_URL", os.environ)


if __name__ == "__main__":
    unittest.main(verbosity=1)
