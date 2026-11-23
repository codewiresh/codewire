#!/usr/bin/env python3
"""At most one standard pod-runtime image build at a time (#5602).

Recorded-response tests of scripts/ci/deploy/pod-runtime-build-in-flight.py:
another Deploy Dev run's running pod-runtime build skips this one; a finished,
cancelled, skipped, waiting or missing one does not; and anything unreadable
builds (it fails open).
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

SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_pod_runtime_build_in_flight", ROOT / "scripts/ci/deploy/pod-runtime-build-in-flight.py"
)
assert SPEC and SPEC.loader
check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check
SPEC.loader.exec_module(check)

DEPLOY_LIST = (
    "/actions/runs?workflow_id=deploy-dev.yaml&status=waiting&status=blocked&status=running"
    "&status=unknown&page=1&limit=100"
)
OWN = 50
SHA = "a" * 40


def jobs(run_id: int, build: str | None) -> list[dict]:
    base = run_id * 10
    listed = [{"id": base + 1, "run_id": run_id, "name": "Deploy selection", "status": "success"}]
    if build is not None:
        listed.append({"id": base + 2, "run_id": run_id, "name": check.BUILD_JOB, "status": build})
    return listed


class FakeForgejo:
    """Deploy Dev's unfinished runs and each one's pod-runtime build state."""

    repository = fx.REPOSITORY

    def __init__(self, builds: dict[int, str | None], runs_error: Exception | None = None,
                 jobs_error: Exception | None = None):
        self.builds = builds
        self.runs_error = runs_error
        self.jobs_error = jobs_error
        self.paths: list[str] = []

    def get_json(self, path: str):
        self.paths.append(path)
        if path == DEPLOY_LIST:
            if self.runs_error:
                raise self.runs_error
            runs = [fx.run(SHA, run_id=run_id, workflow="deploy-dev.yaml", status="running")
                    for run_id in self.builds]
            return {"total_count": len(runs), "workflow_runs": runs}
        if self.jobs_error:
            raise self.jobs_error
        prefix, _, suffix = path.partition("/jobs?")
        assert suffix == "page=1&limit=100", path
        run_id = int(prefix.rsplit("/", 1)[1])
        return jobs(run_id, self.builds[run_id])


class InFlight(unittest.TestCase):
    def decide(self, api: FakeForgejo) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            environ = {"GITHUB_RUN_ID": str(OWN), "GITHUB_OUTPUT": str(output),
                       "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic"}
            printed = io.StringIO()
            with mock.patch.dict(os.environ, environ, clear=True), redirect_stdout(printed):
                self.assertEqual(check.main([], api_factory=lambda _environ: api), 0)
                self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", os.environ)
            return output.read_text(), printed.getvalue()

    def test_another_runs_running_build_skips_this_one(self):
        output, printed = self.decide(FakeForgejo({OWN: "running", 49: "running"}))
        self.assertEqual(output, "in_flight=true\n")
        self.assertIn("Deploy Dev run 49 is building", printed)

    def test_a_finished_cancelled_skipped_waiting_or_missing_build_does_not(self):
        for state in ("success", "failure", "cancelled", "skipped", "waiting", "blocked", None):
            with self.subTest(state=state):
                output, _ = self.decide(FakeForgejo({OWN: "running", 49: state}))
                self.assertEqual(output, "in_flight=false\n")

    def test_its_own_running_build_does_not_count(self):
        output, _ = self.decide(FakeForgejo({OWN: "running"}))
        self.assertEqual(output, "in_flight=false\n")

    def test_every_list_call_names_its_page(self):
        api = FakeForgejo({OWN: "running", 49: "success", 48: "cancelled"})
        self.decide(api)
        self.assertTrue(api.paths)
        self.assertTrue(all("page=1" in path for path in api.paths), api.paths)

    def test_an_unreadable_api_builds(self):
        for api in (FakeForgejo({49: "running"}, runs_error=check.verdicts.Unproven("forgejo-api-unavailable")),
                    FakeForgejo({49: "running"}, jobs_error=TimeoutError("read timed out")),
                    FakeForgejo({49: "running"}, runs_error=ValueError("malformed"))):
            with self.subTest(api=api):
                output, printed = self.decide(api)
                self.assertEqual(output, "in_flight=false\n")
                self.assertIn("::warning::could not read the other Deploy Dev runs", printed)

    def test_a_read_that_takes_too_long_builds(self):
        ticks = iter([0, check.READ_SECONDS + 1, check.READ_SECONDS + 2])
        with self.assertRaises(check.verdicts.Unproven):
            check.other_build_running(FakeForgejo({OWN: "running", 49: "running"}), OWN, clock=lambda: next(ticks))
        with mock.patch.object(check.time, "monotonic", side_effect=[0, check.READ_SECONDS + 1]):
            output, _ = self.decide(FakeForgejo({OWN: "running", 49: "running"}))
        self.assertEqual(output, "in_flight=false\n")

    def test_an_invalid_run_builds(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "", "GITHUB_OUTPUT": str(output)}, clear=True), \
                    redirect_stdout(io.StringIO()):
                check.main([], api_factory=lambda _environ: self.fail("the API was read"))
            self.assertEqual(output.read_text(), "in_flight=false\n")


if __name__ == "__main__":
    unittest.main()
