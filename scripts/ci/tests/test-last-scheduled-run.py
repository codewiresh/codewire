#!/usr/bin/env python3
"""The last successful scheduled run's commit (scripts/ci/select/last-scheduled-run.py).

A scheduled Kind or release dry run compares against this commit. Forgejo
lists a scheduled run that a push to main registered with event push, so only
trigger_event tells it apart; any uncertainty leaves the baseline empty and
the scheduled run checks everything.
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
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/ci/select/last-scheduled-run.py"
SPEC = importlib.util.spec_from_file_location("codewire_last_scheduled_run", HELPER)
assert SPEC and SPEC.loader
helper = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = helper
SPEC.loader.exec_module(helper)

OLD = "1" * 40
NEW = "2" * 40
PUSHED = "3" * 40
SCHEDULE = {"GITHUB_EVENT_NAME": "schedule", "GITHUB_RUN_ID": "99"}


def run(run_id: int, commit: str, trigger: str, **fields: Any) -> dict[str, Any]:
    record = {
        "id": run_id,
        "commit_sha": commit,
        "event": "push",
        "trigger_event": trigger,
        "workflow_id": "ci.yaml",
        "prettyref": "main",
        "status": "success",
    }
    record.update(fields)
    return record


class FakeForgejo:
    def __init__(self, pages: list[list[dict[str, Any]]] | Exception):
        self.pages = pages
        self.paths: list[str] = []

    def factory(self, environ: dict[str, str]):
        return self.fetch

    def fetch(self, path: str) -> Any:
        self.paths.append(path)
        if isinstance(self.pages, Exception):
            raise self.pages
        match = re.fullmatch(
            r"/actions/runs\?workflow_id=([a-z.-]+)&status=success&page=(\d+)&limit=50", path)
        assert match, path
        page = int(match.group(2))
        runs = self.pages[page - 1] if page <= len(self.pages) else []
        return {"total_count": sum(len(p) for p in self.pages), "workflow_runs": runs}


def page_of(count: int, first_id: int) -> list[dict[str, Any]]:
    return [run(first_id - index, PUSHED, "push") for index in range(count)]


class LastScheduledRunTests(unittest.TestCase):
    def choose(self, forgejo: FakeForgejo, environ: dict[str, str] | None = None,
               workflow: str = "ci.yaml") -> tuple[str, str]:
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            commit = helper.choose(environ or dict(SCHEDULE), workflow, forgejo.factory)
        return commit, log.getvalue()

    def test_newest_successful_scheduled_run_on_main(self) -> None:
        forgejo = FakeForgejo([[
            run(60, PUSHED, "push"),
            run(55, NEW, "schedule"),
            run(50, OLD, "schedule"),
        ]])
        commit, log = self.choose(forgejo)
        self.assertEqual(commit, NEW)
        self.assertIn(f"run 55 checked {NEW}", log)
        self.assertEqual(forgejo.paths,
                         ["/actions/runs?workflow_id=ci.yaml&status=success&page=1&limit=50"])

    def test_a_push_run_is_never_a_baseline(self) -> None:
        # Forgejo lists both with event push; only trigger_event differs.
        commit, log = self.choose(FakeForgejo([[run(60, PUSHED, "push"), run(59, NEW, "push")]]))
        self.assertEqual(commit, "")
        self.assertIn("(no-successful-scheduled-run)", log)

    def test_other_branches_failures_and_this_run_are_skipped(self) -> None:
        forgejo = FakeForgejo([[
            run(99, NEW, "schedule"),
            run(98, NEW, "schedule", prettyref="feature"),
            run(97, NEW, "schedule", status="failure"),
            run(96, NEW, "schedule", workflow_id="other.yaml"),
            run(95, OLD, "schedule"),
        ]])
        self.assertEqual(self.choose(forgejo)[0], OLD)

    def test_other_run_shapes_are_accepted(self) -> None:
        forgejo = FakeForgejo([[
            {"id": 70, "head_sha": NEW, "trigger_event": "schedule",
             "path": "cw-release-dry-run.yaml@refs/heads/main",
             "status": "completed", "conclusion": "success"},
        ]])
        commit, _ = self.choose(forgejo, workflow="cw-release-dry-run.yaml")
        self.assertEqual(commit, NEW)

    def test_later_pages_are_read_within_a_bound(self) -> None:
        forgejo = FakeForgejo([page_of(50, 400), page_of(50, 350), [run(300, OLD, "schedule")]])
        self.assertEqual(self.choose(forgejo)[0], OLD)
        self.assertEqual(len(forgejo.paths), 3)
        too_many = FakeForgejo([page_of(50, 1000 - 50 * page) for page in range(helper.MAX_PAGES)])
        commit, log = self.choose(too_many)
        self.assertEqual(commit, "")
        self.assertIn("(no-successful-scheduled-run-in-recent-runs)", log)
        self.assertEqual(len(too_many.paths), helper.MAX_PAGES)

    def test_every_uncertainty_leaves_no_baseline(self) -> None:
        cases = (
            ("not scheduled", FakeForgejo([[run(55, NEW, "schedule")]]),
             {"GITHUB_EVENT_NAME": "push"}, "not-a-scheduled-run"),
            ("API down", FakeForgejo(helper.Unknown("forgejo-api-unavailable")), None,
             "forgejo-api-unavailable"),
            ("no trigger_event", FakeForgejo([[{k: v for k, v in run(55, NEW, "schedule").items()
                                               if k != "trigger_event"}]]), None,
             "trigger-event-unavailable"),
            ("bad commit", FakeForgejo([[run(55, "not-a-commit", "schedule")]]), None,
             "scheduled-run-commit-invalid"),
            ("empty", FakeForgejo([[]]), None, "no-successful-scheduled-run"),
        )
        for label, forgejo, environ, reason in cases:
            with self.subTest(case=label):
                commit, log = self.choose(forgejo, environ)
                self.assertEqual(commit, "")
                self.assertIn(f"({reason}); this run checks everything", log)

    def test_malformed_pages_leave_no_baseline(self) -> None:
        for document in ({"workflow_runs": []}, {"total_count": 1, "workflow_runs": "x"}, []):
            with self.subTest(document=document):
                fetch_log = io.StringIO()
                with contextlib.redirect_stdout(fetch_log):
                    commit = helper.choose(dict(SCHEDULE), "ci.yaml",
                                           lambda environ: (lambda path: document))
                self.assertEqual(commit, "")
                self.assertIn("(forgejo-api-malformed)", fetch_log.getvalue())

    def test_missing_job_token_leaves_no_baseline(self) -> None:
        environ = dict(SCHEDULE, GITHUB_SERVER_URL="https://forge.example.invalid",
                       GITHUB_REPOSITORY="codewire/codewire", GITEA_TOKEN="")
        log = io.StringIO()
        with contextlib.redirect_stdout(log):
            self.assertEqual(helper.choose(environ, "ci.yaml"), "")
        self.assertIn("(gitea-token-unavailable)", log.getvalue())

    def test_command_writes_one_output_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output"
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(("GITHUB_", "GITEA_"))}
            environment.update(GITHUB_EVENT_NAME="push", GITHUB_OUTPUT=str(output))
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(HELPER), "--workflow", "ci.yaml", "--github-output"],
                env=environment, text=True, capture_output=True, check=True,
            )
            self.assertEqual(output.read_text(), "schedule_baseline=\n")
            self.assertTrue(completed.stdout.endswith("schedule_baseline=\n"))
            refused = subprocess.run(
                [sys.executable, "-I", "-B", str(HELPER), "--workflow", "../ci.yaml"],
                env=environment, text=True, capture_output=True, check=False,
            )
            self.assertEqual(refused.returncode, 2)


if __name__ == "__main__":
    unittest.main()
