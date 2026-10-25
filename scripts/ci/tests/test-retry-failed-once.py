#!/usr/bin/env python3
"""A main push run retries its failed test jobs once (infra#1534).

Covers scripts/ci/select/retry-failed-once.py against recorded Forgejo job
lists, and the ci.yaml job that runs it. Forgejo's own behaviour was proven on
a scratch run (22229, 2026-10-25): a later job of a run reran its failed job
with the job token while the run was still going, the job passed on attempt
2, Required verification passed after it, and the retrying job was not run
again.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/ci/plan/tests"))
import verdict_fixtures as fx  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "codewire_ci_retry_failed_once", ROOT / "scripts/ci/select/retry-failed-once.py"
)
assert SPEC and SPEC.loader
retry = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = retry
SPEC.loader.exec_module(retry)

RUN = 41
SHA = "a" * 40


def job(job_id: int, name: str, status: str, attempt: int = 1) -> dict:
    return {"id": job_id, "run_id": RUN, "attempt": attempt, "name": name, "status": status}


def jobs(*extra: dict) -> list[dict]:
    return [
        job(1, "Verification selection", "success"),
        job(2, "Policy verification", "success"),
        job(3, "Rust / transport packages", "success"),
        job(4, "Service runtime-plane verification", "success"),
        job(5, "Required verification", "failure"),
        job(6, "Retry failed test jobs once", "running"),
        *extra,
    ]


def replace(listing: list[dict], new: dict) -> list[dict]:
    return [new if item["id"] == new["id"] else item for item in listing]


class RetryTests(unittest.TestCase):
    def run_retry(self, listing: list[dict]) -> tuple[str, list[str], str]:
        api = fx.FakeForgejo(jobs={RUN: listing})
        out = io.StringIO()
        result = retry.retry(api, RUN, log=lambda line: out.write(line + "\n"))
        return result, api.posts, out.getvalue()

    def test_failed_test_jobs_are_rerun_once(self) -> None:
        listing = replace(replace(jobs(), job(3, "Rust / transport packages", "failure")),
                          job(4, "Service runtime-plane verification", "failure"))
        result, posts, log = self.run_retry(listing)
        self.assertEqual(result, "retried")
        self.assertEqual(posts, ["/actions/jobs/3/rerun", "/actions/jobs/4/rerun"])
        self.assertIn("retrying once, as a possible flake: Rust / transport packages, "
                      "Service runtime-plane verification", log)

    def test_a_job_that_failed_again_after_its_retry_is_never_retried(self) -> None:
        listing = jobs(job(13, "Rust / transport packages", "failure", attempt=2))
        listing = replace(listing, job(3, "Rust / transport packages", "failure"))
        result, posts, log = self.run_retry(listing)
        self.assertEqual((result, posts), ("already-retried", []))
        self.assertIn("already retried once: Rust / transport packages", log)

    def test_policy_is_never_retried(self) -> None:
        # Advisory and expiry checks live in Policy and stay blocking (#3119).
        result, posts, log = self.run_retry(replace(jobs(), job(2, "Policy verification", "failure")))
        self.assertEqual((result, posts), ("nothing", []))
        self.assertIn("a Policy failure is never retried", log)

    def test_a_refused_rerun_leaves_the_run_red_and_says_so(self) -> None:
        listing = replace(jobs(), job(3, "Rust / transport packages", "failure"))
        api = fx.FakeForgejo(jobs={RUN: listing}, reruns={3: [409]})
        out = io.StringIO()
        self.assertEqual(retry.retry(api, RUN, log=lambda line: out.write(line + "\n")), "refused")
        self.assertIn("Forgejo refused to rerun Rust / transport packages (HTTP 409)", out.getvalue())

    def test_unreadable_jobs_retry_nothing(self) -> None:
        api = fx.FakeForgejo(jobs={RUN: RuntimeError("boom")})
        api.get_json = lambda path: (_ for _ in ()).throw(retry.verdicts.Unproven("forgejo-api-unreachable"))
        self.assertEqual(retry.retry(api, RUN, log=lambda line: None), "unreadable")
        self.assertEqual(api.posts, [])

    def test_only_a_push_to_main_at_main_s_tip_retries(self) -> None:
        base = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main",
                "GITHUB_RUN_ID": str(RUN), "GITHUB_SHA": SHA}
        cases = {
            "pull request": ({**base, "GITHUB_EVENT_NAME": "pull_request"}, SHA, "only a push to main"),
            "schedule": ({**base, "GITHUB_EVENT_NAME": "schedule"}, SHA, "only a push to main"),
            "main moved on": (base, "b" * 40, "main has moved on to " + "b" * 40),
            "tip unreadable": (base, None, "main has moved on to an unreadable commit"),
        }
        for label, (environ, tip, message) in cases.items():
            with self.subTest(case=label):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(retry.main(environ, tip=lambda tip=tip: tip), 0)
                self.assertIn(message, out.getvalue())


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.jobs = yaml.safe_load((ROOT / ".gitea/workflows/ci.yaml").read_text())["jobs"]

    def test_the_retry_job_runs_after_a_red_verdict_on_an_unsuperseded_main_push_only(self) -> None:
        job_ = self.jobs["retry-failed-once"]
        self.assertEqual(job_["needs"], ["verification-selection", "required-verification"])
        for fragment in ("always()", "github.event_name == 'push'", "github.ref == 'refs/heads/main'",
                         "needs.verification-selection.outputs.superseded == 'false'",
                         "needs.required-verification.result == 'failure'"):
            self.assertIn(fragment, job_["if"])
        self.assertIn("scripts/ci/select/retry-failed-once.py", job_["steps"][-1]["run"])
        self.assertIn("UNTRUSTED_LIGHT", job_["runs-on"])
        # Nothing needs it, so a retry never holds the run's verdict.
        for name, other in self.jobs.items():
            needs = other.get("needs") or []
            self.assertNotIn("retry-failed-once", [needs] if isinstance(needs, str) else needs, name)

    def test_every_retryable_name_is_a_ci_yaml_test_job_and_policy_is_not(self) -> None:
        names = {job_["name"] for job_ in self.jobs.values()}
        retryable = {name for name in names if retry.RETRYABLE_RE.fullmatch(name)}
        self.assertEqual(retryable, {
            "Standard verification", "Tooling / delivery contract verification", "Compile every Rust target",
            "Rust / transport packages", "Rust / transport feature graphs", "Rust / transport verification",
            "Database verification", "Service control-plane verification", "Service runtime-plane verification",
        })
        self.assertNotIn("Policy verification", retryable)


if __name__ == "__main__":
    unittest.main()
